#!/usr/bin/env python3
"""本地遥测接收器：原样回显报文，可延迟回包；并提供独立的上行抓包能力。

职责：
1. UDP 回显（原有行为，抓包绝不影响转发/回显）：
   - 报文以 "DELAY:<秒>:" 开头时按该值延迟，否则用环境变量 REPLY_DELAY；
2. 抓包证据点（与代理相互独立）：
   - 仅记录代理通过 HTTP 控制接口下发的、指定上游端口发来的数据报原文；
   - 每侧 1 MiB 硬上限，超额只停止记录（truncated），回显照常；
   - 抓包结果（PCAP + 逐条摘要）在停止后冻结，重复下载内容不变；
3. 控制接口全部基于标准库 http.server，无第三方依赖。

环境变量：
  RECEIVER_NAME   显示名（默认 receiver）
  LISTEN_PORT     UDP 监听端口（默认 9001）
  CONTROL_PORT    HTTP 控制端口（默认 9101）
  REPLY_DELAY     默认回包延迟秒数（默认 0）
  CAPTURE_DIR     抓包文件目录（默认 /tmp/telemetry-captures）
  CAP_MAX_BYTES   单次抓包每侧字节上限（默认 1048576 = 1 MiB）
  DROP_CONTAINS   测试用：逗号分隔的字节子串，命中即整包丢弃（不回显不记录）
"""

import asyncio
import hashlib
import json
import os
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# 与代理共用的纯标准库 PCAP 写入器
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.pcaputil import PcapRecorder  # noqa: E402

NAME = os.environ.get("RECEIVER_NAME", "receiver")
PORT = int(os.environ.get("LISTEN_PORT", "9001"))
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "9101"))
DEFAULT_DELAY = float(os.environ.get("REPLY_DELAY", "0"))
MAX_DELAY = float(os.environ.get("MAX_DELAY", "60"))
CAPTURE_DIR = os.environ.get("CAPTURE_DIR", "/tmp/telemetry-captures")
CAP_MAX_BYTES = int(os.environ.get("CAP_MAX_BYTES", str(1024 * 1024)))
# 停止宽限：代理请求停止后，接收器继续记录这么久再冻结，
# 保证代理冻结前已发出的在途数据报都能落进接收器窗口。
STOP_GRACE = float(os.environ.get("STOP_GRACE", "0.25"))
DROP_SUBSTRINGS = [
    s.encode() for s in os.environ.get("DROP_CONTAINS", "").split(",") if s
]

DELAY_RE = re.compile(rb"^DELAY:([0-9]+(?:\.[0-9]+)?):")

os.makedirs(CAPTURE_DIR, exist_ok=True)


def _local_ip_toward(remote_ip: str) -> str:
    """查询本机发往 remote_ip 时使用的源 IP（不真正发包）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((remote_ip, 9))  # UDP connect 不产生流量
        return s.getsockname()[0]
    finally:
        s.close()


class Capture:
    """接收器侧一次抓包的全部状态。"""

    def __init__(self, capture_id, sender_ip, sender_port, duration, max_bytes):
        self.id = capture_id
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        self.duration = duration
        self.max_bytes = max_bytes
        self.started_wall = time.time()
        self.stopped_wall = None
        self.state = "active"            # active -> stopped
        self.truncated = False
        self.reason = ""
        self.records = []                # 逐条原文摘要（仅成功写入 PCAP 的）
        self.received_total = 0          # 窗口内实际收到的匹配数据报总数
        self.dropped_total = 0           # DROP_CONTAINS 测试丢弃数
        self._lock = threading.Lock()
        local_ip = _local_ip_toward(sender_ip)
        self.tuple4 = (sender_ip, local_ip, sender_port, PORT)
        self.path = os.path.join(CAPTURE_DIR, f"receiver-{capture_id}.pcap")
        self.recorder = PcapRecorder(self.path, self.tuple4, max_bytes=max_bytes)
        self._timers = []

    def offer(self, data: bytes):
        """事件循环线程调用：记录一条匹配数据报（预算/状态控制全在此处）。"""
        with self._lock:
            if self.state != "active":
                return
            self.received_total += 1
            ts = time.time()
            ok = self.recorder.record(data, int(ts), int((ts % 1) * 1_000_000))
            if not ok:
                self.truncated = True
                return
            self.records.append({
                "seq": len(self.records) + 1,
                "ts": ts,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            })

    def stop(self, reason):
        with self._lock:
            if self.state != "active":
                return False
            self.state = "stopped"
            self.reason = reason
            self.stopped_wall = time.time()
            rec = self.recorder
        rec.close()
        for t in self._timers:
            t.cancel()
        return True

    def snapshot(self):
        with self._lock:
            return {
                "id": self.id,
                "state": self.state,
                "truncated": self.truncated,
                "reason": self.reason,
                "sender_ip": self.sender_ip,
                "sender_port": self.sender_port,
                "tuple": list(self.tuple4),
                "packets": self.recorder.packets,
                "bytes_used": self.recorder.bytes_used,
                "max_bytes": self.max_bytes,
                "received_total": self.received_total,
                "dropped_total": self.dropped_total,
                "started_wall": self.started_wall,
                "stopped_wall": self.stopped_wall,
                "records": list(self.records),
                "pcap_path": self.path,
            }


class CaptureRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._by_id = {}          # id -> Capture
        self._port_index = {}     # sender_port -> capture_id（仅 active）

    def start(self, capture_id, sender_ip, sender_port, duration, max_bytes):
        with self._lock:
            existing = self._by_id.get(capture_id)
            if existing is not None:
                # 幂等重试：参数一致则返回既有抓包
                if existing.sender_port == sender_port:
                    return existing, False
                raise ValueError(f"capture_id {capture_id} 已被占用且参数不一致")
            other = self._port_index.get(sender_port)
            if other is not None:
                raise ValueError(f"上游端口 {sender_port} 已有进行中的抓包 {other}")
            cap = Capture(capture_id, sender_ip, sender_port, duration, max_bytes)
            self._by_id[capture_id] = cap
            self._port_index[sender_port] = capture_id
        # 失联保护：到时自动冻结（代理正常时会先显式安排停止）
        timer = threading.Timer(duration + 5, self.hard_stop, args=(capture_id, "auto-timeout"))
        timer.daemon = True
        cap._timers.append(timer)
        timer.start()
        return cap, True

    def schedule_stop(self, capture_id, reason, grace):
        """安排在宽限期后冻结：宽限期内端口索引仍在，在途数据报继续记录。"""
        with self._lock:
            cap = self._by_id.get(capture_id)
        if cap is None or cap.state != "active":
            return cap
        timer = threading.Timer(grace, self.hard_stop, args=(capture_id, reason))
        timer.daemon = True
        cap._timers.append(timer)
        timer.start()
        return cap

    def hard_stop(self, capture_id, reason):
        """真正冻结：此刻才移除端口索引，保证宽限期内的在途报文都已入文件。"""
        with self._lock:
            cap = self._by_id.get(capture_id)
            if cap is None:
                return None
            self._port_index.pop(cap.sender_port, None)
        cap.stop(reason)
        return cap

    def get(self, capture_id):
        with self._lock:
            return self._by_id.get(capture_id)

    def offer_by_port(self, sender_port, data):
        with self._lock:
            cid = self._port_index.get(sender_port)
            cap = self._by_id.get(cid) if cid else None
        if cap is not None:
            cap.offer(data)
            return True
        return False

    def mark_dropped_by_port(self, sender_port, size):
        """测试用 DROP_CONTAINS：统计被整包丢弃的数据报（仍计入窗口）。"""
        with self._lock:
            cid = self._port_index.get(sender_port)
            cap = self._by_id.get(cid) if cid else None
        if cap is not None:
            with cap._lock:
                if cap.state == "active":
                    cap.received_total += 1
                    cap.dropped_total += 1


REGISTRY = CaptureRegistry()


class ReceiverProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # 测试用丢包开关：命中即整包消失（不回显、不记录），用于验证未证实统计
        for needle in DROP_SUBSTRINGS:
            if needle in data:
                REGISTRY.mark_dropped_by_port(addr[1], len(data))
                print(f"[{NAME}] DROP_CONTAINS 命中，丢弃 {len(data)}B 来自 {addr}", flush=True)
                return

        # 独立证据点：按代理上游端口匹配并记录原文（与回显互不影响）
        REGISTRY.offer_by_port(addr[1], data)

        delay = DEFAULT_DELAY
        m = DELAY_RE.match(data)
        if m:
            delay = min(float(m.group(1)), MAX_DELAY)
        print(f"[{NAME}] 收到 {len(data)}B 来自 {addr[0]}:{addr[1]}，{delay}s 后回包", flush=True)
        asyncio.get_running_loop().call_later(delay, self._reply, data, addr)

    def _reply(self, data, addr):
        try:
            self.transport.sendto(data, addr)  # 原样回显
            print(f"[{NAME}] 已回包 {len(data)}B 到 {addr[0]}:{addr[1]}", flush=True)
        except Exception as exc:
            print(f"[{NAME}] 回包失败: {exc}", flush=True)


# ---------------- HTTP 控制接口（标准库） ----------------
class ControlHandler(BaseHTTPRequestHandler):
    server_version = "telemetry-receiver/1.0"

    def log_message(self, fmt, *args):  # 安静一点
        print(f"[{NAME}-ctrl] {self.address_string()} {fmt % args}", flush=True)

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, msg, status=400):
        self._json({"ok": False, "error": msg}, status)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/health":
            return self._json({"ok": True, "receiver": NAME, "listen_port": PORT})
        if parsed.path in ("/capture/status", "/capture/records"):
            cid = (qs.get("id") or [""])[0]
            cap = REGISTRY.get(cid)
            if cap is None:
                return self._error(f"未知抓包 id: {cid}", 404)
            return self._json({"ok": True, "capture": cap.snapshot()})
        if parsed.path == "/capture/pcap":
            cid = (qs.get("id") or [""])[0]
            cap = REGISTRY.get(cid)
            if cap is None:
                return self._error(f"未知抓包 id: {cid}", 404)
            snap = cap.snapshot()
            if snap["state"] != "stopped":
                return self._error("抓包尚未停止，不能下载", 409)
            try:
                with open(snap["pcap_path"], "rb") as f:
                    blob = f.read()
            except OSError as exc:
                return self._error(f"PCAP 读取失败: {exc}", 500)
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="receiver-{cid}.pcap"',
            )
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)
            return
        return self._error("not found", 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length).decode() or "{}")
        except json.JSONDecodeError:
            return self._error("请求体不是合法 JSON")

        if parsed.path == "/capture/start":
            try:
                cid = str(payload["capture_id"])
                sender_ip = str(payload["sender_ip"])
                sender_port = int(payload["sender_port"])
                duration = float(payload.get("duration", 30))
                max_bytes = int(payload.get("max_bytes", CAP_MAX_BYTES))
            except (KeyError, TypeError, ValueError) as exc:
                return self._error(f"参数错误: {exc}")
            try:
                cap, created = REGISTRY.start(
                    cid, sender_ip, sender_port, duration, max_bytes
                )
            except ValueError as exc:
                return self._error(str(exc), 409)
            return self._json({"ok": True, "created": created, "capture": cap.snapshot()})

        if parsed.path == "/capture/stop":
            cid = str(payload.get("capture_id", ""))
            grace = float(payload.get("grace", STOP_GRACE))
            cap = REGISTRY.get(cid)
            if cap is None:
                return self._error(f"未知抓包 id: {cid}", 404)
            # 宽限期内继续记录在途数据报，到时才冻结并释放端口索引
            REGISTRY.schedule_stop(cid, "manual-stop", grace)
            return self._json({"ok": True, "capture": cap.snapshot()})

        return self._error("not found", 404)


def _run_control_server():
    httpd = ThreadingHTTPServer(("0.0.0.0", CONTROL_PORT), ControlHandler)
    print(f"[{NAME}] 抓包控制 HTTP 监听 0.0.0.0:{CONTROL_PORT}", flush=True)
    httpd.serve_forever()


async def main():
    threading.Thread(target=_run_control_server, name="ctrl-http", daemon=True).start()
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        lambda: ReceiverProtocol(), local_addr=("0.0.0.0", PORT)
    )
    print(f"[{NAME}] UDP 监听 0.0.0.0:{PORT}，默认延迟 {DEFAULT_DELAY}s，"
          f"抓包上限 {CAP_MAX_BYTES}B", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
