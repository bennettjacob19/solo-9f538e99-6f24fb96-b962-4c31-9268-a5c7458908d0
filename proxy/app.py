#!/usr/bin/env python3
"""遥测 UDP 代理 + 操作网页 + 上行抓包对账。

转发与会话（原有行为）：
- 按客户端 IP:端口建立会话，空闲超时（默认 5 秒）后过期；
- 建会话时把该会话固定到当前目标接收器（A/B），会话期间不随切换改变；
- 每个会话使用一条独立的、已 connect 的上游 UDP 套接字（独立本地端口），
  因此回包天然只能属于一个会话；
- 会话过期即关闭其上游端口，且端口进入冷却期不再分配；
- 报文与回包原样透传，不做任何修改；
- 当前目标保存在 SQLite，重启后保留；会话全在内存，重启即清空。

上行抓包对账（本版本新增）：
- 值班员在网页对“活动会话”启动最长 30 秒的上行抓包；
- 两个相互独立的证据点：
  * 代理侧：记录会话上游套接字“实际发出”的 UDP 原文（发送成功才记录）；
  * 接收器侧：接收器独立记录“实际收到”的原文，按本会话上游端口过滤；
- 启动顺序：先让接收器开始记录并得到确认，代理侧才布防，
  因此代理记录的每一条都落在接收器窗口之内，只有两侧都确认启动后才对账；
- 任一侧失联、任一侧 1 MiB 抓满 → 证据不完整，只报告未证实，绝不断言丢包；
- 两侧均完整时，按报文 SHA-256 摘要做多重集对账，重传按次数核对，
  同文重发不能凭一份收包算作全部到达；
- 每侧硬上限 1 MiB，抓满只停止记录，原样转发与回显完全不受影响；
- 抓包结果（两份 PCAP + 对账摘要）停止即冻结并落盘，下载内容永久不变；
- 抓包期间会话关闭/端口复用：端口冻结到抓包结束，文件只含本会话本窗口。
"""

import asyncio
import hashlib
import json
import os
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import uuid

from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request, url_for)

# 与接收器共用的纯标准库 PCAP 写入器
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.pcaputil import PcapRecorder  # noqa: E402

# ---------------- 配置 ----------------
UDP_LISTEN_HOST = os.environ.get("UDP_LISTEN_HOST", "0.0.0.0")
UDP_LISTEN_PORT = int(os.environ.get("UDP_LISTEN_PORT", "9000"))
HTTP_HOST = os.environ.get("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
DB_PATH = os.environ.get(
    "DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy.db")
)
CAPTURE_DIR = os.environ.get(
    "CAPTURE_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")
)
SESSION_IDLE_TIMEOUT = float(os.environ.get("SESSION_IDLE_TIMEOUT", "5"))
UPSTREAM_PORT_MIN = int(os.environ.get("UPSTREAM_PORT_MIN", "20000"))
UPSTREAM_PORT_MAX = int(os.environ.get("UPSTREAM_PORT_MAX", "29999"))
UPSTREAM_PORT_COOLDOWN = float(os.environ.get("UPSTREAM_PORT_COOLDOWN", "30"))
LOG_KEEP = int(os.environ.get("LOG_KEEP", "1000"))

CAP_MAX_SECONDS = float(os.environ.get("CAP_MAX_SECONDS", "30"))
CAP_MAX_BYTES = int(os.environ.get("CAP_MAX_BYTES", str(1024 * 1024)))  # 每侧 1 MiB
MAX_ACTIVE_CAPTURES = int(os.environ.get("MAX_ACTIVE_CAPTURES", "8"))
CAPTURE_HTTP_TIMEOUT = float(os.environ.get("CAPTURE_HTTP_TIMEOUT", "5"))
# 停止宽限：代理先冻结自己，再让接收器在宽限期后冻结，
# 保证代理冻结前已发出的在途数据报都能进入接收器窗口。
CAPTURE_STOP_GRACE = float(os.environ.get("CAPTURE_STOP_GRACE", "0.25"))
# 接收器失联时的重试窗口：超时仍联系不上则冻结为“证据不完整”
RECEIVER_RETRY_WINDOW = float(os.environ.get("RECEIVER_RETRY_WINDOW", "10"))

RECEIVERS = {
    "A": (
        os.environ.get("RECEIVER_A_HOST", "127.0.0.1"),
        int(os.environ.get("RECEIVER_A_PORT", "9001")),
    ),
    "B": (
        os.environ.get("RECEIVER_B_HOST", "127.0.0.1"),
        int(os.environ.get("RECEIVER_B_PORT", "9002")),
    ),
}
# 接收器抓包控制接口（HTTP）。compose 内走容器名。
RECEIVER_CONTROL = {
    "A": os.environ.get(
        "RECEIVER_A_CONTROL_URL",
        f"http://127.0.0.1:{int(os.environ.get('RECEIVER_A_CONTROL_PORT', '9101'))}",
    ).rstrip("/"),
    "B": os.environ.get(
        "RECEIVER_B_CONTROL_URL",
        f"http://127.0.0.1:{int(os.environ.get('RECEIVER_B_CONTROL_PORT', '9102'))}",
    ).rstrip("/"),
}
DEFAULT_TARGET = os.environ.get("DEFAULT_TARGET", "A")


def fmt_addr(addr):
    return f"{addr[0]}:{addr[1]}"


def preview(data: bytes) -> str:
    """报文内容展示：可打印文本原样显示，否则用 hex。"""
    try:
        text = data.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return text if len(text) <= 200 else text[:200] + "…"
    except UnicodeDecodeError:
        pass
    hexed = data.hex()
    return "hex:" + (hexed if len(hexed) <= 200 else hexed[:200] + "…")


def fmt_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int((ts % 1) * 1000):03d}"


# ---------------- SQLite：目标持久化 + 报文日志 ----------------
class Store:
    """线程安全的 SQLite 存取。目标(target)落库，重启后保留。"""

    def __init__(self, path):
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS message_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts REAL NOT NULL,
                   client TEXT NOT NULL DEFAULT '',
                   session_id INTEGER NOT NULL DEFAULT 0,
                   direction TEXT NOT NULL,
                   receiver TEXT NOT NULL DEFAULT '',
                   payload TEXT NOT NULL DEFAULT '',
                   note TEXT NOT NULL DEFAULT '')"""
        )
        self._conn.commit()
        row = self._conn.execute("SELECT value FROM settings WHERE key='target'").fetchone()
        if row and row[0] in RECEIVERS:
            self._target = row[0]
        else:
            self._target = DEFAULT_TARGET if DEFAULT_TARGET in RECEIVERS else sorted(RECEIVERS)[0]
            self._conn.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('target',?)", (self._target,)
            )
            self._conn.commit()
        self._inserts = 0

    def get_target(self):
        with self._lock:
            return self._target

    def set_target(self, target):
        """先持久化，成功后才切换内存中的当前目标；失败则抛异常并保留原目标。"""
        if target not in RECEIVERS:
            raise ValueError(f"未知接收器: {target!r}")
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('target',?)", (target,)
            )
            self._conn.commit()
            self._target = target

    def log(self, direction, client="", session_id=0, receiver="", payload="", note=""):
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO message_log(ts,client,session_id,direction,receiver,payload,note)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (time.time(), client, session_id, direction, receiver, payload, note),
                )
                self._conn.commit()
                self._inserts += 1
                if self._inserts % 200 == 0:
                    self._conn.execute(
                        "DELETE FROM message_log WHERE id < "
                        "(SELECT COALESCE(MIN(id),0) FROM "
                        "(SELECT id FROM message_log ORDER BY id DESC LIMIT ?))",
                        (LOG_KEEP,),
                    )
                    self._conn.commit()
        except sqlite3.Error:
            pass  # 日志失败绝不影响转发

    def recent_messages(self, limit=100):
        with self._lock:
            rows = self._conn.execute(
                "SELECT id,ts,client,session_id,direction,receiver,payload,note "
                "FROM message_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        cols = ("id", "ts", "client", "session_id", "direction", "receiver", "payload", "note")
        return [dict(zip(cols, r)) for r in rows]

    def latest_receiver_for_client(self, client):
        with self._lock:
            row = self._conn.execute(
                "SELECT receiver FROM message_log WHERE client=? AND direction='c2r' "
                "ORDER BY id DESC LIMIT 1",
                (client,),
            ).fetchone()
        return row[0] if row else None


# ---------------- 上游端口分配（带冷却期） ----------------
class PortAllocator:
    """显式管理上游本地端口：关闭后冷却期内不再分配。"""

    def __init__(self, low, high, cooldown):
        self.low, self.high, self.cooldown = low, high, cooldown
        self._next = low
        self._in_use = set()
        self._closed = {}  # port -> 关闭时刻(monotonic)
        self._frozen = set()  # 抓包占用：会话关闭后仍不释放，直到抓包结束
        self._lock = threading.Lock()

    def allocate(self):
        with self._lock:
            now = time.monotonic()
            for _ in range(self.high - self.low + 1):
                port = self._next
                self._next += 1
                if self._next > self.high:
                    self._next = self.low
                if port in self._in_use or port in self._frozen:
                    continue
                closed_at = self._closed.get(port)
                if closed_at is not None and now - closed_at < self.cooldown:
                    continue
                self._in_use.add(port)
                self._closed.pop(port, None)
                return port
        raise RuntimeError("上游 UDP 端口耗尽")

    def release(self, port):
        with self._lock:
            self._in_use.discard(port)
            self._closed[port] = time.monotonic()

    def freeze(self, port):
        """会话关闭但抓包未结束：端口保持占用，杜绝复用串入本次 PCAP。"""
        with self._lock:
            self._in_use.discard(port)
            self._frozen.add(port)

    def unfreeze(self, port):
        with self._lock:
            self._frozen.discard(port)
            self._closed[port] = time.monotonic()

    def discard(self, port):
        """分配后绑定失败：不进入冷却，直接可用。"""
        with self._lock:
            self._in_use.discard(port)


# ---------------- 会话与转发 ----------------
class Session:
    __slots__ = (
        "id", "client_addr", "receiver_name", "receiver_addr",
        "upstream_port", "transport", "state", "closed",
        "created", "last_activity", "pending", "capture",
    )

    def __init__(self, sid, client_addr):
        self.id = sid
        self.client_addr = client_addr
        self.receiver_name = ""
        self.receiver_addr = None
        self.upstream_port = None
        self.transport = None
        self.state = "opening"  # opening -> open -> closed
        self.closed = False
        self.created = time.monotonic()
        self.last_activity = self.created
        self.pending = []
        self.capture = None  # 活动抓包任务（CaptureJob），由抓包管理器线程赋值


class ClientProtocol(asyncio.DatagramProtocol):
    """面向遥测终端的 UDP 端。"""

    def __init__(self, state):
        self.state = state

    def datagram_received(self, data, addr):
        self.state.on_client_datagram(data, addr)

    def error_received(self, exc):
        pass


class UpstreamProtocol(asyncio.DatagramProtocol):
    """每个会话一条、已 connect 到其接收器的上游 UDP 端。"""

    def __init__(self, state):
        self.state = state
        self.session = None

    def datagram_received(self, data, addr):
        sess = self.session
        if sess is not None:
            self.state.on_upstream_datagram(sess, data)

    def error_received(self, exc):
        pass  # 如对端 ICMP 不可达，忽略


class ProxyState:
    def __init__(self, store):
        self.store = store
        self.loop = None
        self.client_transport = None
        self.sessions = {}  # client_addr -> Session（仅事件循环线程修改）
        self.lock = threading.RLock()
        self.next_session_id = 1
        self.ports = PortAllocator(UPSTREAM_PORT_MIN, UPSTREAM_PORT_MAX, UPSTREAM_PORT_COOLDOWN)
        self.capture_manager = None  # main() 中注入

    async def start(self):
        transport, _ = await self.loop.create_datagram_endpoint(
            lambda: ClientProtocol(self),
            local_addr=(UDP_LISTEN_HOST, UDP_LISTEN_PORT),
        )
        self.client_transport = transport
        self.loop.create_task(self._sweeper())
        print(f"[proxy] 客户端 UDP 监听 {UDP_LISTEN_HOST}:{UDP_LISTEN_PORT}", flush=True)
        print(f"[proxy] 空闲会话超时 {SESSION_IDLE_TIMEOUT}s，当前目标 {self.store.get_target()}",
              flush=True)

    # ---- 客户端方向 ----
    def on_client_datagram(self, data, addr):
        now = time.monotonic()
        with self.lock:
            sess = self.sessions.get(addr)
            if sess is not None and sess.closed:
                sess = None
            if (sess is not None and sess.state == "open"
                    and now - sess.last_activity > SESSION_IDLE_TIMEOUT):
                self._close_session(sess, "idle-timeout")
                sess = None
            if sess is None:
                # 建会话：固定到“当前”目标接收器
                sess = Session(self.next_session_id, addr)
                self.next_session_id += 1
                self.sessions[addr] = sess
                sess.pending.append(data)
                self.loop.create_task(self._open_session(sess))
                return
            sess.last_activity = now
            if sess.state == "opening":
                sess.pending.append(data)
                return
        self._forward(sess, data)

    async def _open_session(self, sess):
        target = self.store.get_target()  # 建会话时固定接收器
        host, port = RECEIVERS[target]
        client = fmt_addr(sess.client_addr)
        try:
            transport = None
            upstream_port = None
            last_err = None
            for _ in range(8):
                upstream_port = self.ports.allocate()
                try:
                    transport, proto = await self.loop.create_datagram_endpoint(
                        lambda: UpstreamProtocol(self),
                        local_addr=("0.0.0.0", upstream_port),
                        remote_addr=(host, port),  # connect：只收该接收器的回包
                    )
                    break
                except OSError as exc:
                    last_err = exc
                    self.ports.discard(upstream_port)
            if transport is None:
                raise last_err or RuntimeError("无可用上游端口")
            with self.lock:
                if sess.closed:
                    transport.close()
                    self.ports.release(upstream_port)
                    return
                sess.receiver_name = target
                sess.receiver_addr = (host, port)
                sess.upstream_port = upstream_port
                sess.transport = transport
                sess.state = "open"
                proto.session = sess
                pending, sess.pending = sess.pending, []
            self.store.log("event", client=client, session_id=sess.id, receiver=target,
                           note=f"会话建立，固定到接收器 {target}（上游端口 {upstream_port}）")
            for data in pending:
                self._forward(sess, data)
        except Exception as exc:
            self.store.log("event", client=client, session_id=sess.id,
                           note=f"会话建立失败: {exc}")
            self.close_session(sess, f"open-failed: {exc}")

    def _forward(self, sess, data):
        with self.lock:
            if sess.closed or sess.transport is None:
                return
            sess.last_activity = time.monotonic()
        try:
            sess.transport.sendto(data)  # 已 connect，原样发往该会话的接收器
        except Exception as exc:
            self.store.log("event", client=fmt_addr(sess.client_addr), session_id=sess.id,
                           note=f"转发失败: {exc}")
            return
        # 抓包证据点（代理侧）：仅在“实际发送成功”后记录原文，异常不影响转发
        job = sess.capture
        if job is not None:
            job.proxy_record(data)
        self.store.log("c2r", client=fmt_addr(sess.client_addr), session_id=sess.id,
                       receiver=sess.receiver_name, payload=preview(data))

    # ---- 接收器方向 ----
    def on_upstream_datagram(self, sess, data):
        now = time.monotonic()
        with self.lock:
            if sess.closed or self.sessions.get(sess.client_addr) is not sess:
                self.store.log("drop", client=fmt_addr(sess.client_addr), session_id=sess.id,
                               receiver=sess.receiver_name, payload=preview(data),
                               note="旧会话迟到的回包，已丢弃")
                return
            if now - sess.last_activity > SESSION_IDLE_TIMEOUT:
                self._close_session(sess, "idle-timeout")
                self.store.log("drop", client=fmt_addr(sess.client_addr), session_id=sess.id,
                               receiver=sess.receiver_name, payload=preview(data),
                               note="回包到达时会话已过期，已丢弃")
                return
            sess.last_activity = now
        self.client_transport.sendto(data, sess.client_addr)  # 原样送回该客户端
        self.store.log("r2c", client=fmt_addr(sess.client_addr), session_id=sess.id,
                       receiver=sess.receiver_name, payload=preview(data))

    # ---- 会话生命周期 ----
    def _close_session(self, sess, reason):
        """调用方需持有 self.lock。"""
        if sess.closed:
            return
        sess.closed = True
        sess.state = "closed"
        if self.sessions.get(sess.client_addr) is sess:
            del self.sessions[sess.client_addr]
        transport, sess.transport = sess.transport, None
        port, sess.upstream_port = sess.upstream_port, None
        if transport is not None:
            transport.close()  # 迟到的回包到此端口将被系统丢弃
        job = sess.capture
        if port is not None:
            if job is not None:
                # 抓包未结束：冻结端口，杜绝端口复用把别的会话串进本 PCAP
                self.ports.freeze(port)
            else:
                self.ports.release(port)  # 进入冷却期
        self.store.log("event", client=fmt_addr(sess.client_addr), session_id=sess.id,
                       receiver=sess.receiver_name, note=f"会话关闭（{reason}）")
        if job is not None and self.capture_manager is not None:
            # 通知抓包任务：会话已关闭（异步收尾，不阻塞事件循环）
            self.loop.run_in_executor(
                None, self.capture_manager.notify_session_closed, job, reason
            )

    def close_session(self, sess, reason):
        with self.lock:
            self._close_session(sess, reason)

    async def _sweeper(self):
        while True:
            await asyncio.sleep(0.25)
            now = time.monotonic()
            with self.lock:
                expired = [s for s in self.sessions.values()
                           if not s.closed and now - s.last_activity > SESSION_IDLE_TIMEOUT]
                for sess in expired:
                    self._close_session(sess, "idle-timeout")

    def snapshot_sessions(self):
        now = time.monotonic()
        with self.lock:
            return [
                {
                    "id": s.id,
                    "client": fmt_addr(s.client_addr),
                    "receiver": s.receiver_name or "?",
                    "upstream_port": s.upstream_port,
                    "state": s.state,
                    "idle": round(now - s.last_activity, 1),
                    "age": round(now - s.created, 1),
                    "capturing": s.capture is not None,
                }
                for s in sorted(self.sessions.values(), key=lambda x: x.id)
            ]


# ---------------- 上行抓包管理 ----------------
def _http_json(method, url, body=None, timeout=CAPTURE_HTTP_TIMEOUT):
    """标准库 HTTP 客户端，返回 (status, json)。"""
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode())
        except Exception:
            return exc.code, {"ok": False, "error": str(exc)}
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return None, {"ok": False, "error": str(exc)}


class CaptureJob:
    """一次抓包的完整生命周期与冻结结果（线程模型：仅管理器工作线程写）。"""

    def __init__(self, capture_id, sess, duration):
        self.id = capture_id
        self.session_id = sess.id
        self.client = fmt_addr(sess.client_addr)
        self.receiver = sess.receiver_name
        self.upstream_port = sess.upstream_port
        self.duration = duration
        self.state = "starting"          # starting -> running -> finalizing -> done
        self.armed = False               # 两侧都确认启动后置 True
        self.started_wall = time.time()
        self.armed_wall = None
        self.stopped_wall = None
        self.proxy_recorder = None
        self.proxy_path = os.path.join(CAPTURE_DIR, f"proxy-{capture_id}.pcap")
        self.proxy_records = []
        self.proxy_truncated = False
        self.receiver_snapshot = None
        self.receiver_started = False
        self.incomplete = True
        self.incomplete_reasons = []
        self.end_reason = ""
        self.session_closed = False
        self.session_close_reason = ""
        self.result = None               # 冻结后的对账结果（落盘 JSON）
        self._lock = threading.Lock()

    def proxy_record(self, data: bytes):
        """事件循环线程调用：仅当布防后记录代理“实际发出”的原文。

        任何记录失败都被吞掉并转为 truncated 标记，绝不影响转发路径。
        """
        with self._lock:
            if not self.armed or self.proxy_recorder is None:
                return
            rec = self.proxy_recorder
            ts = time.time()
        try:
            ok = rec.record(data, int(ts), int((ts % 1) * 1_000_000))
        except Exception:  # 停止与收包交错等极端情形：记录失败不影响转发
            ok = False
        if not ok:
            with self._lock:
                if not self.proxy_truncated:
                    self.proxy_truncated = True
                    self.incomplete_reasons.append("proxy-cap-full")
            return
        with self._lock:
            self.proxy_records.append({
                "seq": len(self.proxy_records) + 1,
                "ts": ts,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "preview": preview(data),
            })

    def public(self):
        with self._lock:
            return {
                "id": self.id,
                "session_id": self.session_id,
                "client": self.client,
                "receiver": self.receiver,
                "upstream_port": self.upstream_port,
                "duration": self.duration,
                "state": self.state,
                "armed": self.armed,
                "started_wall": self.started_wall,
                "armed_wall": self.armed_wall,
                "stopped_wall": self.stopped_wall,
                "proxy_packets": self.proxy_recorder.packets if self.proxy_recorder else 0,
                "proxy_bytes": self.proxy_recorder.bytes_used if self.proxy_recorder else 0,
                "proxy_truncated": self.proxy_truncated,
                "receiver_started": self.receiver_started,
                "receiver_snapshot": self.receiver_snapshot,
                "incomplete": self.incomplete,
                "incomplete_reasons": list(self.incomplete_reasons),
                "end_reason": self.end_reason,
                "session_closed": self.session_closed,
                "session_close_reason": self.session_close_reason,
                "result": self.result,
            }


class CaptureManager:
    def __init__(self, proxy_state: ProxyState):
        self.state = proxy_state
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        self._lock = threading.Lock()
        self._jobs = {}          # id -> CaptureJob
        self._session_jobs = {}  # session_id -> capture_id（活动任务）
        self._results = {}       # id -> 冻结结果 dict（含落盘信息）
        self._load_persisted()

    # ---------- 持久化：结果冻结后不可变 ----------
    def _load_persisted(self):
        try:
            for name in os.listdir(CAPTURE_DIR):
                if not (name.startswith("result-") and name.endswith(".json")):
                    continue
                cid = name[len("result-"):-len(".json")]
                try:
                    with open(os.path.join(CAPTURE_DIR, name), encoding="utf-8") as f:
                        self._results[cid] = json.load(f)
                except (OSError, json.JSONDecodeError):
                    continue
        except OSError:
            pass

    def _persist_result(self, job: CaptureJob, result: dict):
        path = os.path.join(CAPTURE_DIR, f"result-{job.id}.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        result["result_path"] = path
        with self._lock:
            self._results[job.id] = result

    # ---------- 启动 ----------
    def start_capture(self, session_id: int, duration: float):
        duration = max(1.0, min(float(duration), CAP_MAX_SECONDS))
        with self.state.lock:
            sess = next((s for s in self.state.sessions.values() if s.id == session_id), None)
            if sess is None or sess.closed or sess.state != "open":
                raise ValueError("会话不存在或已关闭，只能对活动会话抓包")
            if sess.capture is not None:
                raise ValueError("该会话已有进行中的抓包")
            with self._lock:
                if len(self._session_jobs) >= MAX_ACTIVE_CAPTURES:
                    raise ValueError(f"活动抓包数已达上限 {MAX_ACTIVE_CAPTURES}")
                capture_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
                job = CaptureJob(capture_id, sess, duration)
                sess.capture = job
                self._jobs[capture_id] = job
                self._session_jobs[sess.id] = capture_id
        t = threading.Thread(target=self._run, args=(job, sess), name=f"cap-{capture_id}",
                             daemon=True)
        t.start()
        return job

    def get_job(self, capture_id):
        with self._lock:
            return self._jobs.get(capture_id)

    def list_jobs(self):
        with self._lock:
            jobs = [j.public() for j in self._jobs.values()]
            results = list(self._results.values())
        jobs.sort(key=lambda x: x["started_wall"], reverse=True)
        results.sort(key=lambda x: x.get("started_wall", 0), reverse=True)
        return jobs, results

    def get_result(self, capture_id):
        with self._lock:
            return self._results.get(capture_id)

    def pcap_path(self, capture_id, side):
        with self._lock:
            result = self._results.get(capture_id)
        if result is None:
            return None
        if side == "proxy":
            return result.get("proxy_pcap")
        if side == "receiver":
            return result.get("receiver_pcap")
        return None

    # ---------- 会话关闭通知（事件循环 executor 调用） ----------
    def notify_session_closed(self, job: CaptureJob, reason):
        with job._lock:
            job.session_closed = True
            job.session_close_reason = reason

    # ---------- 主流程（独立工作线程） ----------
    def _run(self, job: CaptureJob, sess: Session):
        try:
            self._start_receiver(job, sess)
            if not job.receiver_started:
                self._finalize(job, sess, "receiver-unreachable")
                return
            self._arm_proxy(job, sess)
            if not job.armed:
                self._finalize(job, sess, "arm-failed")
                return
            job.state = "running"
            self.store_event(sess, job, f"抓包 {job.id} 两侧均已确认启动，窗口 {job.duration}s")
            self._wait_window(job, sess)
            self._finalize(job, sess, job.end_reason or "window-ended")
        except Exception as exc:  # 兜底：任何意外都要冻结证据并标记不完整
            with job._lock:
                if "internal-error" not in job.incomplete_reasons:
                    job.incomplete_reasons.append("internal-error")
                job.end_reason = f"exception: {exc}"
            try:
                self._finalize(job, sess, "exception")
            except Exception:
                pass

    def store_event(self, sess, job, note):
        self.state.store.log("event", client=job.client, session_id=job.session_id,
                             receiver=job.receiver, note=note)

    def _start_receiver(self, job: CaptureJob, sess: Session):
        """先启动接收器侧记录；带重试窗口，失联则标记证据不完整。"""
        url = RECEIVER_CONTROL[job.receiver] + "/capture/start"
        body = {
            "capture_id": job.id,
            "sender_ip": self._local_ip_toward(sess.receiver_addr[0]),
            "sender_port": job.upstream_port,
            "duration": job.duration,
            "max_bytes": CAP_MAX_BYTES,
        }
        deadline = time.monotonic() + RECEIVER_RETRY_WINDOW
        while time.monotonic() < deadline:
            status, resp = _http_json("POST", url, body)
            if status == 200 and resp.get("ok"):
                with job._lock:
                    job.receiver_started = True
                    job.receiver_snapshot = resp.get("capture")
                self.store_event(sess, job, f"接收器 {job.receiver} 已确认开始抓包")
                return
            time.sleep(0.5)
        with job._lock:
            if "receiver-unreachable" not in job.incomplete_reasons:
                job.incomplete_reasons.append("receiver-unreachable")

    @staticmethod
    def _local_ip_toward(remote_ip: str) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((remote_ip, 9))
            return s.getsockname()[0]
        finally:
            s.close()

    def _arm_proxy(self, job: CaptureJob, sess: Session):
        """接收器确认后代理侧才布防：保证代理记录全部落在接收器窗口内。"""
        try:
            local_ip = self._local_ip_toward(sess.receiver_addr[0])
            tuple4 = (local_ip, sess.receiver_addr[0],
                      job.upstream_port, sess.receiver_addr[1])
            rec = PcapRecorder(job.proxy_path, tuple4, max_bytes=CAP_MAX_BYTES)
            with job._lock:
                job.proxy_recorder = rec
                job.armed = True
                job.armed_wall = time.time()
        except OSError as exc:
            with job._lock:
                if "proxy-recorder-failed" not in job.incomplete_reasons:
                    job.incomplete_reasons.append("proxy-recorder-failed")
                job.end_reason = f"代理记录器初始化失败: {exc}"

    def _wait_window(self, job: CaptureJob, sess: Session):
        """等待抓包窗口结束，或会话提前关闭。"""
        deadline = time.monotonic() + job.duration
        while time.monotonic() < deadline:
            with job._lock:
                if job.session_closed:
                    job.end_reason = "session-closed"
                    return
            time.sleep(0.1)
        job.end_reason = "window-ended"

    # ---------- 冻结与对账 ----------
    def _finalize(self, job: CaptureJob, sess: Session, reason: str):
        job.state = "finalizing"
        with job._lock:
            job.stopped_wall = time.time()
            if not job.end_reason:
                job.end_reason = reason

        # 1) 代理侧先撤防再冻结（停止与收包交错时，撤防后的报文不再入文件）
        with job._lock:
            job.armed = False
            rec = job.proxy_recorder
            if rec is not None:
                rec.close()
                if rec.truncated and "proxy-cap-full" not in job.incomplete_reasons:
                    job.incomplete_reasons.append("proxy-cap-full")

        # 2) 接收器侧宽限后冻结，并取回最终快照
        if job.receiver_started:
            stop_url = RECEIVER_CONTROL[job.receiver] + "/capture/stop"
            status, resp = _http_json("POST", stop_url, {
                "capture_id": job.id, "grace": CAPTURE_STOP_GRACE,
            })
            if status != 200 or not resp.get("ok"):
                with job._lock:
                    if "receiver-lost-on-stop" not in job.incomplete_reasons:
                        job.incomplete_reasons.append("receiver-lost-on-stop")
            # 等待宽限期结束，接收器完成冻结
            time.sleep(CAPTURE_STOP_GRACE + 0.1)
            status, resp = _http_json(
                "GET", RECEIVER_CONTROL[job.receiver] + f"/capture/records?id={job.id}"
            )
            if status == 200 and resp.get("ok"):
                with job._lock:
                    job.receiver_snapshot = resp["capture"]
            else:
                with job._lock:
                    if "receiver-unreachable" not in job.incomplete_reasons:
                        job.incomplete_reasons.append("receiver-unreachable")

        # 3) 接收器侧超额
        snap = job.receiver_snapshot or {}
        if snap.get("truncated"):
            with job._lock:
                if "receiver-cap-full" not in job.incomplete_reasons:
                    job.incomplete_reasons.append("receiver-cap-full")

        # 4) 接收器侧 PCAP 落盘到代理结果目录（经代理统一下载，已下载内容不变）
        receiver_pcap = None
        if job.receiver_started:
            receiver_pcap = self._fetch_receiver_pcap(job)
            if receiver_pcap is None:
                with job._lock:
                    if "receiver-pcap-missing" not in job.incomplete_reasons:
                        job.incomplete_reasons.append("receiver-pcap-missing")

        # 5) 端口解冻（若会话已关闭）与会话引用清理
        with self.state.lock:
            port = job.upstream_port
            if sess.closed:
                self.state.ports.unfreeze(port)
            if sess.capture is job:
                sess.capture = None
        with self._lock:
            active_sid = self._session_jobs.pop(sess.id, None)

        # 6) 对账并冻结结果
        result = self._reconcile(job, receiver_pcap)
        with job._lock:
            job.result = result
            job.state = "done"
        self._persist_result(job, result)
        self.store_event(sess, job,
                         f"抓包 {job.id} 已冻结：证据{'不完整' if result['incomplete'] else '完整'}，"
                         f"已证实 {result['totals']['confirmed']}，"
                         f"未证实 {result['totals']['unproven']}，"
                         f"漏记 {result['totals']['missed']}")

    def _fetch_receiver_pcap(self, job: CaptureJob):
        url = RECEIVER_CONTROL[job.receiver] + f"/capture/pcap?id={job.id}"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=CAPTURE_HTTP_TIMEOUT) as resp:
                blob = resp.read()
            path = os.path.join(CAPTURE_DIR, f"receiver-{job.id}.pcap")
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(blob)
            os.replace(tmp, path)
            return path
        except (urllib.error.URLError, OSError):
            return None

    def _reconcile(self, job: CaptureJob, receiver_pcap):
        """按报文 SHA-256 摘要做多重集对账（重传按次数核对）。"""
        with job._lock:
            proxy_records = list(job.proxy_records)
            proxy_truncated = job.proxy_truncated
            reasons = list(job.incomplete_reasons)
            snap = dict(job.receiver_snapshot or {})
            started_wall = job.started_wall
            armed_wall = job.armed_wall
            stopped_wall = job.stopped_wall
            duration = job.duration

        # 接收器记录只保留代理布防之后的：只有两侧都确认启动后的报文可对账
        receiver_records = []
        receiver_window_extra = 0
        for r in snap.get("records", []):
            if armed_wall is not None and r["ts"] < armed_wall:
                receiver_window_extra += 1
                continue
            receiver_records.append(r)

        p_counts, r_counts = {}, {}
        previews = {}
        for r in proxy_records:
            p_counts[r["sha256"]] = p_counts.get(r["sha256"], 0) + 1
            previews.setdefault(r["sha256"], r.get("preview", ""))
        for r in receiver_records:
            r_counts[r["sha256"]] = r_counts.get(r["sha256"], 0) + 1

        rows = []
        totals = {"confirmed": 0, "unproven": 0, "missed": 0,
                  "proxy_sent": 0, "receiver_recv": 0}
        for digest in sorted(set(p_counts) | set(r_counts)):
            p_n, r_n = p_counts.get(digest, 0), r_counts.get(digest, 0)
            confirmed = min(p_n, r_n)
            unproven = max(p_n - r_n, 0)
            missed = max(r_n - p_n, 0)
            totals["confirmed"] += confirmed
            totals["unproven"] += unproven
            totals["missed"] += missed
            totals["proxy_sent"] += p_n
            totals["receiver_recv"] += r_n
            rows.append({
                "sha256": digest,
                "preview": previews.get(digest, ""),
                "proxy_count": p_n,
                "receiver_count": r_n,
                "confirmed": confirmed,
                "unproven": unproven,
                "missed": missed,
            })
        rows.sort(key=lambda x: (x["unproven"] == 0, -x["proxy_count"], x["sha256"]))

        # 证据完整性：两侧都成功、都没抓满、全程在线才算完整；
        # 不完整时只报告“未证实”，不断言丢包。
        # 接收器在代理布防前的毫秒级窗口记录属正常边界，按规则排除出对账即可，
        # 不据此判定证据不完整（数量仍作为 receiver_window_extra 公示）。
        incomplete = bool(reasons) or not job.receiver_started

        reason_labels = {
            "receiver-unreachable": "接收器失联（启动/停止/取结果时联系不上）",
            "receiver-lost-on-stop": "停止时接收器失联",
            "receiver-cap-full": "接收器抓包超过 1 MiB，后续只漏记",
            "proxy-cap-full": "代理抓包超过 1 MiB，后续只漏记",
            "proxy-recorder-failed": "代理记录器初始化失败",
            "receiver-pcap-missing": "接收器 PCAP 取回失败",
            "receiver-pre-arm-records":
                f"接收器窗口含 {receiver_window_extra} 条代理布防前记录（不计入对账）",
            "internal-error": "抓包流程内部异常",
        }
        return {
            "id": job.id,
            "session_id": job.session_id,
            "client": job.client,
            "receiver": job.receiver,
            "upstream_port": job.upstream_port,
            "duration": duration,
            "started_wall": started_wall,
            "armed_wall": armed_wall,
            "stopped_wall": stopped_wall,
            "end_reason": job.end_reason,
            "session_closed": job.session_closed,
            "session_close_reason": job.session_close_reason,
            "incomplete": incomplete,
            "incomplete_reasons": reasons,
            "incomplete_reason_text": [reason_labels.get(x, x) for x in reasons],
            "totals": totals,
            "rows": rows,
            "proxy_pcap": job.proxy_path,
            "receiver_pcap": receiver_pcap,
            "proxy_pcap_name": f"proxy-{job.id}.pcap",
            "receiver_pcap_name": f"receiver-{job.id}.pcap",
            "receiver_received_total": snap.get("received_total", 0),
            "receiver_dropped_total": snap.get("dropped_total", 0),
            "receiver_window_extra": receiver_window_extra,
            "proxy_truncated": proxy_truncated,
            "receiver_truncated": bool(snap.get("truncated")),
            "proxy_bytes": (job.proxy_recorder.bytes_used if job.proxy_recorder else 0),
            "receiver_bytes": snap.get("bytes_used", 0),
            "cap_max_bytes": CAP_MAX_BYTES,
        }


# ---------------- Flask 网页 ----------------
store = Store(DB_PATH)
state = ProxyState(store)
app = Flask(__name__)
app.secret_key = os.urandom(16)

_last_test = {}
_last_test_lock = threading.Lock()

DIRECTION_LABELS = {
    "c2r": "客户端→接收器",
    "r2c": "接收器→客户端",
    "event": "事件",
    "drop": "丢弃",
}


def _format_message(m):
    m = dict(m)
    m["ts"] = fmt_ts(m["ts"])
    m["direction"] = DIRECTION_LABELS.get(m["direction"], m["direction"])
    return m


@app.get("/")
def index():
    with _last_test_lock:
        lt = dict(_last_test) if _last_test else None
    jobs, results = state.capture_manager.list_jobs()
    return render_template(
        "index.html",
        target=store.get_target(),
        receivers={k: f"{h}:{p}" for k, (h, p) in RECEIVERS.items()},
        idle_timeout=SESSION_IDLE_TIMEOUT,
        udp_listen_port=UDP_LISTEN_PORT,
        cap_max_seconds=int(CAP_MAX_SECONDS),
        cap_max_kib=CAP_MAX_BYTES // 1024,
        last_test=lt,
        jobs=jobs,
        results=results,
    )


@app.get("/api/state")
def api_state():
    with _last_test_lock:
        lt = dict(_last_test) if _last_test else None
    jobs, results = state.capture_manager.list_jobs()
    return jsonify({
        "target": store.get_target(),
        "receivers": {k: f"{h}:{p}" for k, (h, p) in RECEIVERS.items()},
        "idle_timeout": SESSION_IDLE_TIMEOUT,
        "sessions": state.snapshot_sessions(),
        "messages": [_format_message(m) for m in store.recent_messages(100)],
        "last_test": lt,
        "capture_jobs": jobs,
        "capture_results": results,
    })


@app.post("/switch")
def switch():
    target = request.form.get("target", "")
    try:
        store.set_target(target)
        store.log("event", note=f"网页切换目标为接收器 {target}")
        flash(f"已切换到接收器 {target}。新会话走 {target}，旧会话继续走原接收器直至过期。", "ok")
    except Exception as exc:
        flash(f"切换保存失败，保留原目标 {store.get_target()}。原因：{exc}", "error")
    return redirect(url_for("index"))


@app.post("/test")
def test():
    global _last_test
    result = run_test(
        payload=request.form.get("payload", "PING"),
        delay_s=request.form.get("delay", "").strip(),
        client_port_s=request.form.get("client_port", "").strip(),
        wait_s=request.form.get("wait", "10").strip(),
    )
    with _last_test_lock:
        _last_test = result
    return redirect(url_for("index"))


def run_test(payload, delay_s, client_port_s, wait_s):
    """从网页后端经代理发一条试传报文并等待回包。"""
    try:
        wait = min(max(float(wait_s), 0.5), 60.0)
    except ValueError:
        wait = 10.0
    wire = payload
    try:
        delay = float(delay_s)
        if delay > 0:
            wire = f"DELAY:{delay}:{payload}"  # 接收器识别的延迟回包指令
    except ValueError:
        pass
    data = wire.encode()
    result = {"time": fmt_ts(time.time()), "payload": wire, "ok": False,
              "reply": "", "error": "", "rtt": None, "client": "", "receiver": None}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if client_port_s:
            sock.bind(("0.0.0.0", int(client_port_s)))
        sock.settimeout(wait)
        sock.connect(("127.0.0.1", UDP_LISTEN_PORT))
        result["client"] = fmt_addr(sock.getsockname())
        t0 = time.monotonic()
        sock.send(data)
        try:
            reply = sock.recv(65535)
            result["ok"] = True
            result["rtt"] = round(time.monotonic() - t0, 3)
            result["reply"] = preview(reply)
        except socket.timeout:
            result["error"] = f"等待回包超时（{wait}s）"
    except Exception as exc:
        result["error"] = f"发送失败：{exc}"
    finally:
        sock.close()
    time.sleep(0.05)  # 等代理把日志落库
    if result["client"]:
        result["receiver"] = store.latest_receiver_for_client(result["client"])
    return result


# ---------------- 抓包网页接口 ----------------
@app.post("/capture/start")
def capture_start():
    try:
        session_id = int(request.form.get("session_id", ""))
        duration = float(request.form.get("duration", "10"))
    except ValueError:
        flash("参数错误：会话 ID 或时长非法。", "error")
        return redirect(url_for("index"))
    try:
        job = state.capture_manager.start_capture(session_id, duration)
        flash(f"抓包 {job.id} 已提交：等待两侧确认启动，窗口最长 {int(CAP_MAX_SECONDS)} 秒。", "ok")
    except ValueError as exc:
        flash(f"无法启动抓包：{exc}", "error")
    return redirect(url_for("index"))


@app.get("/capture/result/<capture_id>")
def capture_result_page(capture_id):
    result = state.capture_manager.get_result(capture_id)
    if result is None:
        abort(404)
    return render_template("result.html", r=result)


@app.get("/capture/download/<capture_id>/<side>")
def capture_download(capture_id, side):
    if side not in ("proxy", "receiver"):
        abort(404)
    path = state.capture_manager.pcap_path(capture_id, side)
    if not path or not os.path.exists(path):
        abort(404)
    with open(path, "rb") as f:
        blob = f.read()
    fname = f"{side}-{capture_id}.pcap"
    return Response(
        blob,
        mimetype="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ---------------- 启动：asyncio 线程 + Flask 主线程 ----------------
def _run_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    state.loop = loop
    loop.run_until_complete(state.start())
    loop.run_forever()


def main():
    state.capture_manager = CaptureManager(state)
    t = threading.Thread(target=_run_loop, name="udp-proxy-loop", daemon=True)
    t.start()
    print(f"[proxy] 操作网页 http://{HTTP_HOST}:{HTTP_PORT}", flush=True)
    app.run(host=HTTP_HOST, port=HTTP_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
