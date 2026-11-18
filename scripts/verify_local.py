#!/usr/bin/env python3
"""本地端到端验证：不依赖 Docker，直接以子进程启动两个接收器和代理，
逐项验证原有转发行为与新增的上行抓包对账行为。

用法：python3 -I scripts/verify_local.py
（本机无 Flask 时自动使用 tools/flask_shim 垫片；Docker 镜像内仍是真 Flask。）
"""

import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIM = os.path.join(ROOT, "tools", "flask_shim")
sys.path.insert(0, SHIM)  # 无 Flask 环境下的最小兼容垫片（仅本地验证用）
sys.path.insert(0, ROOT)

PROXY_PY = os.path.join(ROOT, "proxy", "app.py")
RECEIVER_PY = os.path.join(ROOT, "receiver", "receiver.py")

UDP_PORT = 19000
HTTP_PORT = 18080
BASE = f"http://127.0.0.1:{HTTP_PORT}"
RA_CTRL, RB_CTRL = 19101, 19102

_failures = []


def check(name, cond, detail=""):
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  -- {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def http_get(path, base=BASE, timeout=15, allow_errors=False):
    req = urllib.request.Request(base + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            ct = r.headers.get("Content-Type", "")
            return r.status, (json.loads(data) if "json" in ct else data)
    except urllib.error.HTTPError as exc:
        if not allow_errors:
            raise
        return exc.code, exc.read()


def http_post(path, data, base=BASE, timeout=45, json_body=False):
    if json_body:
        body = json.dumps(data).encode()
        headers = {"Content-Type": "application/json"}
    else:
        body = urllib.parse.urlencode(data).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    req = urllib.request.Request(base + path, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                return r.status, raw
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_http_up(timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            http_get("/api/state")
            return True
        except Exception:
            time.sleep(0.3)
    return False


def wait_capture_done(cid, timeout=45):
    t0 = time.time()
    while time.time() - t0 < timeout:
        _, st = http_get("/api/state")
        for r in st["capture_results"]:
            if r["id"] == cid:
                return r
        time.sleep(0.3)
    return None


def udp_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("127.0.0.1", UDP_PORT))
    return s


def send_recv(sock, payload: bytes, timeout=5.0):
    sock.settimeout(timeout)
    sock.send(payload)
    return sock.recv(65535)


def start_receiver(name, port, ctrl, logdir, extra_env=None):
    env = dict(os.environ, RECEIVER_NAME=name, LISTEN_PORT=str(port),
               CONTROL_PORT=str(ctrl), REPLY_DELAY="0",
               CAPTURE_DIR=os.path.join(logdir, f"rcap-{name}"),
               PYTHONPATH=SHIM + os.pathsep + ROOT)
    if extra_env:
        env.update(extra_env)
    log = open(os.path.join(logdir, f"receiver-{name}.log"), "w")
    return subprocess.Popen([sys.executable, RECEIVER_PY], env=env,
                            stdout=log, stderr=subprocess.STDOUT)


def start_proxy(db_path, logdir, tag, extra_env=None):
    env = dict(
        os.environ,
        UDP_LISTEN_PORT=str(UDP_PORT), HTTP_PORT=str(HTTP_PORT),
        RECEIVER_A_HOST="127.0.0.1", RECEIVER_A_PORT="19001",
        RECEIVER_B_HOST="127.0.0.1", RECEIVER_B_PORT="19002",
        RECEIVER_A_CONTROL_URL=f"http://127.0.0.1:{RA_CTRL}",
        RECEIVER_B_CONTROL_URL=f"http://127.0.0.1:{RB_CTRL}",
        SESSION_IDLE_TIMEOUT="5", DB_PATH=db_path,
        CAPTURE_DIR=os.path.join(logdir, "captures"),
        PYTHONPATH=SHIM + os.pathsep + ROOT,
    )
    if extra_env:
        env.update(extra_env)
    log = open(os.path.join(logdir, f"proxy-{tag}.log"), "w")
    return subprocess.Popen([sys.executable, PROXY_PY], env=env,
                            stdout=log, stderr=subprocess.STDOUT)


# ---------------- PCAP 解析（验证 Wireshark 可打开的结构） ----------------
def parse_pcap(blob: bytes):
    """返回 (linktype, [payload...])，校验全局头/记录头/IP/UDP 结构与校验和。"""
    assert len(blob) >= 24, "PCAP 短于全局头"
    magic, ver_mj, ver_mn, _tz, _sig, snap, linktype = struct.unpack("<IHHiIII", blob[:24])
    assert magic == 0xA1B2C3D4 and (ver_mj, ver_mn) == (2, 4), "PCAP 魔数/版本错误"
    assert linktype == 1, "链路类型不是 Ethernet"

    def csum(data):
        if len(data) % 2:
            data += b"\x00"
        total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    off, payloads, frames = 24, [], []
    while off < len(blob):
        ts_s, ts_us, caplen, origlen = struct.unpack("<IIII", blob[off:off + 16])
        off += 16
        frame = blob[off:off + caplen]
        assert len(frame) == caplen and origlen == caplen, "记录长度不一致"
        off += caplen
        frames.append(frame)
        assert struct.unpack("!H", frame[12:14])[0] == 0x0800, "非 IPv4 帧"
        ihl = (frame[14] & 0x0F) * 4
        assert frame[14 + 9] == 17, "非 UDP 协议"
        ip_total = struct.unpack("!H", frame[14 + 2:14 + 4])[0]
        assert ip_total == len(frame) - 14, "IP 总长不一致"
        assert csum(frame[14:14 + ihl]) == 0, "IPv4 头校验和错误"
        u = 14 + ihl
        sport, dport, ulen, ucs = struct.unpack("!HHHH", frame[u:u + 8])
        assert ulen == len(frame) - 14 - ihl, "UDP 长度不一致"
        payload = frame[u + 8:]
        src_i, dst_i = struct.unpack("!II", frame[14 + 12:14 + 20])
        pseudo = struct.pack("!IIBBH", src_i, dst_i, 0, 17, ulen)
        assert csum(pseudo + frame[u:u + 8] + payload) == 0, "UDP 校验和错误"
        payloads.append({"sport": sport, "dport": dport, "payload": payload})
    assert off == len(blob), "PCAP 尾部有多余字节"
    return linktype, payloads


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main():
    tmp = tempfile.mkdtemp(prefix="cap-verify-")
    db_path = os.path.join(tmp, "proxy.db")
    # 接收器 B 开启测试丢包开关：含 LOST 的报文整包消失
    procs = [
        start_receiver("A", 19001, RA_CTRL, tmp),
        start_receiver("B", 19002, RB_CTRL, tmp, {"DROP_CONTAINS": "LOST"}),
    ]
    proxy = start_proxy(db_path, tmp, "run1")
    procs.append(proxy)
    try:
        if not wait_http_up():
            check("代理启动", False, f"日志目录 {tmp}")
            return 1
        print(f"--- 环境就绪（日志目录 {tmp}）---")

        # ========== 一、原有转发行为回归 ==========
        st = http_get("/api/state")[1]
        check("初始目标为 A", st["target"] == "A")
        c1 = udp_client()
        m1 = b"m1-hello"
        check("报文原样回传", send_recv(c1, m1) == m1)
        blob = bytes(range(256))
        check("二进制报文原样透传", send_recv(c1, blob) == blob)

        http_post("/switch", {"target": "B"})
        check("切换后当前目标为 B", http_get("/api/state")[1]["target"] == "B")
        m2 = b"m2-stick"
        check("旧会话报文仍有回包", send_recv(c1, m2) == m2)
        time.sleep(0.2)
        msgs = http_get("/api/state")[1]["messages"]
        e = [m for m in msgs if "m2-stick" in (m["payload"] or "")]
        check("切换后旧会话继续走接收器 A", e and e[0]["receiver"] == "A", str(e))

        print("--- 等待 6 秒让会话空闲过期 ---")
        time.sleep(6)
        m3 = b"m3-newsession"
        check("新会话报文有回包", send_recv(c1, m3) == m3)
        time.sleep(0.2)
        msgs = http_get("/api/state")[1]["messages"]
        e = [m for m in msgs if "m3-newsession" in (m["payload"] or "")]
        check("过期重建的新会话走接收器 B", e and e[0]["receiver"] == "B", str(e))

        c2 = udp_client()
        t0 = time.time()
        c2.send(b"DELAY:7:late1")
        time.sleep(max(0, 6 - (time.time() - t0)))
        check("过期后新会话报文有回包", send_recv(c2, b"ping2", timeout=3) == b"ping2")
        got_late = False
        c2.settimeout(0.2)
        while time.time() - t0 < 9:
            try:
                if b"late1" in c2.recv(65535):
                    got_late = True
            except socket.timeout:
                pass
        check("旧会话迟到的回包未送达重建的会话", not got_late)

        http_post("/test", {"payload": "webtest1", "wait": "5", "delay": "0",
                            "client_port": ""})
        time.sleep(0.2)
        lt = http_get("/api/state")[1]["last_test"]
        check("网页试传成功且回包一致", lt and lt["ok"] and lt["reply"] == "webtest1", str(lt))
        check("网页试传显示实际去向为 B", lt and lt["receiver"] == "B", str(lt))

        # ========== 二、接收器独立控制接口 ==========
        _, health = http_get("/health", base=f"http://127.0.0.1:{RB_CTRL}")
        check("接收器 B 控制接口健康", health.get("ok") and health["receiver"] == "B", str(health))
        status, body = http_post("/capture/start", {
            "capture_id": "selftest", "sender_ip": "127.0.0.1", "sender_port": 29999,
            "duration": 3, "max_bytes": 1048576},
            base=f"http://127.0.0.1:{RB_CTRL}", json_body=True)
        check("接收器启动抓包成功", status == 200 and body["ok"])
        status2, body2 = http_post("/capture/start", {
            "capture_id": "selftest", "sender_ip": "127.0.0.1", "sender_port": 29999,
            "duration": 3, "max_bytes": 1048576},
            base=f"http://127.0.0.1:{RB_CTRL}", json_body=True)
        check("同 id 重复启动幂等", status2 == 200 and body2["created"] is False)
        code, _ = http_get("/capture/pcap?id=selftest",
                           base=f"http://127.0.0.1:{RB_CTRL}", allow_errors=True)
        check("未停止前禁止下载 PCAP(409)", code == 409)
        http_post("/capture/stop", {"capture_id": "selftest", "grace": 0},
                  base=f"http://127.0.0.1:{RB_CTRL}", json_body=True)
        time.sleep(0.2)
        code, pcap_self = http_get("/capture/pcap?id=selftest",
                                   base=f"http://127.0.0.1:{RB_CTRL}")
        check("停止后可下载接收器 PCAP", code == 200 and pcap_self[:4] == b"\xd4\xc3\xb2\xa1")
        code, _ = http_get("/capture/pcap?id=nope",
                           base=f"http://127.0.0.1:{RB_CTRL}", allow_errors=True)
        check("未知抓包 id 返回 404", code == 404)

        # ========== 三、抓包 happy path：两侧完整 + 重传按次数 ==========
        c3 = udp_client()
        send_recv(c3, b"open-session")  # 建立到 B 的会话
        time.sleep(0.2)
        sessions = http_get("/api/state")[1]["sessions"]
        sess = next((x for x in sessions if x["client"].endswith(
            f":{c3.getsockname()[1]}")), None)
        check("找到活动会话", sess is not None, str(sessions))
        sid = sess["id"]
        upstream = sess["upstream_port"]

        http_post("/capture/start", {"session_id": sid, "duration": "5"})
        # 等两侧确认启动
        t0 = time.time()
        cid = None
        while time.time() - t0 < 8:
            st = http_get("/api/state")[1]
            for j in st["capture_jobs"]:
                if j["session_id"] == sid and j["armed"]:
                    cid = j["id"]
                    break
            if cid:
                break
            time.sleep(0.2)
        check("抓包两侧均确认启动", cid is not None)

        pkts = [b"cap-aaa", b"cap-bbb", b"cap-bbb", b"cap-ccc"]  # bbb 同文重发一次
        for p in pkts:
            c3.send(p)
            c3.settimeout(3)
            c3.recv(65535)
        result = wait_capture_done(cid)
        check("抓包结果已冻结", result is not None)
        happy_cid = happy_pp = happy_rp = None
        if result:
            check("证据完整（两侧在线且未超额）", result["incomplete"] is False,
                  str(result["incomplete_reasons"]))
            t = result["totals"]
            check("已证实到达=4", t["confirmed"] == 4, str(t))
            check("未证实=0、漏记=0", t["unproven"] == 0 and t["missed"] == 0, str(t))
            row_bbb = next((r for r in result["rows"] if r["preview"] == "cap-bbb"), None)
            check("同文重发按次数核对（bbb 两侧均为 2）",
                  row_bbb and row_bbb["proxy_count"] == 2
                  and row_bbb["receiver_count"] == 2 and row_bbb["confirmed"] == 2,
                  str(row_bbb))
            check("页面不断言丢包（字段口径为未证实）",
                  all("丢包" not in x for x in result["incomplete_reason_text"]))

            # 两份 PCAP 下载、结构校验、四元组正确
            _, pp = http_get(f"/capture/download/{cid}/proxy")
            _, rp = http_get(f"/capture/download/{cid}/receiver")
            lt_p, frames_p = parse_pcap(pp)
            lt_r, frames_r = parse_pcap(rp)
            check("两份 PCAP 结构合法且为 Ethernet 链路", lt_p == 1 and lt_r == 1)
            check("代理 PCAP 含 4 帧且端口为该会话上游端口",
                  len(frames_p) == 4 and all(f["sport"] == upstream for f in frames_p),
                  str([(f["sport"], f["dport"]) for f in frames_p]))
            check("接收器 PCAP 含 4 帧且源端口为该会话上游端口",
                  len(frames_r) == 4 and all(f["sport"] == upstream for f in frames_r))
            check("PCAP 载荷与实际报文逐字节一致",
                  sorted(f["payload"] for f in frames_p) == sorted(pkts)
                  and sorted(f["payload"] for f in frames_r) == sorted(pkts))
            # 重复下载字节不变
            _, pp2 = http_get(f"/capture/download/{cid}/proxy")
            _, rp2 = http_get(f"/capture/download/{cid}/receiver")
            check("重复下载 PCAP 字节一致（结果不可变）", pp == pp2 and rp == rp2)
            # 详情页可打开且含对账表
            code, page = http_get(f"/capture/result/{cid}")
            page = page.decode()
            check("对账详情页可打开", code == 200 and "按报文摘要对账" in page
                  and "证据完整" in page)
            happy_cid, happy_pp, happy_rp = cid, pp, rp

        # ========== 四、诱导真实未到达：完整证据下的“未证实” ==========
        c4 = udp_client()
        send_recv(c4, b"open-session-4")
        time.sleep(0.2)
        sess4 = next(x for x in http_get("/api/state")[1]["sessions"]
                     if x["client"].endswith(f":{c4.getsockname()[1]}"))
        http_post("/capture/start", {"session_id": sess4["id"], "duration": "4"})
        cid4 = None
        t0 = time.time()
        while time.time() - t0 < 8:
            for j in http_get("/api/state")[1]["capture_jobs"]:
                if j["session_id"] == sess4["id"] and j["armed"]:
                    cid4 = j["id"]
            if cid4:
                break
            time.sleep(0.2)
        c4.send(b"ok1"); c4.settimeout(3); c4.recv(65535)
        c4.send(b"LOST-pkt-xyz")  # 接收器 DROP_CONTAINS 命中，整包消失
        try:
            c4.settimeout(1.5); c4.recv(65535)
            lost_echoed = True
        except socket.timeout:
            lost_echoed = False
        c4.send(b"ok2"); c4.settimeout(3); c4.recv(65535)
        check("含 LOST 的报文确实未被回显", lost_echoed is False)
        r4 = wait_capture_done(cid4)
        check("未到达场景证据仍标记为完整（两侧在线）",
              r4 and r4["incomplete"] is False, str(r4 and r4["incomplete_reasons"]))
        if r4:
            check("未证实=1、已证实=2（不断言丢包）",
                  r4["totals"]["unproven"] == 1 and r4["totals"]["confirmed"] == 2,
                  str(r4["totals"]))
            check("接收器侧独立记录仅 2 条（另 1 条到达后被测试丢弃）",
                  r4["totals"]["receiver_recv"] == 2
                  and r4["receiver_received_total"] == 3
                  and r4["receiver_dropped_total"] == 1,
                  str((r4["totals"], r4["receiver_received_total"],
                       r4["receiver_dropped_total"])))
            _, rp4 = http_get(f"/capture/download/{cid4}/receiver")
            _, fr4 = parse_pcap(rp4)
            check("接收器 PCAP 中不存在被丢报文",
                  all(b"LOST" not in f["payload"] for f in fr4))
            _, pp4 = http_get(f"/capture/download/{cid4}/proxy")
            _, fp4 = parse_pcap(pp4)
            check("代理 PCAP 仍保留实际发出的被丢报文原文",
                  any(b"LOST-pkt-xyz" in f["payload"] for f in fp4))

        # ========== 五、抓包中会话关闭：端口冻结，文件只含本会话 ==========
        c5 = udp_client()
        send_recv(c5, b"open-session-5")
        time.sleep(0.2)
        sess5 = next(x for x in http_get("/api/state")[1]["sessions"]
                     if x["client"].endswith(f":{c5.getsockname()[1]}"))
        port5 = sess5["upstream_port"]
        http_post("/capture/start", {"session_id": sess5["id"], "duration": "9"})
        cid5 = None
        t0 = time.time()
        while time.time() - t0 < 8:
            for j in http_get("/api/state")[1]["capture_jobs"]:
                if j["session_id"] == sess5["id"] and j["armed"]:
                    cid5 = j["id"]
            if cid5:
                break
            time.sleep(0.2)
        c5.send(b"s5-one"); c5.settimeout(3); c5.recv(65535)
        c5.send(b"s5-two"); c5.settimeout(3); c5.recv(65535)
        print("--- 等待会话空闲过期（抓包仍在窗口内）---")
        time.sleep(6)
        # 会话已关闭；再建一个新会话制造流量，验证端口未被复用串入
        c6 = udp_client()
        send_recv(c6, b"other-session-traffic")
        r5 = wait_capture_done(cid5)
        check("抓包随会话关闭而结束并冻结",
              r5 and r5["session_closed"] is True and r5["end_reason"] == "session-closed",
              str(r5 and r5["end_reason"]))
        if r5:
            _, pp5 = http_get(f"/capture/download/{cid5}/proxy")
            _, rp5 = http_get(f"/capture/download/{cid5}/receiver")
            _, fp5 = parse_pcap(pp5)
            _, fr5 = parse_pcap(rp5)
            check("两份 PCAP 只含本会话本窗口报文（2 条）",
                  len(fp5) == 2 and len(fr5) == 2
                  and {f["payload"] for f in fp5} == {b"s5-one", b"s5-two"}
                  and {f["payload"] for f in fr5} == {b"s5-one", b"s5-two"})
            check("PCAP 四元组仍指向被冻结的上游端口",
                  all(f["sport"] == port5 for f in fp5 + fr5))
        check("端口冻结未影响后续新会话转发", c6 is not None)

        # ========== 五-B、停止宽限与停止/收包交错：在途报文仍入文件，之后报文不入 ==========
        c5b = udp_client()
        send_recv(c5b, b"open-session-5b")
        time.sleep(0.2)
        sess5b = next(x for x in http_get("/api/state")[1]["sessions"]
                      if x["client"].endswith(f":{c5b.getsockname()[1]}"))
        http_post("/capture/start", {"session_id": sess5b["id"], "duration": "3"})
        cid5b = None
        t0 = time.time()
        while time.time() - t0 < 8:
            for j in http_get("/api/state")[1]["capture_jobs"]:
                if j["session_id"] == sess5b["id"] and j["armed"]:
                    cid5b = j["id"]
            if cid5b:
                break
            time.sleep(0.1)
        check("5b 抓包已布防", cid5b is not None)
        c5b.send(b"grace-before")  # 窗口内正常报文
        c5b.settimeout(3); c5b.recv(65535)
        # 等到接近窗口结束，使下一条报文落在“停止宽限期”的在途区间
        st_now = http_get("/api/state")[1]
        job_now = next(j for j in st_now["capture_jobs"] if j["id"] == cid5b)
        elapsed = time.time() - job_now["armed_wall"]
        remain = max(0.0, 3.0 - elapsed)
        time.sleep(max(0.0, remain - 0.05))  # 在窗口结束前 ~50ms 发出，落入宽限在途
        c5b.send(b"grace-inflight")
        c5b.settimeout(3); c5b.recv(65535)
        r5b = wait_capture_done(cid5b)
        check("宽限期在途报文已进入接收器 PCAP",
              r5b and r5b["incomplete"] is False, str(r5b and r5b["incomplete_reasons"]))
        fr5b = []
        if r5b:
            _, rp5b = http_get(f"/capture/download/{cid5b}/receiver")
            _, fr5b = parse_pcap(rp5b)
            check("接收器 PCAP 同时含窗口内与宽限在途两条报文",
                  {f["payload"] for f in fr5b}
                  == {b"grace-before", b"grace-inflight"},
                  str(sorted(f["payload"] for f in fr5b)))
        # 冻结之后继续发报：转发/回显正常，但不再进入已冻结文件，且代理不崩溃
        time.sleep(0.4)
        check("冻结后新报文仍原样转发", send_recv(c5b, b"after-freeze") == b"after-freeze")
        _, rp5b2 = http_get(f"/capture/download/{cid5b}/receiver")
        _, fr5b2 = parse_pcap(rp5b2)
        check("已下载结果不随冻结后收报变化（不可变）",
              all(f["payload"] != b"after-freeze" for f in fr5b2) and len(fr5b2) == len(fr5b))

        # ========== 六、接收器失联：证据不完整，不得断言丢包 ==========
        rb = procs[1]  # 接收器 B 子进程
        c7 = udp_client()
        send_recv(c7, b"open-session-7")
        time.sleep(0.2)
        sess7 = next(x for x in http_get("/api/state")[1]["sessions"]
                     if x["client"].endswith(f":{c7.getsockname()[1]}"))
        http_post("/capture/start", {"session_id": sess7["id"], "duration": "4"})
        time.sleep(1.5)  # 等接收器确认启动
        c7.send(b"before-kill"); c7.settimeout(3); c7.recv(65535)
        rb.terminate(); rb.wait(timeout=10)
        c7.send(b"after-kill")  # 接收器已死，无回包
        time.sleep(0.5)
        r7 = wait_capture_done(
            next(j["id"] for j in http_get("/api/state")[1]["capture_jobs"]
                 if j["session_id"] == sess7["id"]), timeout=30)
        check("接收器失联后结果标记证据不完整",
              r7 and r7["incomplete"] is True
              and any("receiver" in x for x in r7["incomplete_reasons"]),
              str(r7 and r7["incomplete_reasons"]))
        if r7:
            code, page = http_get(f"/capture/result/{r7['id']}", allow_errors=True)
            page = page.decode()
            check("详情页明示不得断言丢包", "不得据此断言丢包" in page)
        # 接收器恢复
        rb2 = start_receiver("B", 19002, RB_CTRL, tmp, {"DROP_CONTAINS": "LOST"})
        procs[1] = rb2
        time.sleep(1.0)
        check("接收器 B 恢复后健康",
              http_get("/health", base=f"http://127.0.0.1:{RB_CTRL}")[1].get("ok") is True)

        # ========== 七、重启代理：结果持久化、下载不变、目标保留、会话清空 ==========
        proxy.terminate(); proxy.wait(timeout=10)
        proxy = start_proxy(db_path, tmp, "run2")
        procs[2] = proxy
        check("代理重启后恢复", wait_http_up())
        st = http_get("/api/state")[1]
        check("重启后目标保留为 B", st["target"] == "B")
        check("重启后会话已清空", st["sessions"] == [])
        ids = {r["id"] for r in st["capture_results"]}
        check("历史抓包结果重启后仍在", happy_cid in ids, str(ids))
        _, pp_after = http_get(f"/capture/download/{happy_cid}/proxy")
        _, rp_after = http_get(f"/capture/download/{happy_cid}/receiver")
        check("重启后已下载 PCAP 内容保持不变",
              pp_after == happy_pp and rp_after == happy_rp)

        # ========== 八、1 MiB 硬上限：抓满只漏记，转发不受影响 ==========
        proxy.terminate(); proxy.wait(timeout=10)
        proxy = start_proxy(db_path, tmp, "run3", {"CAP_MAX_BYTES": "400"})
        procs[2] = proxy
        check("小上限代理重启后恢复", wait_http_up())
        c8 = udp_client()
        send_recv(c8, b"open-session-8")
        time.sleep(0.2)
        sess8 = next(x for x in http_get("/api/state")[1]["sessions"]
                     if x["client"].endswith(f":{c8.getsockname()[1]}"))
        http_post("/capture/start", {"session_id": sess8["id"], "duration": "6"})
        cid8 = None
        t0 = time.time()
        while time.time() - t0 < 8:
            for j in http_get("/api/state")[1]["capture_jobs"]:
                if j["session_id"] == sess8["id"] and j["armed"]:
                    cid8 = j["id"]
            if cid8:
                break
            time.sleep(0.2)
        echoed_after_full = 0
        for i in range(40):
            p = f"flood-{i:03d}-".encode() + b"x" * 40
            c8.send(p)
            c8.settimeout(3)
            try:
                if c8.recv(65535) == p:
                    echoed_after_full += 1
            except socket.timeout:
                pass
        r8 = wait_capture_done(cid8)
        check("抓满后标记证据不完整（代理 cap-full）",
              r8 and r8["incomplete"] is True
              and "proxy-cap-full" in r8["incomplete_reasons"],
              str(r8 and r8["incomplete_reasons"]))
        if r8:
            check("代理侧 PCAP 不超过本测 400B 预算",
                  r8["proxy_bytes"] <= 400, str(r8["proxy_bytes"]))
            _, pp8 = http_get(f"/capture/download/{cid8}/proxy")
            _, rp8 = http_get(f"/capture/download/{cid8}/receiver")
            check("抓满后的 PCAP 仍是合法文件", parse_pcap(pp8) and parse_pcap(rp8))
        check("抓满只漏记不影响原样转发（40 条全部回显）",
              echoed_after_full == 40, f"实际回显 {echoed_after_full}/40")

        # ========== 九、存储故障时切换保留原目标（单元级） ==========
        os.environ["DB_PATH"] = os.path.join(tmp, "unit.db")
        sys.path.insert(0, os.path.join(ROOT, "proxy"))
        import importlib
        import app as proxy_app
        importlib.reload(proxy_app)
        s = proxy_app.Store(os.path.join(tmp, "unit-t.db"))
        s.set_target("B")
        s._conn.close()
        failed = False
        try:
            s.set_target("A")
        except Exception:
            failed = True
        check("保存失败时切换报错且保留原目标", failed and s.get_target() == "B")

    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()

    print("---")
    if _failures:
        print(f"共 {len(_failures)} 项失败: {_failures}")
        return 1
    print("全部验证通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
