#!/usr/bin/env python3
"""纯标准库 PCAP 写入器（Wireshark 可直接打开）。

链路类型 LINKTYPE_ETHERNET(1)：为每个 UDP 数据报自行拼装
以太网/IPv4/UDP 头并计算真实校验和，使 Wireshark 能完整解析。

设计要点：
- 写盘即用，进程崩溃也留下可打开的文件；
- 调用方用 ``would_exceed`` 做 1 MiB 硬预算判断，超额只停止记录，
  不影响数据报的原样转发；
- 不依赖任何第三方库。
"""

import struct

PCAP_MAGIC = 0xA1B2C3D4          # 微秒时间戳、小端
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
LINKTYPE_ETHERNET = 1

ETH_HEADER_LEN = 14
IPV4_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ETH_PAYLOAD_OFFSET = ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN

# 每个数据报落盘的固定开销：PCAP 记录头(16) + 以太网(14) + IPv4(20) + UDP(8)
FRAME_OVERHEAD = 16 + ETH_PAYLOAD_OFFSET


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip_to_int(ip: str) -> int:
    parts = [int(x) for x in ip.split(".")]
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        raise ValueError(f"非法 IPv4 地址: {ip!r}")
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def build_udp_frame(payload: bytes, src_ip: str, dst_ip: str,
                    src_port: int, dst_port: int) -> bytes:
    """把 UDP 载荷封装成含以太网/IPv4/UDP 头的完整帧。"""
    if len(payload) > 65507:
        raise ValueError("UDP 载荷超长")
    src_i, dst_i = _ip_to_int(src_ip), _ip_to_int(dst_ip)
    udp_len = UDP_HEADER_LEN + len(payload)
    ip_len = IPV4_HEADER_LEN + udp_len

    # ---- IPv4 头（无选项）----
    ip_header = struct.pack(
        "!BBHHHBBHII",
        0x45, 0, ip_len,
        0x1234,                 # 固定标识，抓包文件无需分片
        0,                      # 无分片
        64, 17, 0,              # TTL、协议 17=UDP、头校验和稍后算
        src_i, dst_i,
    )
    ip_cs = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBHII",
        0x45, 0, ip_len, 0x1234, 0, 64, 17, ip_cs, src_i, dst_i,
    )

    # ---- UDP 头（校验和可选，但填真实值 Wireshark 解析更友好）----
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    pseudo = struct.pack("!IIBBH", src_i, dst_i, 0, 17, udp_len)
    udp_cs = _checksum(pseudo + udp_header + payload)
    if udp_cs == 0:
        udp_cs = 0xFFFF
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, udp_cs)

    # ---- 以太网头：本机生成的固定 MAC，仅用于承载 ----
    eth_header = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth_header + ip_header + udp_header + payload


def global_header() -> bytes:
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
        0, 0, 65535, LINKTYPE_ETHERNET,
    )


def packet_record(frame: bytes, ts_sec: int, ts_usec: int,
                  orig_len: int = None) -> bytes:
    cap_len = len(frame)
    return struct.pack("<IIII", ts_sec, ts_usec, cap_len,
                       orig_len if orig_len is not None else cap_len) + frame


class PcapRecorder:
    """磁盘 PCAP 记录器：构造即写全局头，超额由调用方预算控制。

    元组 (src_ip, dst_ip, src_port, dst_port) 在一次抓包内固定，
    保证文件中的报文四元组一致、可逐条核对。
    """

    def __init__(self, path, tuple4, max_bytes=1024 * 1024):
        self.path = path
        self.src_ip, self.dst_ip, self.src_port, self.dst_port = tuple4
        self.max_bytes = max_bytes
        self.bytes_used = len(global_header())
        self.packets = 0
        self.truncated = False
        self._f = open(path, "wb")
        self._f.write(global_header())
        self._f.flush()

    def would_exceed(self, payload_len: int) -> bool:
        """写入该载荷是否会突破 1 MiB 硬上限（含全部封装与记录头开销）。"""
        return self.bytes_used + FRAME_OVERHEAD + payload_len > self.max_bytes

    def record(self, payload: bytes, ts_sec: int, ts_usec: int) -> bool:
        """写入一帧。超额或已截断/已关闭则拒绝写入并返回 False（绝不抛给转发路径）。"""
        if self.truncated or self.would_exceed(len(payload)):
            self.truncated = True
            return False
        frame = build_udp_frame(
            payload, self.src_ip, self.dst_ip, self.src_port, self.dst_port
        )
        try:
            self._f.write(packet_record(frame, ts_sec, ts_usec))
            self._f.flush()
        except (OSError, ValueError):
            # ValueError：文件已被停止流程关闭（停止与收包交错的极端情形）
            self.truncated = True
            return False
        self.bytes_used += len(frame) + 16
        self.packets += 1
        return True

    def close(self):
        try:
            self._f.flush()
            self._f.close()
        except OSError:
            pass
