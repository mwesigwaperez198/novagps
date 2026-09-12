"""Packet capture and traffic analysis tools."""

import json
import os
import re
import shutil
import subprocess
import time
from typing import Optional

from ..tools import Tool, ToolResult, ToolRegistry


class PacketCapture(Tool):
    name = "packet_capture"
    description = (
        "Capture live packets or analyze a pcap file. Reveals senders, receivers, "
        "requests, DNS queries, TCP flags. Engine: tshark → tcpdump → raw socket."
    )
    category = "network"

    def execute(
        self,
        interface: str = "",
        count: int = 25,
        duration: int = 10,
        protocol: str = "all",
        host: str = "",
        port: int = 0,
        pcap_file: str = "",
        **kwargs,
    ) -> ToolResult:
        if pcap_file:
            return self._analyze_pcap(pcap_file, protocol, host, port)

        engine = self._detect_engine()
        if engine == "none":
            return self._raw_socket_capture(duration, protocol, host, port, count)

        if engine == "tshark":
            return self._tshark_capture(interface, count, duration, protocol, host, port)
        else:
            return self._tcpdump_capture(interface, count, duration, protocol, host, port)

    def _detect_engine(self) -> str:
        if shutil.which("tshark"):
            return "tshark"
        if shutil.which("tcpdump"):
            return "tcpdump"
        return "none"

    def _tshark_capture(self, interface, count, duration, protocol, host, port) -> ToolResult:
        args = ["tshark", "-T", "fields", "-E", "header=y", "-E", "separator=|",
                "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
                "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport",
                "-e", "udp.dstport", "-e", "dns.qry.name", "-e", "dns.a",
                "-e", "tcp.flags.str", "-e", "_ws.col.Protocol", "-e", "frame.len"]
        if interface:
            args += ["-i", interface]
        else:
            args += ["-i", "any"]
        if count > 0:
            args += ["-c", str(count)]
        if duration > 0:
            args += ["-a", f"duration:{duration}"]
        if host:
            args += ["-f", f"host {host}"]
        if port > 0:
            args += ["-f", f"port {port}"]
        if protocol == "dns":
            args += ["-f", "udp port 53 or tcp port 53"]
        elif protocol == "tcp":
            args += ["-f", "tcp"]

        return self._run_capture(args, "tshark")

    def _tcpdump_capture(self, interface, count, duration, protocol, host, port) -> ToolResult:
        args = ["tcpdump", "-n", "-tttt", "-v"]
        iface = interface or "en0"
        args += ["-i", iface]
        if count > 0:
            args += ["-c", str(count)]
        if duration > 0:
            args += ["-z", str(duration)]
        if host:
            args += ["host", host]
        if port > 0:
            args += ["port", str(port)]
        if protocol == "dns":
            args += ["udp", "port", "53"]
        elif protocol == "tcp":
            args += ["tcp"]

        return self._run_capture(args, "tcpdump")

    def _raw_socket_capture(self, duration, protocol, host, port, count) -> ToolResult:
        try:
            import socket as _sock
            if not os.environ.get("NOVA_ALLOW_RAW_SOCK"):
                return ToolResult(
                    success=False, output=None,
                    error="No tshark/tcpdump available. Set NOVA_ALLOW_RAW_SOCK=1 for raw socket capture (requires root).",
                )
            raw = _sock.socket(_sock.AF_INET, _sock.SOCK_RAW, _sock.IPPROTO_TCP)
            raw.settimeout(min(duration, 30))
            packets = []
            start = time.time()
            while time.time() - start < duration and len(packets) < count:
                try:
                    data, addr = raw.recvfrom(65535)
                    ts = time.time()
                    packets.append(self._parse_raw_packet(data, ts))
                except _sock.timeout:
                    break
            raw.close()
            return self._summarize_packets(packets, "raw_socket")
        except Exception as e:
            return ToolResult(success=False, output=None, error=f"Raw socket failed: {e}")

    def _parse_raw_packet(self, data: bytes, ts: float) -> dict:
        ip_header = data[:20]
        ihl = (ip_header[0] & 0x0F) * 4
        proto = ip_header[9]
        src = ".".join(str(b) for b in ip_header[12:16])
        dst = ".".join(str(b) for b in ip_header[16:20])

        pkt = {
            "time": round(ts, 6), "src": src, "dst": dst,
            "proto": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto)),
            "len": len(data),
        }
        if proto == 6 and len(data) > ihl + 13:
            tcp = data[ihl:]
            pkt["src_port"] = (tcp[0] << 8) | tcp[1]
            pkt["dst_port"] = (tcp[2] << 8) | tcp[3]
            flags = tcp[13]
            pkt["tcp_flags"] = self._tcp_flags_str(flags)
        return pkt

    @staticmethod
    def _tcp_flags_str(flags_byte: int) -> str:
        names = []
        if flags_byte & 0x02: names.append("SYN")
        if flags_byte & 0x10: names.append("ACK")
        if flags_byte & 0x01: names.append("FIN")
        if flags_byte & 0x04: names.append("RST")
        if flags_byte & 0x08: names.append("PSH")
        if flags_byte & 0x20: names.append("URG")
        return ",".join(names) or "NONE"

    def _run_capture(self, args: list, engine: str) -> ToolResult:
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True, timeout=35, stderr=subprocess.PIPE,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return self._parse_output(proc.stdout, engine)
            stderr = proc.stderr.strip()[:300]
            if "permission denied" in stderr.lower() or "not permitted" in stderr.lower() or "Operation not permitted" in stderr:
                return ToolResult(
                    success=False, output=None,
                    error=f"{engine} needs root. Run `sudo ./lau.sh` or pass a pcap file instead.",
                )
            if proc.returncode != 0:
                return ToolResult(success=False, output=None, error=f"{engine} error: {stderr}")
            return ToolResult(success=True, output={"engine": engine, "packets": [], "message": "No packets captured."})
        except FileNotFoundError:
            return ToolResult(success=False, output=None, error=f"{engine} not found.")
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output=None, error=f"{engine} capture timed out (35s).")

    def _parse_output(self, output: str, engine: str) -> ToolResult:
        lines = [l.strip() for l in output.strip().splitlines() if l.strip()]
        if engine == "tshark":
            return self._parse_tshark_fields(lines)
        return self._parse_tcpdump_text(lines)

    def _parse_tshark_fields(self, lines: list) -> ToolResult:
        if len(lines) < 2:
            return ToolResult(success=True, output={"engine": "tshark", "packets": [], "message": "No packets captured."})
        packets = []
        for line in lines[1:]:
            parts = line.split("|")
            if len(parts) < 9:
                continue
            pkt = {"time": parts[0], "src": parts[1], "dst": parts[2]}
            if parts[3]: pkt["src_port"] = parts[3]
            if parts[4]: pkt["dst_port"] = parts[4]
            if parts[5]: pkt["udp_src"] = parts[5]
            if parts[6]: pkt["udp_dst"] = parts[6]
            if parts[7]: pkt["dns_query"] = parts[7]
            if parts[8]: pkt["dns_answer"] = parts[8]
            if parts[9]: pkt["tcp_flags"] = parts[9]
            pkt["proto"] = parts[10] if len(parts) > 10 else ""
            if parts[11]: pkt["length"] = parts[11]
            packets.append(pkt)
        return self._summarize_packets(packets, "tshark")

    def _parse_tcpdump_text(self, lines: list) -> ToolResult:
        packets = []
        ip_re = re.compile(
            r"^(\S+\s+\S+)\s+IP\s+(\S+)\s+>\s+(\S+):\s+(.*)"
        )
        for line in lines:
            m = ip_re.match(line)
            if not m:
                continue
            pkt = {
                "time": m.group(1),
                "src": m.group(2).rsplit(".", 1)[0] if "." in m.group(2) else m.group(2),
                "dst": m.group(3).rsplit(".", 1)[0] if "." in m.group(3) else m.group(3),
            }
            if ":" in m.group(2):
                pkt["src_port"] = m.group(2).rsplit(".", 1)[-1]
            elif "." in m.group(2) and m.group(2).rsplit(".", 1)[-1].isdigit():
                pkt["src_port"] = m.group(2).rsplit(".", 1)[-1]
            if ":" in m.group(3):
                pkt["dst_port"] = m.group(3).rsplit(".", 1)[-1]
            elif "." in m.group(3) and m.group(3).rsplit(".", 1)[-1].isdigit():
                pkt["dst_port"] = m.group(3).rsplit(".", 1)[-1]
            rest = m.group(4)
            flags_m = re.search(r"Flags \[([^\]]+)\]", rest)
            if flags_m:
                pkt["tcp_flags"] = flags_m.group(1)
            dns_m = re.search(r"(?:A\?|AAAA\?)\s+(\S+)", rest)
            if dns_m:
                pkt["dns_query"] = dns_m.group(1).rstrip(".")
            packets.append(pkt)
        return self._summarize_packets(packets, "tcpdump")

    def _analyze_pcap(self, path: str, protocol: str, host: str, port: int) -> ToolResult:
        engine = "tshark" if shutil.which("tshark") else "tcpdump" if shutil.which("tcpdump") else "none"
        if engine == "none":
            return ToolResult(success=False, output=None, error="Neither tshark nor tcpdump installed — cannot read pcap.")
        if not os.path.exists(path):
            return ToolResult(success=False, output=None, error=f"File not found: {path}")

        if engine == "tshark":
            args = ["tshark", "-r", path, "-T", "fields", "-E", "header=y", "-E", "separator=|",
                    "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
                    "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport",
                    "-e", "udp.dstport", "-e", "dns.qry.name", "-e", "dns.a",
                    "-e", "tcp.flags.str", "-e", "_ws.col.Protocol", "-e", "frame.len"]
            if protocol == "dns": args += ["-Y", "dns"]
            elif protocol == "tcp": args += ["-Y", "tcp"]
            if host: args += ["-Y", f"ip.addr == {host}"]
            if port > 0: args += ["-Y", f"tcp.port == {port} || udp.port == {port}"]
        else:
            args = ["tcpdump", "-n", "-tttt", "-v", "-r", path]
            if host: args += ["host", host]
            if port > 0: args += ["port", str(port)]
            if protocol == "dns": args += ["udp", "port", "53"]
            elif protocol == "tcp": args += ["tcp"]

        return self._run_capture(args, engine)

    def _summarize_packets(self, packets: list, engine: str) -> ToolResult:
        senders = set()
        receivers = set()
        dns_queries = []
        tcp_conns = []
        proto_counts = {}

        for p in packets:
            s, d = p.get("src", ""), p.get("dst", "")
            if s: senders.add(s)
            if d: receivers.add(d)
            proto = p.get("proto", "")
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
            if p.get("dns_query"):
                dns_queries.append({
                    "query": p["dns_query"],
                    "answer": p.get("dns_answer", ""),
                })
            if p.get("tcp_flags"):
                tcp_conns.append({
                    "src": s, "dst": d,
                    "src_port": p.get("src_port", ""),
                    "dst_port": p.get("dst_port", ""),
                    "flags": p["tcp_flags"],
                })

        unique_dns = [dict(t) for t in {tuple(sorted(d.items())) for d in dns_queries}][:30]
        return ToolResult(
            success=True,
            output={
                "engine": engine,
                "total_packets": len(packets),
                "senders": sorted(senders),
                "receivers": sorted(receivers),
                "protocol_distribution": proto_counts,
                "dns_queries": unique_dns,
                "tcp_connections": tcp_conns[:30],
                "packets": packets[:40],
            },
        )


def register_packet_tools(registry: ToolRegistry):
    registry.register(PacketCapture())
