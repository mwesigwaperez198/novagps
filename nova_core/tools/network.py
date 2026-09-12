"""Network diagnostic and resilience tools."""

import socket
import subprocess
import time
import statistics
from typing import Optional

from ..tools import Tool, ToolResult, ToolRegistry


class ConnectivityProbe(Tool):
    name = "connectivity_probe"
    description = "Test network connectivity to a target with retry and latency measurement."
    category = "network"

    def execute(self, host: str = "8.8.8.8", port: int = 53, timeout: float = 3.0, retries: int = 3, **kwargs) -> ToolResult:
        latencies = []
        successes = 0
        failures = 0

        for _ in range(retries):
            try:
                start = time.time()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    sock.connect((host, port))
                elapsed = (time.time() - start) * 1000
                latencies.append(elapsed)
                successes += 1
            except Exception:
                failures += 1

        stats = {
            "host": host,
            "port": port,
            "retries": retries,
            "successes": successes,
            "failures": failures,
            "reachable": successes > 0,
        }

        if latencies:
            stats["latency_ms"] = {
                "min": round(min(latencies), 2),
                "max": round(max(latencies), 2),
                "avg": round(statistics.mean(latencies), 2),
                "stdev": round(statistics.stdev(latencies), 2) if len(latencies) > 1 else 0,
            }

        return ToolResult(success=True, output=stats)


class Traceroute(Tool):
    name = "traceroute"
    description = "Trace the network route to a destination host."
    category = "network"

    def execute(self, host: str = "8.8.8.8", max_hops: int = 15, timeout: float = 5.0, **kwargs) -> ToolResult:
        try:
            result = subprocess.run(
                ["traceroute", "-m", str(max_hops), "-w", str(int(timeout)), host],
                capture_output=True, text=True, timeout=timeout * max_hops + 10,
            )
            hops = []
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    hop = {"ttl": parts[0].strip("*")}
                    if parts[1] != "*":
                        hop["host"] = parts[1]
                        hop["time_ms"] = parts[2] if len(parts) > 2 else "?"
                    else:
                        hop["host"] = "*"
                        hop["time_ms"] = "*"
                    hops.append(hop)

            return ToolResult(
                success=True,
                output={"host": host, "hops": hops, "hop_count": len(hops)},
            )
        except FileNotFoundError:
            return ToolResult(success=True, output={"host": host, "hops": [], "error": "traceroute not installed"})
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))


class MTUTester(Tool):
    name = "mtu_test"
    description = "Test effective MTU by sending packets of varying sizes."
    category = "network"

    def execute(self, host: str = "8.8.8.8", timeout: float = 2.0, **kwargs) -> ToolResult:
        sizes = [1472, 1400, 1200, 1000, 576]
        results = []

        for payload_size in sizes:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                payload = b"X" * payload_size
                start = time.time()
                sock.sendto(payload, (host, 80))
                try:
                    sock.recvfrom(1024)
                except socket.timeout:
                    pass
                elapsed = (time.time() - start) * 1000
                results.append({"payload_size": payload_size, "mtu_estimate": payload_size + 28, "latency_ms": round(elapsed, 2), "delivered": True})
                sock.close()
            except Exception:
                results.append({"payload_size": payload_size, "delivered": False})

        working = [r for r in results if r.get("delivered")]
        effective_mtu = working[0]["mtu_estimate"] if working else 0

        return ToolResult(
            success=True,
            output={
                "host": host,
                "effective_mtu": effective_mtu,
                "tests": results,
            },
        )


class BandwidthEstimator(Tool):
    name = "bandwidth_test"
    description = "Estimate network bandwidth to a target by transferring test data."
    category = "network"

    def execute(self, host: str = "8.8.8.8", port: int = 53, duration: float = 5.0, **kwargs) -> ToolResult:
        bytes_sent = 0
        start = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
        except Exception:
            return ToolResult(
                success=True,
                output={"host": host, "reachable": False, "bandwidth_kbps": 0},
            )

        chunk = b"X" * 4096
        try:
            while time.time() - start < duration:
                sock.send(chunk)
                bytes_sent += len(chunk)
        except Exception:
            pass
        finally:
            sock.close()

        elapsed = time.time() - start
        bandwidth_kbps = (bytes_sent * 8) / (elapsed * 1000) if elapsed > 0 else 0

        return ToolResult(
            success=True,
            output={
                "host": host,
                "bytes_sent": bytes_sent,
                "duration_seconds": round(elapsed, 2),
                "bandwidth_kbps": round(bandwidth_kbps, 2),
                "bandwidth_mbps": round(bandwidth_kbps / 1000, 3),
            },
        )


class DNSResolver(Tool):
    name = "dns_resolve"
    description = "Resolve a domain name and check DNS propagation."
    category = "network"

    def execute(self, domain: str = "novagps.onrender.com", **kwargs) -> ToolResult:
        import socket
        results = []

        try:
            start = time.time()
            ips = socket.getaddrinfo(domain, None)
            elapsed = (time.time() - start) * 1000
            unique_ips = list(set(addr[4][0] for addr in ips))
            results.append({
                "resolver": "system",
                "ips": unique_ips,
                "latency_ms": round(elapsed, 2),
                "success": True,
            })
        except Exception as e:
            results.append({"resolver": "system", "error": str(e), "success": False})

        try:
            import httpx
            for dns_server in ["8.8.8.8", "1.1.1.1", "9.9.9.9"]:
                try:
                    resp = httpx.get(
                        f"https://dns.google/resolve?name={domain}&type=A",
                        timeout=5,
                    )
                    data = resp.json()
                    answers = [a.get("data") for a in data.get("Answer", []) if a.get("type") == 1]
                    results.append({
                        "resolver": dns_server,
                        "ips": answers,
                        "success": bool(answers),
                    })
                    break
                except Exception:
                    continue
        except ImportError:
            pass

        return ToolResult(
            success=True,
            output={"domain": domain, "results": results},
        )


class LANDiscovery(Tool):
    """Find devices on the local network — the machine LAU runs on, plus
    everything attached to the same router/Wi-Fi. Identifies which nearby
    IPs belong to the host itself, the gateway, or other peers.
    """

    name = "network_discovery"
    description = (
        "Discover nearby devices on the local network (same router/Wi-Fi): "
        "the machine's own IPs, gateway, ARP table neighbors, and a bounded "
        "TCP sweep. Answers 'what is on my network', 'nearby ip addresses', "
        "'same internet connection'."
    )
    category = "network"

    def execute(self, subnets: str = "", **kwargs) -> ToolResult:
        import ipaddress

        local_ips = list(self._local_ips())
        if not local_ips:
            return ToolResult(success=False, output=None, error="Could not determine this host's LAN IP")

        gateway = self._gateway()
        arp = self._arp_table()
        arp_by_ip = {a["ip"]: a["mac"] for a in arp}

        targets = set(local_ips)
        if gateway:
            targets.add(gateway)
        for a in arp:
            targets.add(a["ip"])
        if isinstance(subnets, str) and subnets.strip():
            try:
                net = ipaddress.ip_network(subnets.strip(), strict=False)
                if net.num_addresses > 4096:
                    return ToolResult(success=False, output=None, error=f"Subnet too large ({net}). Keep it to /22 or smaller.")
                targets.update(str(h) for h in net.hosts())
            except ValueError as e:
                return ToolResult(success=False, output=None, error=f"Bad subnet '{subnets}': {e}")

        hosts = []
        for ip in sorted(targets, key=lambda i: tuple(int(p) for p in i.split("."))):
            is_self = ip in local_ips
            status = self._probe(ip) if not is_self else {"ports": [], "kind": "self"}
            if status is None:
                continue
            hosts.append({
                "ip": ip,
                "mac": arp_by_ip.get(ip, ""),
                "alive": True,
                "is_self": is_self,
                "is_gateway": ip == gateway,
                "ports": status["ports"],
                "kind": status["kind"],
            })

        return ToolResult(
            success=True,
            output={
                "own_ips": local_ips,
                "gateway": gateway,
                "host_count": len(hosts),
                "alive_count": len(hosts),
                "self_count": sum(1 for h in hosts if h["is_self"]),
                "gateway_count": sum(1 for h in hosts if h["is_gateway"]),
                "hosts": hosts,
            },
        )

    def _local_ips(self) -> list[str]:
        import socket as _socket
        ips = []
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass
        try:
            hostname = _socket.gethostname()
            for info in _socket.getaddrinfo(hostname, None):
                addr = info[4][0]
                if ":" not in addr and addr not in ips:
                    ips.append(addr)
        except Exception:
            pass
        return ips

    def _gateway(self) -> str:
        import re as _re
        try:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if "default via" in line:
                    parts = line.split("default via ")[1].split()
                    return parts[0]
        except Exception:
            pass
        try:
            out = subprocess.run(["route", "-n"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "0.0.0.0" and "." in parts[1]:
                    return parts[1]
        except Exception:
            pass
        return ""

    def _arp_table(self) -> list[dict]:
        import re as _re
        entries = []
        for cmd in (["arp", "-a"], ["ip", "neigh"]):
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
            except Exception:
                continue
            if "No ARP" in out or "not found" in out.lower():
                continue
            for line in out.splitlines():
                mac = _re.search(r"((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", line)
                ip = _re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if mac and ip:
                    entries.append({"ip": ip.group(1), "mac": mac.group(1)})
            if entries:
                break
        return entries

    def _probe(self, ip: str) -> dict | None:
        import socket as _socket
        probe_ports = [22, 80, 443, 554]
        open_ports = []
        for port in probe_ports:
            try:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
        if not open_ports:
            return None
        kind = "host"
        if 554 in open_ports:
            kind = "rtsp-camera"
        elif any(p in open_ports for p in (80, 443, 8080)):
            kind = "web-ui"
        return {"ports": sorted(open_ports), "kind": kind}


def register_network_tools(registry: ToolRegistry):
    for tool_cls in [ConnectivityProbe, Traceroute, MTUTester, BandwidthEstimator, DNSResolver, LANDiscovery]:
        registry.register(tool_cls())
