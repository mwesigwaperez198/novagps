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


def register_network_tools(registry: ToolRegistry):
    for tool_cls in [ConnectivityProbe, Traceroute, MTUTester, BandwidthEstimator, DNSResolver]:
        registry.register(tool_cls())
