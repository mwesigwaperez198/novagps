"""Device fingerprinting via network probing.

Discovers device hardware details by probing IP addresses with nmap,
ONVIF SOAP, SNMP, and UPnP/SSDP. Returns manufacturer, model,
firmware version, serial number, and open services.
"""

import json
import logging
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

import requests as http_requests

logger = logging.getLogger("nova.fingerprint")

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return completed.stdout.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return f"ERROR: {cmd[0]} not installed"
    except subprocess.TimeoutExpired:
        return f"ERROR: command timed out after {timeout}s"


def nmap_service_detect(ip: str) -> dict[str, Any]:
    """Run nmap service version detection against an IP."""
    if not IP_PATTERN.fullmatch(ip):
        return {"error": "invalid IP address"}
    output = _run(["nmap", "-Pn", "-sV", "--top-ports", "50", ip], timeout=60)
    if output.startswith("ERROR:"):
        return {"error": output}
    services: list[dict[str, str]] = []
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            for i, part in enumerate(parts):
                if "/tcp" in part:
                    svc = {"port": part.split("/")[0]}
                    if i + 1 < len(parts):
                        svc["state"] = parts[i + 1]
                    if i + 2 < len(parts):
                        svc["service"] = parts[i + 2]
                    if i + 3 < len(parts):
                        svc["version"] = " ".join(parts[i + 3:])
                    services.append(svc)
                    break
    os_match = ""
    for line in output.splitlines():
        if "OS details:" in line or "Running:" in line:
            os_match = line.split(":", 1)[1].strip()
            break
    return {"ip": ip, "services": services, "os_guess": os_match}


def onvif_probe(ip: str, timeout: int = 8) -> dict[str, Any]:
    """Probe a device for ONVIF (IP camera) capabilities."""
    if not IP_PATTERN.fullmatch(ip):
        return {"error": "invalid IP address"}
    soap_body = '<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><soap:Body><tds:GetDeviceInformation/></soap:Body></soap:Envelope>'
    headers = {
        "Content-Type": 'application/soap+xml; charset=utf-8',
        "SOAPAction": '"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"',
    }
    for port in [80, 8080, 8899]:
        for path in ["/onvif/device_service", "/onvif/DeviceManager", "/DeviceManager"]:
            url = f"http://{ip}:{port}{path}"
            try:
                resp = http_requests.post(url, data=soap_body, headers=headers, timeout=timeout)
                if resp.status_code == 200 and "onvif" in resp.text.lower():
                    return _parse_onvif_response(resp.text, ip, port)
            except Exception:
                continue
    return {"ip": ip, "onvif": False, "note": "ONVIF not found on standard ports"}


def _parse_onvif_response(xml_text: str, ip: str, port: int) -> dict[str, Any]:
    result: dict[str, Any] = {"ip": ip, "onvif": True, "port": port}
    try:
        root = ET.fromstring(xml_text)
        ns = {
            "s": "http://www.w3.org/2003/05/soap-envelope",
            "tds": "http://www.onvif.org/ver10/device/wsdl",
        }
        for field, tag in [
            ("manufacturer", "Manufacturer"),
            ("model", "Model"),
            ("firmware_version", "FirmwareVersion"),
            ("serial_number", "SerialNumber"),
            ("hardware_id", "HardwareId"),
        ]:
            el = root.find(f".//tds:{tag}", ns)
            if el is not None and el.text:
                result[field] = el.text.strip()
    except ET.ParseError:
        result["note"] = "response received but XML parse failed"
    return result


def snmp_walk(ip: str, community: str = "public", timeout: int = 8) -> dict[str, Any]:
    """SNMP walk to gather system info."""
    if not IP_PATTERN.fullmatch(ip):
        return {"error": "invalid IP address"}
    oids = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysObjectID": "1.3.6.1.2.1.1.2.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
        "sysContact": "1.3.6.1.2.1.1.4.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
    }
    result: dict[str, Any] = {"ip": ip, "snmp": False}
    for name, oid in oids.items():
        output = _run(["snmpget", "-v2c", "-c", community, "-t", str(timeout), ip, oid], timeout=timeout + 2)
        if output.startswith("ERROR:"):
            continue
        result["snmp"] = True
        if "No Such" not in output and "No response" not in output:
            parts = output.split("=", 1)
            if len(parts) == 2:
                result[name] = parts[1].strip().strip('"')
    if not result["snmp"]:
        result["note"] = "SNMP not available or community string incorrect"
    return result


def upnp_discover(ip: str, timeout: int = 6) -> dict[str, Any]:
    """UPnP/SSDP discovery to find device descriptions."""
    if not IP_PATTERN.fullmatch(ip):
        return {"error": "invalid IP address"}
    ssdp_msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )
    result: dict[str, Any] = {"ip": ip, "upnp": False}
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(ssdp_msg.encode(), (ip, 1900))
        data, _ = sock.recvfrom(4096)
        sock.close()
        response = data.decode("utf-8", errors="replace")
        result["upnp"] = True
        result["headers"] = {}
        for line in response.splitlines():
            if ":" in line and line != response.splitlines()[0]:
                key, val = line.split(":", 1)
                result["headers"][key.strip().lower()] = val.strip()
        location = result["headers"].get("location", "")
        if location:
            try:
                desc_resp = http_requests.get(location, timeout=timeout)
                if desc_resp.status_code == 200:
                    result["device_description"] = desc_resp.text[:2048]
                    for tag in ["friendlyName", "manufacturer", "modelName", "modelDescription", "serialNumber", "firmwareVersion"]:
                        import re as re_mod
                        match = re_mod.search(f"<{tag}>(.*?)</{tag}>", desc_resp.text)
                        if match:
                            result[tag] = match.group(1)
            except Exception:
                pass
    except Exception:
        result["note"] = "UPnP/SSDP not available"
    return result


def fingerprint_device(ip: str) -> dict[str, Any]:
    """Full fingerprint of a device by IP — runs all probes."""
    if not IP_PATTERN.fullmatch(ip):
        return {"error": "invalid IP address"}
    result: dict[str, Any] = {"ip": ip, "probes": {}}
    nmap = nmap_service_detect(ip)
    result["probes"]["nmap"] = nmap
    onvif = onvif_probe(ip)
    result["probes"]["onvif"] = onvif
    if onvif.get("onvif"):
        result["manufacturer"] = onvif.get("manufacturer", "")
        result["model"] = onvif.get("model", "")
        result["firmware_version"] = onvif.get("firmware_version", "")
        result["serial_number"] = onvif.get("serial_number", "")
        result["device_type"] = "camera"
    snmp_data = snmp_walk(ip)
    result["probes"]["snmp"] = snmp_data
    if snmp_data.get("snmp"):
        if not result.get("manufacturer"):
            result["manufacturer"] = snmp_data.get("sysContact", "")
        if not result.get("model"):
            result["model"] = snmp_data.get("sysName", "")
        if not result.get("firmware_version"):
            result["firmware_version"] = snmp_data.get("sysDescr", "")
    upnp_data = upnp_discover(ip)
    result["probes"]["upnp"] = upnp_data
    if upnp_data.get("upnp"):
        for tag in ["friendlyName", "manufacturer", "modelName", "serialNumber", "firmwareVersion"]:
            if tag in upnp_data and not result.get(tag):
                result[tag] = upnp_data[tag]
    open_ports = [s["port"] for s in nmap.get("services", [])]
    if "554" in open_ports or "8554" in open_ports:
        result["device_type"] = "camera"
        result["rtsp_port"] = 554 if "554" in open_ports else 8554
        result["stream_url"] = f"rtsp://{ip}:{result['rtsp_port']}/live"
    elif any(p in open_ports for p in ["80", "443", "8080"]):
        if "onvif" in str(upnp_data).lower() or onvif.get("onvif"):
            result["device_type"] = "camera"
    if not result.get("device_type"):
        if any(p in open_ports for p in ["22"]):
            result["device_type"] = "server"
        elif any(p in open_ports for p in ["80", "443"]):
            result["device_type"] = "network_device"
        else:
            result["device_type"] = "unknown"
    result["open_ports"] = open_ports
    return result
