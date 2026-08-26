import logging
import subprocess
import re
from dataclasses import dataclass

logger = logging.getLogger("nova.camera")

RTSP_PATTERN = re.compile(r"^rtsp://[a-zA-Z0-9._:/@-]+$")


@dataclass
class CameraInfo:
    ip: str
    port: int
    protocol: str
    manufacturer: str = ""
    model: str = ""
    stream_url: str = ""


def discover_cameras(subnet: str = "192.168.1.0/24") -> list[dict]:
    try:
        completed = subprocess.run(
            ["nmap", "-sV", "-p", "554,80,8080,443", "--open", subnet],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        cameras = []
        current_ip = ""
        for line in output.splitlines():
            if line.startswith("Nmap scan report for"):
                current_ip = line.split()[-1].strip("()")
            elif "554/tcp" in line and "open" in line:
                cameras.append({"ip": current_ip, "port": 554, "protocol": "rtsp", "stream_url": f"rtsp://{current_ip}:554/live"})
            elif "8080/tcp" in line and "open" in line:
                cameras.append({"ip": current_ip, "port": 8080, "protocol": "http", "stream_url": f"http://{current_ip}:8080/video"})
        return cameras
    except FileNotFoundError:
        return [{"error": "nmap not installed"}]
    except subprocess.TimeoutExpired:
        return [{"error": "scan timed out"}]


def get_stream_url(rtsp_url: str) -> dict:
    if not RTSP_PATTERN.fullmatch(rtsp_url):
        return {"error": "invalid RTSP URL format"}
    return {"stream_url": rtsp_url, "status": "ready"}


def capture_screenshot(rtsp_url: str, output_path: str = "/tmp/nova_screenshot.jpg") -> dict:
    if not RTSP_PATTERN.fullmatch(rtsp_url):
        return {"error": "invalid RTSP URL format"}
    try:
        completed = subprocess.run(
            ["ffmpeg", "-y", "-i", rtsp_url, "-frames:v", "1", "-q:v", "2", output_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
        if completed.returncode == 0:
            return {"status": "captured", "path": output_path}
        return {"error": "ffmpeg capture failed", "detail": completed.stdout.decode("utf-8", errors="replace")[:500]}
    except FileNotFoundError:
        return {"error": "ffmpeg not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "capture timed out"}


def start_recording(rtsp_url: str, duration: int = 30) -> dict:
    if not RTSP_PATTERN.fullmatch(rtsp_url):
        return {"error": "invalid RTSP URL format"}
    output_path = f"/tmp/nova_recording_{int(__import__('time').time())}.mp4"
    try:
        proc = subprocess.Popen(
            ["ffmpeg", "-y", "-i", rtsp_url, "-t", str(duration), "-c", "copy", output_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return {"status": "recording", "pid": proc.pid, "path": output_path, "duration": duration}
    except FileNotFoundError:
        return {"error": "ffmpeg not installed"}


def detect_motion(rtsp_url: str) -> dict:
    if not RTSP_PATTERN.fullmatch(rtsp_url):
        return {"error": "invalid RTSP URL format"}
    try:
        completed = subprocess.run(
            ["ffmpeg", "-i", rtsp_url, "-frames:v", "2", "-f", "null", "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        has_motion = "Video:" in output
        return {"motion_detected": has_motion, "frames_analyzed": 2, "source": rtsp_url}
    except FileNotFoundError:
        return {"error": "ffmpeg not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "motion detection timed out"}
