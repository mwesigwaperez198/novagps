"""
NOVA-CORE + Ollama setup helper for macOS (Intel and Apple Silicon).

Run:  python3 setup_ollama.py  --on your machine, NOT on Render
"""

import json
import os
import subprocess
import sys
import urllib.request


def run(cmd, check=True):
    print(f"\n$ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        print(result.stdout.strip()[:2000])
    if result.returncode != 0 and check:
        print(f"WARNING: exit code {result.returncode}")
        if result.stderr.strip():
            print(result.stderr.strip()[:1000])
    return result


def ollama_running():
    try:
        urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=2)
        return True
    except Exception:
        return False


def main():
    print("=" * 60)
    print("NOVA-CORE Setup: Ollama + Model Installation")
    print("=" * 60)

    is_mac = sys.platform == "darwin"
    if not is_mac:
        print(f"\nPlatform: {sys.platform}")
        print("NOTE: This script assumes macOS. Adjust commands for your OS.")

    print("\n[1/5] Checking Ollama installation...")
    which = run("which ollama", check=False)
    if which.returncode != 0:
        if is_mac:
            print("\nOllama not found. Download from:")
            print("  https://ollama.com/download/mac")
            print("\nOr install via Homebrew:")
            print("  brew install ollama")
        else:
            print("\nDownload Ollama from https://ollama.com")
        install = input("\nHave you installed it? (y/N): ").strip().lower()
        if install != "y":
            print("Install it first, then re-run this script.")
            return

    print("\n[2/5] Checking RAM to pick the right model...")
    try:
        if is_mac:
            mem_bytes = int(run("sysctl -in hw.memsize", check=False).stdout.strip())
        else:
            mem_bytes = int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
        mem_gb = mem_bytes / (1024**3)
        print(f"  RAM: {mem_gb:.1f} GB")
    except Exception:
        mem_gb = 8
        print(f"  RAM: could not read, assuming {mem_gb} GB")

    if mem_gb >= 16:
        default_model = "llama3.1:8b"
        fallback = "llama3.2:3b"
    elif mem_gb >= 8:
        default_model = "llama3.2:3b"
        fallback = "tinyllama:1.1b"
    else:
        default_model = "tinyllama:1.1b"
        fallback = None

    print(f"\n[3/5] Pulling model '{default_model}'...")
    result = run(f"ollama pull {default_model}")
    if result.returncode != 0 and fallback:
        print(f"Falling back to '{fallback}'...")
        run(f"ollama pull {fallback}")

    print("\n[4/5] Verifying model works...")
    check = run(f'ollama run {default_model} "Reply with: OK"', check=False)

    print("\n[5/5] Testing the Ollama API server...")
    if ollama_running():
        print("  Ollama API is running on http://127.0.0.1:11434")
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3) as resp:
            data = json.loads(resp.read())
            models = [m["name"] for m in data.get("models", [])]
            print(f"  Installed models: {models}")
    else:
        print("  Ollama API NOT reachable on http://127.0.0.1:11434")
        print("  Make sure the Ollama app is running (check menu bar icon).")
        print("  Then re-run this script.")

    print("\n" + "=" * 60)
    print("SETUP COMPLETE")
    print("=" * 60)
    print(f"\nRecommended model for NOVA-CORE: {default_model}")
    print("Set it in your NovaGPS backend env:")
    print(f"  OLLAMA_MODEL={default_model}")
    print("  OLLAMA_HOST=http://127.0.0.1:11434")


if __name__ == "__main__":
    main()