#!/usr/bin/env python3
"""nova-pack — the NOVA encrypted payload toolchain.

Wraps any agent artifact (Android APK, and later .msi, .dmg, .pkg, ELF
binaries) in a .nova envelope so it can only be opened by a NOVA system:

    magic | version | flags | os | arch | name | nonce | aes-gcm(manifest + payload) | ed25519-signature

Confidentiality + integrity = AES-256-GCM (the header is the AAD).
Origin authenticity   = Ed25519 signature from the NOVA signer key, so
                        only payloads the company actually signed will
                        activate on a device. A device verifies with the
                        embedded public key before touching a byte.

Encryption gates access and guarantees provenance; it does NOT grant the
OS privileges needed for stealth placement. The sanctioned attach step per
platform is printed by `nova-pack attach-guide`.

Usage:
  nova-pack keygen <path>                  create NOVA nova.key + nova.pub (company)
  nova-pack device-keygen <path>           create per-device X25519 keypair
  nova-pack inspect <payload.nova>         read the cleartext header only
  nova-pack pack -i <artifact> -o out.nova --key nova.key \
          --device-pub device.pub \
          --os android --arch arm64 --name "nova-agent.apk" \
          --attach device_owner --requires-root
  nova-pack unpack -p out.nova --key device.key --verify nova.pub --out ./decrypted
  nova-pack attach-guide --os android
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"NOVA"
VERSION = 1
SIG_LEN = 64
NONCE_LEN = 12
X25519_PUB_LEN = 32
SALT_LEN = 16

CRYPTO = "ecies+x25519|aes-256-gcm|hkdf-sha256|ed25519"

ATTACH_PROFILES = {
    "app": "visible app, user installs it",
    "device_owner": "android: dpm set-device-owner (hidden, persistent, boots with phone)",
    "priv_app": "android root/ROM: drop into /system/priv-app or Magisk module",
    "mdm": "ios/macos: Apple MDM enrollment profile (supervised device)",
    "service": "windows: SYSTEM service",
    "daemon": "macos: LaunchDaemon (root, no Dock icon)",
    "systemd": "linux: systemd unit under /etc/systemd/system",
}

OS_ALIASES = {
    "android": "android",
    "ios": "ios",
    "ipados": "ios",
    "windows": "windows",
    "win": "windows",
    "macos": "macos",
    "mac": "macos",
    "darwin": "macos",
    "linux": "linux",
}


def _fail(msg: str, code: int = 1) -> None:
    print(f"nova-pack: error: {msg}", file=sys.stderr)
    sys.exit(code)


def keygen(args: argparse.Namespace) -> None:
    path = args.path
    key = Ed25519PrivateKey.generate()
    pub = key.public_key()
    key_path = Path(path)
    pub_path = key_path.with_name(key_path.stem + ".pub")
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.chmod(key_path, 0o600)
    print(f"wrote {key_path} (keep this secret, never ship it)")
    print(f"wrote {pub_path} (embed this in agents / injectors)")


def device_keygen(args: argparse.Namespace) -> None:
    """Per-device X25519 keypair so a packed file decrypts on that device
    and nowhere else. The device's public key goes to the NOVA server when
    the agent first registers; the server packs payloads to it."""
    path = args.path
    key = X25519PrivateKey.generate()
    key_path = Path(path)
    pub_path = key_path.with_name(key_path.stem + ".pub")
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    pub_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    os.chmod(key_path, 0o600)
    print(f"wrote device private key {key_path}  (this stays ON the device)")
    print(f"wrote device public key  {pub_path}  (send this to the NOVA server)")


def _load_x25519_public(path: str) -> X25519PublicKey:
    return serialization.load_pem_public_key(Path(path).read_bytes())


def _load_x25519_private(path: str) -> X25519PrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def _load_private(path: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def _load_public(path: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(Path(path).read_bytes())


def _header(os_name: str, arch: str, name: str, flags: int) -> bytes:
    raw_os = os_name.encode()
    raw_arch = arch.encode()
    raw_name = name.encode()
    if len(raw_os) > 255 or len(raw_arch) > 255 or len(raw_name) > 255:
        _fail("os/arch/name must be < 256 bytes")
    return (
        MAGIC
        + bytes([VERSION, flags])
        + bytes([len(raw_os)])
        + raw_os
        + bytes([len(raw_arch)])
        + raw_arch
        + bytes([len(raw_name)])
        + raw_name
    )


def _derive_device_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"nova/payload-v1",
    ).derive(shared_secret)


def pack(args) -> None:
    if args.device_pub is None:
        _fail("packing requires --device-pub (the target device's public key)")
    artifact = Path(args.input)
    if not artifact.is_file():
        _fail(f"input artifact not found: {artifact}")
    if args.os.lower() not in OS_ALIASES:
        _fail(f"unknown --os target: {args.os}")
    os_name = OS_ALIASES[args.os.lower()]
    flags = (1 if args.requires_root else 0) | (2 if args.attach == "mdm" else 0)

    manifest = {
        "format": "nova",
        "version": VERSION,
        "crypto": CRYPTO,
        "os": os_name,
        "arch": args.arch,
        "name": args.name or artifact.name,
        "attach": args.attach,
        "requires_root": bool(args.requires_root),
        "requires_admin": bool(args.requires_admin),
        "source": str(artifact),
        "size": artifact.stat().st_size,
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "created_unix": int(__import__("time").time()),
    }

    art_bytes = artifact.read_bytes()
    manifest_json = json.dumps(manifest, indent=2).encode()
    clear = len(manifest_json).to_bytes(8, "big") + manifest_json + art_bytes

    # ECIES: wrap the DEK to the target device only.
    eph = X25519PrivateKey.generate()
    device_key = _load_x25519_public(args.device_pub)
    shared = eph.exchange(device_key)
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    header = _header(os_name, args.arch, manifest["name"], flags)
    aad = header + eph.public_key().public_bytes_raw() + salt
    dek = _derive_device_key(shared, salt)
    ct = AESGCM(dek).encrypt(nonce, clear, aad)
    sig = _load_private(args.key).sign(aad + nonce + ct)

    out = Path(args.out)
    out.write_bytes(aad + nonce + ct + sig)
    print(
        f"packed {artifact.name} ({manifest['size']} bytes) -> {out.name} "
        f"({out.stat().st_size} bytes) attach={args.attach} "
        f"device-only, signed by NOVA ({os_name}/{args.arch})"
    )


def inspect(args) -> None:
    data = Path(args.payload).read_bytes()
    header, aad_tail, nonce, ct, sig = _split(data)
    os_name, arch, name, flags = _parse_header(header)
    pub = _load_public(args.key) if args.key else None
    verified = False
    if pub:
        try:
            pub.verify(sig, header + aad_tail + nonce + ct)
            verified = True
        except Exception:
            verified = False
    print(f"magic         {header[0:4]!r}")
    print(f"format        nova-{header[4]} · {CRYPTO}")
    print(f"os            {os_name}")
    print(f"arch          {arch}")
    print(f"artifact      {name}")
    print(f"flags         requires_root={bool(flags & 1)} mdm={bool(flags & 2)}")
    print(f"ciphertext    {len(ct)} bytes (aes-256-gcm)")
    print(f"recipient     device-only (ecdh over x25519)")
    print(f"signature     {'VALID (NOVA-signed)' if verified else 'not verified (pass --key)'}")


def unpack(args) -> None:
    data = Path(args.payload).read_bytes()
    header, aad_tail, nonce, ct, sig = _split(data)
    os_name, arch, name, flags = _parse_header(header)
    eph_pub_raw = aad_tail[:X25519_PUB_LEN]
    salt = aad_tail[X25519_PUB_LEN:X25519_PUB_LEN + SALT_LEN]
    aad = header + eph_pub_raw + salt   # exact AAD the packer signed

    # 1) only this device's private key can derive the DEK
    device_priv = _load_x25519_private(args.key)
    shared = device_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub_raw))
    dek = _derive_device_key(shared, salt)

    # 2) only a NOVA signature opens it anywhere
    pub = _load_public(args.verify)
    try:
        pub.verify(sig, aad + nonce + ct)
    except Exception:
        _fail("signature is not from the NOVA key — refusing to unlock")
    try:
        clear = AESGCM(dek).decrypt(nonce, ct, aad)
    except Exception:
        _fail("decrypt failed — this device cannot open this payload")

    try:
        manifest_len = int.from_bytes(clear[:8], "big")
        manifest = json.loads(clear[8:8 + manifest_len])
    except Exception:
        _fail("manifest parse failed")
    artifact = clear[8 + manifest_len:]

    digest = hashlib.sha256(artifact).hexdigest()
    if digest != manifest.get("sha256"):
        _fail("artifact digest mismatch after decryption")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    target = out / (manifest.get("name") or name)
    target.write_bytes(artifact)
    os.chmod(target, 0o700)
    print(
        f"verified NOVA signature ({os_name}/{arch}) and unlocked {len(artifact)} bytes "
        f"-> {target}\nattach profile: {manifest.get('attach', '?')}: "
        f"{ATTACH_PROFILES.get(manifest.get('attach'), '?')}"
    )


def attach_guide(args) -> None:
    target = OS_ALIASES.get(args.os.lower(), args.os.lower())
    guide = {
        "android": (
            "stock:  adb install payload.nova  then  adb shell am start -n com.novara.agent/.MainActivity\n"
            "hidden: adb shell dpm set-device-owner com.novara.agent/.bootstrap.DeviceOwnerAdmin\n"
            "        (needs a fresh device with no accounts; icon disappears, boot persistence, always-on VPN firewall)\n"
            "root:   push decrypted module to /system/priv-app or install as a Magisk module"
        ),
        "ios": (
            "iOS only executes Apple-signed apps; there is no code-signing bypass.\n"
            "Ship the visible App Store agent + enroll the target through Apple Business Manager\n"
            "(supervised MDM). Apple supplies lock/wipe/lost-mode and RemoveApp once supervised."
        ),
        "windows": (
            "decrypt to a SYSTEM service:  sc create NovaAgent binPath=\"C:\\ProgramData\\Nova\\agent.exe\" start=auto\n"
            "firewall via Windows Filtering Platform in the service; runs before login, no taskbar presence"
        ),
        "macos": (
            "decrypt to /Library/LaunchDaemons/com.novara.agent.plist + /Library/Nova/agent\n"
            "sudo launchctl load ...; root daemon, no Dock icon, survives logout/restart"
        ),
        "linux": (
            "install to /opt/nova/agent + /etc/systemd/system/nova-agent.service\n"
            "systemctl enable --now nova-agent; firewall via nftables rules"
        ),
    }
    print(f"attach guide for {target}:\n")
    print(guide.get(target, "unsupported target"))


def _split(data: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    if len(data) < 12 or data[:4] != MAGIC:
        _fail("not a NOVA payload (bad magic)")
    os_len = data[6]
    arch_len = data[7 + os_len]
    name_len = data[8 + os_len + arch_len]
    header_len = 9 + os_len + arch_len + name_len
    body_start = header_len + X25519_PUB_LEN + SALT_LEN
    if len(data) < body_start + NONCE_LEN + SIG_LEN:
        _fail("truncated NOVA payload")
    header = data[:header_len]
    aad_tail = data[header_len: body_start]              # eph_pub + salt
    nonce = data[body_start: body_start + NONCE_LEN]
    sig = data[-SIG_LEN:]
    ct = data[body_start + NONCE_LEN: -SIG_LEN]
    return header, aad_tail, nonce, ct, sig


def _parse_header(header: bytes) -> tuple[str, str, str, int]:
    os_len = header[6]
    arch_len = header[7 + os_len]
    name_len = header[8 + os_len + arch_len]
    os_name = header[7: 7 + os_len].decode()
    arch = header[8 + os_len: 8 + os_len + arch_len].decode()
    name = header[9 + os_len + arch_len: 9 + os_len + arch_len + name_len].decode()
    return os_name, arch, name, header[5]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen")
    p.add_argument("path")
    p.set_defaults(func=keygen)

    p = sub.add_parser("device-keygen")
    p.add_argument("path")
    p.set_defaults(func=device_keygen)

    p = sub.add_parser("inspect")
    p.add_argument("-p", "--payload", required=True)
    p.add_argument("--key", default=None)
    p.set_defaults(func=inspect)

    p = sub.add_parser("pack")
    p.add_argument("-i", "--input", required=True, help="the agent artifact (APK/DMG/MSI/ELF)")
    p.add_argument("-o", "--out", required=True, help=".nova output path")
    p.add_argument("--key", required=True, help="NOVA Ed25519 secret key (never ship)")
    p.add_argument("--device-pub", required=True, help="X25519 public key of the target device")
    p.add_argument("--os", required=True, choices=sorted(OS_ALIASES))
    p.add_argument("--arch", required=True, choices=["arm64", "armv7", "x64", "x86", "aarch64"])
    p.add_argument("--name", default=None)
    p.add_argument("--attach", choices=ATTACH_PROFILES, default="app")
    p.add_argument("--requires-root", action="store_true")
    p.add_argument("--requires-admin", action="store_true")
    p.set_defaults(func=pack)

    p = sub.add_parser("unpack")
    p.add_argument("-p", "--payload", required=True)
    p.add_argument("--key", required=True, help="this device's X25519 private key")
    p.add_argument("--verify", required=True, help="NOVA Ed25519 public key")
    p.add_argument("-o", "--out", default=".")
    p.set_defaults(func=unpack)

    p = sub.add_parser("attach-guide")
    p.add_argument("--os", required=True)
    p.set_defaults(func=attach_guide)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()