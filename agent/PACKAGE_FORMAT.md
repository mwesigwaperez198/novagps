# NOVA payload format — `.nova`

A `.nova` file is a signed, encrypted delivery envelope. It wraps any agent
artifact (right now the Android APK; later `.msi`, `.dmg`, `.pkg`, ELF
binaries) so that it can only be unlocked **on a specific device** and
**by a Novara-issued signature**.

On-disk layout (byte stream):

```
┌────────────────────────────────────────────────────────────┐
│ magic       4 bytes   "NOVA"                                │
│ version     1 byte    format version                        │
│ flags       1 byte    bit0 requires_root · bit1 mdm         │
│ os_len     1 byte    os name length                        │
│ os                             "android" / "ios" / ...      │
│ arch_len   1 byte    arch name length                      │
│ arch                            "arm64" / "x64" / ...       │
│ name_len   1 byte    artifact name length                  │
│ name                           e.g. "nova-agent.apk"        │
│ eph_pub    32 bytes  ephemeral X25519 public (ECDH)        │
│ salt       16 bytes  HKDF salt                             │
│ nonce      12 bytes  AES-GCM nonce                         │
│ ciphertext         AES-256-GCM(manifest_json ‖ artifact)   │
│ signature  64 bytes Ed25519 over (header ‖ eph_pub ‖ salt  │
│                       ‖ nonce ‖ ciphertext)                │
└────────────────────────────────────────────────────────────┘
```

## Who can open it (three gates)

1. **Authenticity — Ed25519.** The signature must verify against the Novara
   public key embedded in the agent. A payload vended by anybody else is
   refused before a single byte is decrypted.
2. **Confidentiality — ECIES over X25519.** The data key is derived from
   `HKDF-SHA256(shared, salt, "nova/payload-v1")` where `shared` is the
   X25519 agreement between a fresh ephemeral key and **the target device's
   public key**. Only the device holding the matching private key can derive
   the key. A `.nova` copied to any other phone is unreadable.
3. **Integrity — AES-256-GCM.** The header and the ephemeral pubkey are the
   associated data, so any edit is caught, plus an inner SHA-256 of the
   artifact in the manifest.

This is the same family of construction used by secured delivery systems
(Diebold/air-gapped provisioning, HSM-sealed updates): *encrypt to the
receiver, sign with the issuer*.

## Toolchain

`agent/tools/nova_pack.py` (Python 3.9+, `cryptography` package):

```bash
# 1. Company identity — keep nova.key secret, embed nova.pub in agents.
python nova_pack.py keygen nova.key                # -> nova.key, nova.pub

# 2. Each device has its own keypair.
python nova_pack.py device-keygen deviceA.key      # -> deviceA.key, deviceA.pub
# The agent sends deviceA.pub to the server during its first register;
# the server stores it on the device record.

# 3. Pack an artifact for THAT device.
python nova_pack.py pack -i app-debug.apk -o deviceA.nova \
    --key nova.key --device-pub deviceA.pub \
    --os android --arch arm64 --name nova-agent.apk \
    --attach device_owner --requires-root

# 4. Share the file. It is inert anywhere except device A.
python nova_pack.py inspect deviceA.nova           # header only, no keys
python nova_pack.py unpack -p deviceA.nova \
    --key deviceA.key --verify nova.pub -o ./open  # gate check + decrypt

python nova_pack.py attach-guide --os android      # sanctioned attach step
```

On-device, the same logic lives in
`android/app/src/main/java/com/novara/agent/util/NovaPayload.kt`
(Ed25519 verify → X25519 unlock → AES-GCM decrypt). Keep it in lock-step
with `nova_pack.py`.

## How registration uses it

1. Agent boots, generates its X25519 keypair (Android Keystore), registers
   the device with NOVA and uploads the device public key.
2. Console: **Download payload** for that device → server shells out to
   `nova_pack pack … --device-pub <device.pub>` → returns `device.nova`.
3. The file is shared over any channel (WhatsApp, Telegram, USB, email).
4. The receiving device runs the agent's `open()` — if the device key
   matches and the Novara signature verifies, the agent activates and
   applies the attach profile (device owner, service, daemon…).
5. Anything else (other device, unsigned file, tampered bytes) is rejected.

## Limits, stated plainly

Encryption + signature **prove origin and block other devices**. They do
**not** grant OS privileges. On stock Android the sanctioned attach is
still Device Owner; on iOS it is still supervised MDM. Encrypted delivery
is the lock on the door — the attach profile is the door that the OS
controls.