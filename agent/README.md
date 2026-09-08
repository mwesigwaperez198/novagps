# NOVA Agent — on-device telemetry, protection and remote action

When you register a phone in the NOVA dashboard you are only creating a
**database record**. Real location, firmware info and remote actions only
exist once a small program is running **on the device itself** — that is
what this `agent/` tree is: the cross-platform client that makes NOVA
work on an actual phone, laptop, tablet or watch.

This is not a guess about what is possible. What follows is the exact
mechanism each operating system provides, and the implementation we ship.

---

## 1. Why the map had "wrong" coordinates before

Coordinates in the web app are fed by `POST /update-location`. Nothing
calls that endpoint for a real phone until there is something on the phone
to call it. The dashboard's "SIMULATE SIGNAL" button is a stand-in:
it calls the same endpoint with a fake trip so you can watch the product
behave. The Android agent below replaces that fake with a real GPS feed.
Until then, that is why a freshly registered device reads `WAITING_FOR_SIGNAL`.

---

## 2. What "seats inside the factory system" really means, per platform

People often believe an APK can silently become part of a phone's firmware.
The OEMs built against exactly that idea, so here is the honest, working
mechanism for each OS:

| Platform | Hidden, system-level install | How it is actually done | Firewall option |
|---|---|---|---|
| Android (stock) | **Yes — no root needed** | **Device Owner** provisioning (`dpm set-device-owner`) — the app disappears from the launcher, cannot be force-stopped or uninstalled without ADB/factory reset, starts at boot, is exempt from battery killer. This is exactly how corporate EMM and Google's own Find My Device operate. | `VpnService` per-app allowlist (NetGuard-style, no root). As Device Owner it can force "always-on + lockdown" so traffic only flows through our rules. |
| Android (root/ROM) | **Yes — firmware level** | Magisk module or `/system/priv-app/` package. True kernel-level placement, `iptables` firewall, survives its own process being hunted. Only possible on hardware/firmware we control or that the user consents to flash. | `iptables` + netfilter, stealth renaming, tamper guard. |
| iOS / iPadOS | **Partially** | No sideloaded code ever runs on iOS: only Apple-signed apps install, and the App Store rejects hidden-tracking software. The sanctioned "system-level" route is **MDM enrollment** (Apple Business Manager / supervised device): the OS itself hides the app (`RemoveApp`), enforces restrictions, and supplies lock / wipe / lost-mode at the OS level. Consent-based Find-My/safety/enterprise apps are accepted. | `NEPacketTunnelProvider` network extension (only in a visible, approved app). |
| macOS | **Yes** | LaunchDaemon (`/Library/LaunchDaemons`) run as root — no Dock icon, starts before login, survives logout. Installed once with the owner's admin password. | NetworkExtension System Extension (content filter) or PF/netsh rules. |
| Windows | **Yes** | Windows Service running as `SYSTEM`, starts at boot, no taskbar entry. | Windows Filtering Platform (WFP). |
| Linux | **Yes** | `systemd` service under `/etc/systemd/system`, root privilege. | `nftables` / `iptables`. |

**The summary you should carry:** "invisible system agent" = **Device Owner
on Android** and **MDM on iOS**. Both are legitimate, both are what
serious security companies do, and neither requires breaking the phone.
The root/Magisk tier exists but is only for hardware you control.
Do not let anyone sell you a "jailbreak APK that hides on any iPhone without
consent" — it does not exist and any product claiming it is either a scam
or malware.

---

## 3. The Android agent (this repo, `agent/android`)

Build a signing APK and provision it for stealth as follows.

### 3.1 Build the APK

```bash
# requires Android Studio (or JDK 17 + Android SDK)
cd agent/android
./gradlew assembleDebug        # unsigned debug APK for testing
./gradlew assembleRelease      # signed APK (see app/build.gradle.kts signing)
```

`app/build/outputs/apk/debug/app-debug.apk` is produced. On macOS you can
transfer it to a test phone with `adb install app-debug.apk`.

### 3.2 Step 1 — first boot as a normal app (the honest way)

```bash
adb install app-debug.apk
adb shell am start -n com.novara.agent/.MainActivity
```

On first launch the agent asks for **location permission**, displays the
NOVA server URL, and takes the device **identifier** printed after the
device is registered in the dashboard. Opening it as a normal app is *not*
stealth yet — this step is just for validation of the network path
(live location should appear on the map within 30 seconds).

### 3.3 Step 2 — become Device Owner (the "sits in the system" step)

With a fresh factory reset (or a device that has no accounts yet):

```bash
adb shell dpm set-device-owner com.novara.agent/.bootstrap.DeviceOwnerAdmin
```

Once this succeeds:
- the launcher icon **disappears** — the app is no longer in the drawer,
- the user **cannot force-stop or uninstall** it without ADB,
- it **auto-starts at boot** and survives Google Play Protect's battery kills,
- the VPN firewall can be forced **always-on + lockdown** so the device only
  communicates through NOVA rules.

Device Owner cannot be removed by the phone user; it is removed by
`adb shell dpm remove-active-admin com.novara.agent/.bootstrap.DeviceOwnerAdmin`
or a factory reset. That is the entire point for stolen-device recovery.

### 3.4 What the agent reports every 30 s

`POST /update-location` — GPS + network location, altitude, speed, heading,
accuracy, battery level, network type, signal dBm — plus one heartbeat a
minute to `/analytics/device/{id}/heartbeat`. OS/build/manufacturer/model
came from the original `/register` call.

### 3.5 Remote actions that now actually work

The dashboard's existing **REMOTE** workspace buttons queue commands in the
`pending_commands` table. The agent polls `POST /device/pull-commands`
(authenticated by its own identifier like `/update-location`), executes, and
acks via `POST /device/ack-command`.

| Dashboard button | Agent behaviour |
|---|---|
| Locate | instant location upload (network triangulation if GPS denied) |
| Remote lock | lock screen immediately + owner message/contact, re-locks every keystroke attempt |
| Lost mode | full-screen alert, photo + microphone capture attempt, 30 s locate interval |
| Send message | heads-up notification shown on screen |
| Remote wipe (admin) | `DevicePolicyManager.wipeData()` — factory reset |

### 3.6 The firewall (protection mode)

`FirewallService` is an Android **`VpnService`** — the official, root-free
mechanism used by apps like NetGuard and corporate agents. It builds a VPN
tunnel that inspects every address:

- **Allowlist first**: known system + NOVA traffic is passed.
- **Block everything else** by default, or per-app rules from the server
  (`raw_payload` in the command).
- As Device Owner it forces **always-on + lockdown** so no app can sneak
  traffic past a dropped VPN.

With a rooted/Magisk build the same rules are applied with `iptables`
instead, so they persist even if the VPN service is killed.

---

## 4. iOS agent (consent + MDM, not covert)

iOS has no code-signing bypass. The NOVA iOS agent is a **normal App Store
app** (Location-access manifest reason, background location for a genuine
safety/find-my purpose) that:

- streams location + battery + firmware version to NOVA,
- receives lock / lost-mode / wipe / message commands,
- and, when enrolled through **Apple Business Manager** with a supervised
  device, gains `RemoveApp` (hidden app) + MDM lock/wipe delivered by Apple's
  own Mobile Device Management transport.

Where a phone shop or IT admin flashes a device on behalf of an owner, the
enrollment profile is installed with the owner present and approving —
exactly how a carrier or school provisions company devices today.

## 5. Desktop agents

- **macOS**: a LaunchDaemon agent. Same command/location contract, root
  privileges, invisible by design (no Dock/UI). Packaged as a `.pkg` with an
  installer.sh that installs `/Library/LaunchDaemons/com.novara.agent.plist`
  once the owner enters an admin password.
- **Windows**: a Service (SYSTEM). Packaged as an MSI or `sc create` +
  `binPath` install script.
- **Linux**: a `systemd` unit + binary, installed by an `install.sh`.

Repos for these are next; this directory ships Android first because it is
where the stolen-device use case hurts most.

---

## 6. The compliance line we never cross

Everything above runs **with the owner's consent** (the existing active
consent record at `POST /consent` is mandatory for `/update-location`).
Stealth *placement* serves theft recovery and corporate fleet management.
We do not provide covert surveillance of people who did not agree to be
tracked, and we do not claim hidden installation on unmodified iPhones,
which is not technically possible.