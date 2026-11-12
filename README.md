# NetScope — Native, 100% Free iPhone Network Auditing

[![Build NetScope.ipa](https://github.com/Shashi552/netscope/actions/workflows/build-ipa.yml/badge.svg)](https://github.com/Shashi552/netscope/actions/workflows/build-ipa.yml)
[![iOS 17+](https://img.shields.io/badge/iOS-17.0%2B-blue.svg)](https://developer.apple.com/ios/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Trackers](https://img.shields.io/badge/Trackers-0-brightgreen.svg)](Resources/PrivacyInfo.xcprivacy)
[![Architecture: arm64](https://img.shields.io/badge/Architecture-arm64-orange.svg)]()

**NetScope** is a native, fully graphical network assessment and security auditing application built exclusively for iPhone. 

**100% Free Forever.** No subscriptions, in-app purchases, ads, tracking frameworks, remote scanning agents, or mandatory cloud backends. Everything executes locally on your iPhone using Apple's native `Network.framework`, `URLSession`, and `Security.framework`.

---

## Quick Install on iPhone

Download the latest pre-compiled **[NetScope.ipa](https://github.com/Shashi552/netscope/releases/latest)**:

* **LiveContainer (No Revokes / JIT-less):**
  1. Download `NetScope.ipa` to the iPhone Files app.
  2. Open **LiveContainer** → tap `+` (**Import IPA**) → select `NetScope.ipa` → Tap to launch!
* **Sideloadly / AltStore (Free Apple ID):**
  1. Connect your iPhone to your Mac/PC.
  2. Drag `NetScope.ipa` into Sideloadly / AltStore, sign in with your Apple ID, and install.
  3. Trust your developer certificate under **Settings → General → VPN & Device Management**.
* **TrollStore (iOS 14.0–16.6.1 / 17.0):**
  1. AirDrop or open `NetScope.ipa` directly in TrollStore and tap Install.

---

## Key Capabilities

### 1. High-Performance TCP Port Assessment
* **Flexible Scope Parser:** Target single hostnames, IPv4/IPv6 addresses, CIDR notation (`/20` to `/32`), and hyphenated ranges (`10.0.0.1-10.0.0.50`).
* **Profile Library:** Quick presets for Web (80, 443, 8080, 8443), Common (top 30), or customized ranges up to 65,535.
* **Smart Concurrency & Backoff:** Concurrent non-blocking probes with automatic rate throttling on timeout bursts or connection limits.
* **Checkpoint & Resume:** Real-time state preservation every 512 observations with multi-session resume tracking.

### 2. Deep Diagnostic & Protocol Inspector
* **DNS Diagnostics (UDP, TCP & DoH):** Supports RFC 8484 **DNS over HTTPS (DoH)**, RFC 1035 **SOA record decoding** (serial, timers, master, mailbox), compression-loop protection, and side-by-side resolver answer diffing.
* **WebSocket Handshake Verification:** RFC 6455 HTTP upgrade testing, subprotocol negotiation, and ping round-trip latency measurement via `URLSessionWebSocketTask`.
* **TLS & Certificate Public-Key Pinning:** Evaluates X.509 chains, extracts **Subject Alternative Names (SANs)**, parses validity dates, and computes **SPKI SHA-256 fingerprints** for baseline public-key diffing.
* **HTTP / API Inspector:** Structured JSON response explorer, method testing (GET, HEAD, POST, PUT, DELETE, OPTIONS), side-by-side response comparison, origin binding, and local Keychain secret vault.
* **Service Greeting Reader:** Connects and captures initial banner output (SSH, FTP, SMTP) with differential change highlighting against previous connections.
* **OpenAPI Specification Explorer:** Local bounded JSON schema viewer with automatic warnings for state-changing endpoints.
* **Local Interfaces & Bonjour:** Reads assigned IPv4/IPv6 addresses and browses declared local mDNS services (`_http`, `_https`, `_ssh`, `_ipp`, `_smb`).

### 3. Professional Security Audit Lifecycle
* **Projects & Workspaces:** Group scans, target scopes, and review deadlines into distinct audit engagements.
* **Findings Tracker:** Triage security observations with CVSS-like transparent priority scoring, confidence ratings, and host/severity groupings.
* **Exception Expiry Reminders:** Schedule local device notifications 7 days before temporary security exemptions expire.
* **Baseline Differential Audits:** Compare two scan records side-by-side to detect newly opened ports, closed services, or changed greetings.
* **Executive PDF & CSV Reports:** Export paginated, branded PDF summaries with target redaction and automated SHA-256 evidence integrity manifests.
* **Encrypted Archives:** PBKDF2-HMAC-SHA256 and AES-GCM 256-bit password-protected project backups.

---

## Honest Platform Boundaries

NetScope strictly adheres to Apple's iOS security architecture:
* **No Raw SYN Scans:** iOS sandboxing denies `SOCK_RAW`. All scans use standard TCP handshakes via `Network.framework`.
* **No ARP / MAC Harvesting:** Apple blocks MAC address lookups on iOS 11+; addresses are evaluated via IP/DNS.
* **Foreground Operational Safety:** Active network probes pause when the app is backgrounded to prevent silent OS termination and incomplete data.
* **Defensive Only:** No exploit payloads, credential dictionary brute-forcing, or unauthorized scripts.

---

## Verification & Automated Test Suite

NetScope includes automated unit and integration tests covering scope expansion, DNS codecs, compression loop guards, encrypted archive round-trips, and WebSocket models.

Run the test suite on any macOS system:
```bash
swiftc -parse-as-library -o /tmp/netscope_tests \
  Scripts/run_standalone_tests.swift \
  Sources/Models.swift \
  Sources/Networking/Scope.swift \
  Sources/Networking/DNSClient.swift \
  Sources/Networking/HTTPInspector.swift \
  Sources/Networking/SocketExchange.swift \
  Sources/Networking/WebSocketInspector.swift \
  Sources/Audit/SecurityTools.swift \
  Sources/Audit/AuditModels.swift \
  Sources/Audit/ProbeProfile.swift \
  Sources/ScanStore.swift \
  Sources/TCPScanner.swift && /tmp/netscope_tests
```
**Result:** 75 assertions passed, 0 failures.

---

## Building from Source

### Cloud Build (GitHub Actions)
Push changes to your repository. The included `.github/workflows/build-ipa.yml` compiles on `macos-15` (Xcode 16 / iOS 18 SDK) and outputs `NetScope.ipa` in under 2 minutes.

### Local Mac Build (Xcode 15+)
```bash
# 1. Open project
open NetScope.xcodeproj

# 2. Package .ipa locally
./Scripts/build-ipa.sh
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
