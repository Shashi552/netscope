# NetScope — free, native, iPhone-only network auditing

**Handoff version 0.2.0. No subscriptions, purchases, ads, analytics SDKs, runtime agents, or cloud scanning backend.** The Mac is needed only to compile/sign/install the iPhone app.

## Start here

1. Unzip and open **NetScope.xcodeproj** on your Mac (Xcode 16+ recommended; deployment target iOS 17).
2. Read **MAC_AGENT_HANDOFF.md** and **Docs/RELEASE_GATES.md** before asking an agent to continue.
3. Select your signing team and unique app bundle identifier for physical-device installation.
4. Run `bash Scripts/verify_on_mac.sh` to attempt an unsigned simulator build. Fix build issues before proceeding.
5. Run the XCTest suite on an installed simulator, then perform actual network tests on a physical iPhone.

The included project can be regenerated with `python3 Scripts/generate_project.py` (no third-party Python dependencies). An optional `project.yml` is also included for XcodeGen users; use one generation approach consistently.

## Important status

This is a substantial **uncompiled source implementation**, not a production-certified app or an IPA. The authoring environment had no Swift compiler, Xcode, simulator, signing team, or iPhone. A Swift syntax-tree parse and project/resource integrity checks were performed; those do **not** validate Swift types, Apple SDK availability, threading, successful networking, or App Store acceptance. The Mac agent must compile and fix issues, run tests, and complete the release gates.

**The 180-item conversation list is a planning backlog, not 180 shipped features.** Read `Docs/FEATURE_STATUS.md` for exact boundaries. No placeholder result data is presented as a scan.

## Implemented source modules

### Scan
- Individual hostnames, IPv4/IPv6, IPv4 CIDR /20–/32 and full IPv4 ranges; validation, deduplication, scope-size limits.
- Common/web/custom/full TCP-port lists; host/port exclusions; optional RFC1918 IPv4-only policy.
- Authorization confirmation and workload preview; saved target/port/concurrency/timeout profiles.
- Bounded concurrent TCP-connect probes, rate limiting, configurable timeouts, up to two ambiguous-failure retries, gentle settings.
- Open/refused/timed-out/unreachable/error observations, live results, cancellation, checkpoints and same-record resume.
- Background cancellation; best-effort network-path-change cancellation. No uninterrupted background scans.

### Discover & inspect
- Local interface addresses/netmasks; Bonjour browsing for five declared service types.
- Bounded greeting reads for servers that speak first (e.g. SSH/SMTP/FTP); no false protocol verification claim.
- HTTP/API inspector with explicit GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE confirmation, HTTPS Basic/Bearer authentication, optional origin header, text/status assertions, safe response preview and hashes.
- Optional origin-keyed device-only Keychain credential storage. Changing the URL clears in-memory tokens/passwords. Redirects never followed.
- TLS system trust/hostname evaluation, evaluated chain, certificate validity dates, public-key attributes, SHA-256 fingerprint and DER export; expiry reminders by explicit permission.
- DNS UDP/TCP queries, answer decoding, TTLs, transaction/question validation, compressed-name cycle guards, two-resolver answer comparison.
- Foreground HTTP HEAD health sessions and charts.
- Local OpenAPI JSON explorer (no external references fetched and no auto-executed operations).
- Bounded single TCP text/hex probe tool (no script execution).
- Target-list file import and optional camera-based scope QR import; neither starts a scan.

### Audit & privacy
- Projects, authorization dates, manual checklists, scan links, device aliases/tags/trust/criticality/notes, expected-port review.
- Evidence/remediation findings with user-assigned severity, confidence and lifecycle.
- Scan comparisons, latest-scan service exposure view, minimal saved HTTP/TLS observations, local activity history.
- Full scan CSV/JSON export; JSON scan import; paginated PDF scan reports with optional target alias redaction and branding text; SHA-256 manifests.
- iOS file protection and backup exclusion for local records, opt-in device-authentication lock, app-switcher cover, theme support.
- Password-encrypted audit database archives (PBKDF2-HMAC-SHA256, random salt, AES-GCM); explicit replacement import; password recovery is not possible. **Does not include TCP scan history or Keychain credentials.**
- Data deletion, temporary-export cleanup, fixed collection retention caps.

## Constraints you must retain

- No raw SYN, ARP/MAC inventory, monitor mode, Wi-Fi cracking, OS fingerprinting, complete network enumeration or exploitation.
- A successful TCP connection does not verify a service or vulnerability. A timeout does not prove closed/filtered/absent.
- Bonjour lists advertised service names, not resolved IP inventory. TCP subnet scanning is best effort; no “all devices” claim.
- TLS inspection evaluates a connection, not every supported version/cipher. Failed trust is never bypassed, so invalid-TLS endpoints cannot be authenticated or browsed through this inspector.
- Single-packet/chunk greeting reads can truncate fragmented greetings. DNS SOA is currently hex; authority/additional records are not rendered. DNS requests are not encrypted; DoH/DoT are not implemented.
- HTTP capture max 128 KiB, text preview max 32 KiB, request body max 64 KiB. Hashes cover captured bytes only. Cookies are redacted, not comprehensively analyzed. Headers/body/query strings can still contain sensitive data.
- Scan budget: 262,144 host-port pairs, up to 4096 hosts. Scan UI shows first 200 open results; history UI first 500 filtered outcomes. JSON/CSV retain all outcomes; PDF details capped at 5000 rows and explicitly labeled.
- Checkpoints every 512 observations: abrupt termination may lose observations since the last checkpoint. Graceful cancellation saves received results. Resume does not recheck completed outcomes.
- Scan records capped at 20 and a combined 262,144 stored observations; saved HTTP observations 100; activity events 1000. Audit collection size/age policies still need production tuning.
- Scope authorization is user-confirmed, not verified ownership. DNS rebinding/resolved-address pinning is not implemented. Private-only scan mode rejects hostnames and IPv6 rather than pretending to enforce a DNS-safe policy.
- `NWPathMonitor` cannot reliably identify every same-interface Wi-Fi/subnet change. No SSID/location entitlement is requested.
- Device lock is a UI gate, not a separate encrypted database key. File protection is not secure erase. Local activity and file hashes are not independently signed/timestamped proof.

## Project map

- `Sources/NetScopeApp.swift`: app shell, scanner, history, reporting, settings.
- `Sources/TCPScanner.swift`, `ScanStore.swift`, `Models.swift`: scan engine, checkpointing and persistence.
- `Sources/Networking/`: scope/interfaces, Bonjour, bounded socket exchanges, DNS codec/client, HTTP/TLS inspector, path monitoring.
- `Sources/ToolsViews.swift`, `CustomProbeView.swift`, `QRScannerView.swift`: diagnostic tools.
- `Sources/Audit/`, `AuditViews.swift`: projects, findings, inventory, comparisons, reports, encrypted archives, app authentication and Keychain helpers.
- `Tests/`: input/scope, DNS safety, archive integrity, comparison and serialization tests (not executed here).
- `Resources/`: app icon and privacy manifest draft.
- `Docs/`: feature status, threat model, release gates, manual tests and App Store notes.

## License

MIT for original project code. Uses Apple system frameworks; no Nmap/RustScan binaries, proprietary fingerprint data, CVE feed, or third-party scanning engine is bundled. Standard encryption still requires App Store export-compliance classification; answer the questionnaire based on your final app, not assumptions.
