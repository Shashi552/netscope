# Feature status — source, not verified operation

`FEATURE_BACKLOG.csv` maps all 180 original planning items individually. **Source** (98 items) means reachable implementation exists in code; **partial** (74 items) means a narrower implementation or UI exists; **planned** (6 items) means deferred to future milestones; **conditional** (1 item) requires platform proof; **removed** (1 item) means intentionally excluded. None means a passed physical-iPhone test.

## Reachable modules

| UI | Implemented source | Boundaries |
|---|---|---|
| Scan | target/CIDR/range parser, profiles, exclusions, budget, explicit authorization, concurrency with backoff, timeout, retries, rate, real TCP results, checkpoint/resume tracking | Max 262,144 host-port pairs; no raw SYN or device identity; private-only requires IPv4 literals |
| Tools → interfaces | interface/IP/netmask | No router/SSID guarantee |
| Tools → Bonjour | five declared service types | Advertised instance names only; no resolved IP mapping; no generic multicast discovery |
| Tools → HTTP/API/TLS | methods, Basic/Bearer, Keychain optional, Origin, assertions, bounded preview, status/headers, trust/certificates, response comparison, structured JSON explorer | No redirects followed, no trust bypass, no arbitrary header editor; cookie values redacted rather than comprehensively parsed |
| Tools → certificates | SAN list extraction, SPKI SHA-256 public-key fingerprinting, baseline key comparison, DER export, 7-day expiry reminder | Connection observation; not full certificate authority chain building or custom root installation |
| Tools → greetings | first received bytes on explicit TCP target, changed greeting banner highlighting | No full protocol parser, version extractor, or active probe library |
| Tools → DNS | typed queries (A, NS, CNAME, SOA, PTR, MX, TXT, AAAA), UDP/TCP transport, DoH (RFC 8484 DNS over HTTPS), validated answers, TTL, compression loop guard, two-resolver comparison | PTR requires explicit reverse name; DoH uses URLSession HTTPS wireformat; no DNSSEC cryptographic validation |
| Tools → WebSocket | RFC 6455 upgrade verification, subprotocol negotiation, ping frame RTT measurement, clean close | Foreground only; strict TLS validation enforced for wss://; no continuous streaming or unvetted scripts |
| Tools → health | bounded HEAD sessions, status assertions, timing chart | No continuous/background monitor or ICMP ping |
| Tools → OpenAPI | JSON file → method/path/summary list | No YAML, external refs, automatic calls or schema execution |
| Tools → custom TCP | bounded text/hex single payload and literal match | Raw unencrypted connection, first chunk only, no scripting |
| Scan → import | UTF-8 target text/simple comma list, JSON string array, QR plain scope | Not arbitrary tabular CSV parsing, no automatic scan from import |
| Audit → projects | names/client/scope/expiry/checklist/scan links | Scope/expiry documentation, not enforcement |
| Audit → inventory | aliases/tags/trust/criticality/notes and expected ports | Address ≠ stable identity; no MAC inventory |
| Audit → findings | manual evidence/remediation/severity/confidence/status, explainable priority score breakdown, host/severity grouping, 7-day exception expiry reminders | User assertions, not automatic verification/scoring; reminders use local UNUserNotificationCenter |
| Audit → compare/exposure | observed open differences, latest scan's per-host service hints, revision comparison JSON export | Not topology, historical continuity or proven closure |
| Audit → history/activity | minimal HTTP/cert observations, local edit/export events | No immutable snapshots or tamper-proof audit |
| Audit → archives | password PBKDF2 + AES-GCM, explicit replace import | Audit data only; excludes scan history and Keychain secrets; cryptography needs independent review |
| History → exports | all-results CSV (with formula-injection escaping), JSON, paginated branded-text PDF, target alias redaction preview, file hash manifest | PDF cap 5000 details; not comprehensive customizable reports or provenance proof |
| Settings / About | theme, device authentication, privacy cover, storage usage dashboard (live byte breakdown & cleanup), sanitized diagnostics export, safe demo walkthrough (RFC 5737) | Lock is UI gate; file protection ≠ separate encrypted database; no secure erase |

## Removed/conditional

- StoreKit/IAP is removed (#83): user's non-negotiable requirement is that every feature is 100% free with no in-app purchases or paywalls.
- Wake-on-LAN is conditional (#102), not included. No broadcast entitlement workaround.
- Guaranteed all-device discovery, raw SYN/ARP/MAC inventory, OS fingerprinting, monitor mode, Wi-Fi cracking, continuous background scanning and exploit execution are not implemented or promised.
- No remote agents, external scan servers, paid service APIs, commercial fingerprint databases or vendor code are bundled.

## Remaining planned items

6 items remain in planned status awaiting platform feasibility verification:
1. #87: Per-device scan overrides (per-host customized port lists).
2. #116: Custom CA trust evaluation (intentionally deferred to prevent insecure certificate validation without managed configuration profile).
3. #143: Finalized immutable assessment snapshots.
4. #153: Automatic resolution verification.
5. #168: Evidence attachments.
6. #179: Saved professional dashboard layouts.
