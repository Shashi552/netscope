# Feature status — source, not verified operation

`FEATURE_BACKLOG.csv` maps all 180 original planning items individually. **Source** means reachable implementation exists; **partial** means a narrower implementation or UI exists; **planned** means absent; **conditional** requires platform proof; **removed** means intentionally excluded. None means a passed physical-iPhone test.

## Reachable modules

| UI | Implemented source | Boundaries |
|---|---|---|
| Scan | target/CIDR/range parser, profiles, exclusions, budget, explicit authorization, concurrency, timeout, retries, rate, real TCP results, checkpoint/resume | Max 262,144 host-port pairs; no raw SYN or device identity; private-only requires IPv4 literals |
| Tools → interfaces | interface/IP/netmask | No router/SSID guarantee |
| Tools → Bonjour | five declared service types | Advertised instance names only; no resolved IP mapping; no generic multicast discovery |
| Tools → HTTP/API/TLS | methods, Basic/Bearer, Keychain optional, Origin, assertions, bounded preview, status/headers, trust/certificates | No redirects followed, no trust bypass, no arbitrary header editor; cookie values redacted rather than comprehensively parsed |
| Tools → greetings | first received bytes on explicit TCP target | No full protocol parser, version extractor, or active probe library |
| Tools → DNS | typed queries, UDP/TCP, validated answers, TTL, compression guard, two-resolver comparison | PTR requires explicit reverse name; SOA hex; no authority/additional section UI; no encryption |
| Tools → health | bounded HEAD sessions, status assertions, timing chart | No continuous/background monitor or ICMP ping |
| Tools → OpenAPI | JSON file → method/path/summary list | No YAML, external refs, automatic calls or schema execution |
| Tools → custom TCP | bounded text/hex single payload and literal match | Raw unencrypted connection, first chunk only, no scripting |
| Scan → import | UTF-8 target text/simple comma list, JSON string array, QR plain scope | Not arbitrary tabular CSV parsing, no automatic scan from import |
| Audit → projects | names/client/scope/expiry/checklist/scan links | Scope/expiry documentation, not enforcement |
| Audit → inventory | aliases/tags/trust/criticality/notes and expected ports | Address ≠ stable identity; no MAC inventory |
| Audit → findings | manual evidence/remediation/severity/confidence/status | User assertions, not automatic verification/scoring |
| Audit → compare/exposure | observed open differences, latest scan's per-host service hints | Not topology, historical continuity or proven closure |
| Audit → history/activity | minimal HTTP/cert observations, local edit/export events | No immutable snapshots or tamper-proof audit |
| Audit → archives | password PBKDF2 + AES-GCM, explicit replace import | Audit data only; excludes scan history and Keychain secrets; cryptography needs independent review |
| History → exports | all-results CSV/JSON, paginated branded-text PDF, optional target alias redaction, file hash | PDF cap 5000 details; not comprehensive customizable reports or provenance proof |
| Settings | theme, device authentication, privacy cover, imports, cleanup/delete | Lock is UI gate; file protection ≠ separate encrypted database; no secure erase |

## Removed/conditional

- StoreKit/IAP is removed: user's final requirement is that every feature be free.
- Wake-on-LAN is conditional, not included. No broadcast entitlement workaround.
- Guaranteed all-device discovery, raw SYN/ARP/MAC inventory, OS fingerprinting, monitor mode, Wi-Fi cracking, continuous background scanning and exploit execution are not implemented or promised.
- No remote agents, external scan servers, paid service APIs, commercial fingerprint databases or vendor code are bundled.

## Next source gaps (not placeholders)

DoH/DoT, rich certificate SAN/issuer/extension parser, custom CA trust evaluation, certificate public-key pinning/diff, JSON field assertions, structured HTTP response diff, attachments, reporting revision locks/templates, project policy enforcement, retention-by-age UI, fine-grained redaction, localized strings, in-app training/demo mode, automatic remediation check catalog and CVE intelligence are absent or partial. Implement only after current modules pass testing.
