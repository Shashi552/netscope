# Physical iPhone test plan (not executed here)

Use only a lab you own/control. Never run mass discovery on a workplace/guest/customer network without authorization. A Mac may provide test services in a lab; the installed app must not depend on a Mac at runtime.

| Area | Scenario | Expected |
|---|---|---|
| TCP | Listener open, explicit reject, silent drop, unreachable route | Distinct open/refused/no-response/unreachable where observable; ambiguous errors not invented |
| Scope | Subnet /30, /31, /32; bounded range; exclusions | Preview and attempted endpoints exactly match parser output |
| Scope | URL, huge CIDR, invalid IPv4/IPv6, zero port, reversed ranges | Clear validation failure before network traffic |
| Scope | Private-only with public literal/DNS/IPv6 | Rejected, not silently resolved/expanded |
| Lifecycle | Cancel immediately, during timeout, while many probes complete | One completion per probe, no crash, sockets close, partial results |
| Lifecycle | Background/lock/terminate/relaunch/resume | Graceful stops save; abrupt loss limited to checkpoint window; no auto-resume |
| Connectivity | Wi-Fi off, roaming, new interface, same-interface subnet change | Stop where detected; limitation disclosed where not detectable |
| Discovery | Granted/denied local permission, declared HTTP/IPP service | Only real service advertisements; no all-devices claim |
| HTTP | Normal GET, HEAD, OPTIONS, large/chunked/binary response | Bounded capture; preview as text, not scripts; no silent full-body-hash claim |
| HTTP | Same/cross-host redirect, HTTP→HTTPS, HTTPS→HTTP | Redirect displayed and never followed |
| Auth | Basic/Bearer, URL edit, hostname mismatch, untrusted cert, plain HTTP | Secrets only on trusted HTTPS; URL edits clear memory values |
| Keychain | Save/load/delete at origin A and origin B | No automatic cross-origin credential reuse; delete-all removes items |
| TLS | Valid/expired/not-yet-valid/wrong-name/self-signed fixture | Correct system trust result, valid DER export/hash/dates; no insecure fetch of protected content |
| DNS | UDP/TCP, A/AAAA/MX/TXT/SRV/CAA, negative answer, truncation | Type/TTL/code rendered; truncation warning; malformed data fails safely |
| DNS | Mismatched ID/name/type, compression cycle, record overflow | Reject without hangs or out-of-bounds access |
| Health | Endpoint status changes, disconnect, navigate away/background | Correct bounded samples, clean stop, not continuous monitoring |
| OpenAPI | Valid JSON, YAML, oversized file, external $ref, POST | JSON only; no external fetches or operations executed |
| QR | Deny camera, malformed scope, URL payload, cancel sheet | No scan starts automatically; invalid scope rejected |
| Archive | Valid/wrong password/tampered/version mismatch | Authentication failures and invalid schemas do not destroy existing data |
| Files | Scan import, protected-device lock, corrupted JSON, low disk | Clear errors, original corrupt data preserved, no hidden success |
| Reports | Redacted PDF, >5000 outcomes, formula-leading CSV text | Host aliases only in redacted PDF; cap visible; CSV cannot start formulas |
| Privacy | Active→inactive snapshot, auth overlay, token editing | Sensitive UI obscured during app-switch transitions; no hidden auth bypass |
| Accessibility | VoiceOver, largest Dynamic Type, landscape, small screen | All actions reachable and readable; no color-only status |

Run full-range single-host scan and large CIDR/common-port scan under Instruments before raising limits. Log peak memory, CPU, battery, task/socket counts, false negatives, timing distribution and UI responsiveness. Do not publish speed benchmarks from localhost or substitute desktop tool claims.
