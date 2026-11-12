# Threat model and security boundaries

## Assets

Authorized scope, private addresses/hostnames, response text, service banners, credentials, certificates, findings, projects and exported files. The phone owner controls the tool; target servers and imported data are untrusted.

## Boundaries and mitigations present in source

- No downloaded scripts, shell execution, exploit engine, or cloud scan relay.
- Explicit scope/authorization controls; bounded target and port lists, scan workload confirmation, concurrency/rate/time limits.
- Optional literal-private-IPv4 mode; it rejects hostnames instead of pretending to resolve/rebind safely.
- HTTP redirects blocked to prevent surprise scope/credential forwarding; credentials allowed only on HTTPS; system certificate + hostname trust evaluated. URL edits clear token/password fields.
- Ephemeral URLSession configuration, no automatic cookie persistence, no shared credential storage, no shared response cache. Optional Keychain entries keyed by HTTPS host + port and device-only accessibility.
- Captured payload sizes bounded; text displayed as Text, not WebView HTML. DNS parser guards record lengths, compression cycles and transaction/question mismatch.
- Imported file limits/schema checks. QR data is only scope text, never a deep link executing actions. Imports never automatically contact a target.
- iOS file protection, backup exclusion, app-switcher privacy cover and optional LocalAuthentication UI lock.
- Encrypted audit archives use AES-GCM with authenticated magic/salt and random 16-byte salt; PBKDF2-HMAC-SHA256 600,000 rounds; minimum password length. This is not a professionally audited archive standard.
- CSV text cells quote/escape data and prefix spreadsheet-formula-leading content. PDF target alias redaction omits raw host identifiers/evidence. JSON/CSV are unredacted and explicitly labeled sensitive.

## Residual risks / production blockers

1. User authorization is asserted, not verified. The app cannot prove ownership of targets. Exclusions apply to normalized target strings, not all equivalent DNS/IP identities.
2. DNS rebinding/resolved-address pinning and hostname-based policy enforcement are absent. URLSession may resolve a different address later. Do not advertise protection against this.
3. Scanning/probing can disrupt fragile devices or trigger alerts even without exploits. Use gentle profile; warn and test.
4. Arbitrary HTTP inspection requires ATS exception. TLS policy must not be weakened for HTTPS. Review this exception with App Review.
5. Private response bodies, URLs/query strings and arbitrary headers can carry secrets despite cookie redaction. Full observation exports are sensitive; no guarantee of comprehensive secret detection.
6. NSFileProtectionComplete mitigates locked-device access, not an unlocked compromised device. App lock is not a cryptographic database lock. Secret Swift strings are not reliably zeroized from memory.
7. Local JSON and activity records are mutable by a device owner. Export hashes provide no independent provenance, signature or timestamp.
8. App extensions, universal links and URL handlers are not present; if added, re-evaluate automatic execution/import risks.
9. Whole-file persistence/decoding/report generation and frequent UI filtering can consume CPU/memory and hang UI under large scans. Profile and redesign before release.
10. Limited DER parser extracts dates only; no complete X.509 parser. Trust framework is authoritative for connection validity. Do not derive issuer/SAN or self-signed status heuristically.
11. Notifications are saved-date reminders, not verified renewals. A changed/renewed certificate does not automatically cancel previous reminders.
12. Export files can survive until manual cleanup/next launch or OS purge. Shared copies cannot be revoked. Deletion is not secure erase and original copies/backups outside app control remain.
13. Corruption write guards preserve original storage files but lack a complete recovery UI. Archive replacement now writes atomically before publishing state; verify disk-full/failure behavior before shipping.
14. Raw TCP probe payloads are user supplied; the app cannot establish that a payload is harmless. Bound size/time, require confirmation, no auto-repeat or script engine.

## Required review

Run sanitizers/stress tests, fuzz the network/import parsers, review crypto/Keychain, test failure and lifecycle states on real iPhones, audit all logs/exports for secrets and independently validate App Store privacy/export declarations. No claim of security certification is made.
