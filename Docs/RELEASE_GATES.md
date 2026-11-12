# Release gates — all currently pending unless separately evidenced

## Build & tests
- [ ] Xcode project loads and unsigned simulator Debug + Release builds pass.
- [ ] XCTest suite passes on selected simulator; tests are not marked passed from syntax checks.
- [ ] Signed physical-iPhone build and Release archive pass; analyzer warnings reviewed.
- [ ] No unsupported Apple API, private entitlement or strict-concurrency defect.
- [ ] Thread Sanitizer / Address Sanitizer and Instruments sessions reviewed.

## Correctness
- [ ] Known-open/refused/drop/unreachable targets accurately classified against ground truth.
- [ ] Permission denied, pending prompt, later grant and revocation handled honestly.
- [ ] Cancellation, timeout, simultaneous completion, navigation-away, background, phone lock and path-change stress: no leaked sockets, tasks or continuations.
- [ ] CIDR /20, /24, /30, /31, /32, excluded hosts/ports, full-range TCP and IPv6 zones tested.
- [ ] Retry/rate limits measured; no scan goes outside confirmed expanded target scope.
- [ ] Checkpoint crash/restart/resume coverage correct, no duplicate observations, session boundaries disclosed.
- [ ] HTTP redirects blocked across host/scheme/port; credentials never sent on HTTP, failed trust or after origin change.
- [ ] TLS dates/trust/fingerprints verified with fixture certificates; no hidden trust bypass.
- [ ] DNS compression loops/truncation/oversized records/question mismatch handled; fixtures fuzzed.
- [ ] Bonjour real-device entitlement/permission behavior and QR camera lifecycle tested.

## Storage & security
- [ ] Transactional persistence/import/recovery with no overwrite of corrupt original files.
- [ ] Limits/quotas validated on large files/long scans; main-thread stalls eliminated.
- [ ] Keychain save/update/delete/origin isolation validated; delete-all removes app credentials.
- [ ] Archive encryption reviewed, wrong password/tamper rejected, schema errors leave existing workspace intact.
- [ ] Privacy cover, passcode/biometric fallback, Face ID interruption and lock-enable/disable tested.
- [ ] Exports/PDF/CSV formula escaping/redaction verified; PDF cap and observation limitations visible.
- [ ] Data deletion removes checkpoints, app database, Keychain, app notifications and export files as advertised; no secure erase claim.

## Product & store
- [ ] Feature matrix and marketing match actual tested behavior; do not claim all 180 items.
- [ ] VoiceOver labels/navigation, Dynamic Type, contrast, portrait/landscape and small iPhone layouts pass.
- [ ] Localization decision and all permission text reviewed.
- [ ] No paywalls, IAP, subscriptions or mandatory external services added.
- [ ] App icon/screenshots/version metadata/privacy policy/support contact complete.
- [ ] Privacy manifest reasons/API inventory and App Store privacy labels independently verified.
- [ ] ATS exception justified by authorized HTTP inspection; encryption export classification completed.
- [ ] Applicable laws/acceptable use/authorized-scope language reviewed.
- [ ] App Review provided reproducible safe lab/demo instructions without fabricated live results.

Only mark production-ready after these have evidence, not because source exists or compilation succeeds.
