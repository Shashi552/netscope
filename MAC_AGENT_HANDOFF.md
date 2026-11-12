# Mac agent: continue NetScope safely

## User requirements (non-negotiable)

- Native iPhone app; all functionality free, no paywalls, IAP, subscriptions, ads, or remote scan agents.
- The Mac is only the build/sign/test environment. Do not introduce a runtime Mac, Pi, Linux, or cloud dependency.
- Fully graphical workflows. No terminal required by app users.
- Only authorized network auditing. No fabricated scan results, exact-version guarantees, or unsupported iOS features.

## Current source status

A broad implementation is present, **not compiled in the authoring environment**. Swift source syntax was tree-parsed, XML/property lists parsed, project references checked, and source archive integrity checked. No XCTest, Xcode build, device network test, Instruments run, security certification, or App Store review has occurred.

Read README.md, Docs/FEATURE_STATUS.md, Docs/FEATURE_BACKLOG.csv, Docs/THREAT_MODEL.md, and Docs/RELEASE_GATES.md. Do not mark the entire 180-item backlog shipped. Status "source" in the CSV means code exists, not verified functionality.

## First actions

1. Inspect project and build configuration; `open NetScope.xcodeproj`.
2. `bash Scripts/verify_on_mac.sh` (simulator compile, signing disabled).
3. Fix all Swift/SDK/type-checking/build errors without replacing functionality with mock data. Focus on Network/Security delegate APIs, Swift concurrency captures, CommonCrypto import, SwiftUI type-checker complexity and the custom project.
4. If large SwiftUI builders time out, split into small views; do not delete diagnostics to get a green build.
5. `xcodebuild -showdestinations -project NetScope.xcodeproj -scheme NetScope`; run unit tests on an available simulator. Use concrete destinations, not the generic destination for tests.
6. Set signing team + unique bundle ID. Build/run on physical iPhone; allow Local Network only after deliberate scan/discovery action.
7. Run manual scenarios in Docs/DEVICE_TEST_PLAN.md using your own lab.
8. Save actual logs/results under Verification/. No credentials, client IP lists or sensitive response bodies in committed logs.

## Known engineering priorities before external release

- Thread/cancellation stress for TCPProbe, SocketExchange and URLSession delegate transport. Check every continuation completes once and every timer/socket/session is torn down.
- Main-thread scan history/checkpoint JSON writes, repeated live filters/sorts, PDF rendering and audit decode are potentially expensive. Move heavy operations to dedicated actors/workers with atomic commits and bounded UI updates. Test a full 65,535-port scan and large imports with Instruments.
- Storage uses whole JSON files and fixed record caps; migrate to a schema-versioned database (SwiftData/SQLite) with safe migrations, per-result paging, transactional checkpoints and storage quotas. Preserve imports and privacy behavior.
- Resume currently extends the same scan's observation window and skips recorded outcomes. Record session segments/settings and distinguish recovery from a new comparable scan. Abrupt termination can lose up to 511 post-checkpoint observations.
- If loading fails, preserve original files (write guards exist); implement a user-facing recovery/export workflow. Verify encrypted audit restore publishes state only after durable validation/write; extend equivalent guarantees to other imports.
- `NWPathMonitor` isn't a reliable Wi-Fi network identity. Do not silently resume based on unchanged interface name. Require scope reconfirmation and clearly disclose ambiguity.
- Exact-address exclusions do not block alternate hostnames resolving to the same IP. Add DNS-resolved scope policy/pinning where supportable. Never claim hostname authorization or DNS rebinding protection until tested.
- Verify response-size caps, connection resource caps, structured DNS parser bounds, malformed data fuzzing and image/QR lifecycle. Add SOA decoding and authority/additional rendering if pursued.
- Authenticate requests only after successful hostname/system trust validation. Never add a global "trust all certificates" bypass. For standalone invalid-cert inspection, retain metadata but do not send secrets or follow redirects.
- Refine certificate parsing: the custom DER utility extracts validity only; use a reviewed parser for SAN/issuer/extensions. Do not infer self-signed or exact issuer from subject summary.
- Review App Store ATS exception justification (intentional inspection of arbitrary authorized HTTP endpoints), privacy manifest/API reasons, camera/FaceID text, export encryption classification and product metadata.
- Verify Keychain scoped credentials are never sent after URL changes. Add secure credential editing/deletion UX, avoid secrets in exported evidence. Keychain helpers currently delete+insert; use an atomic update-first strategy for production.
- Verify lock/unlock and privacy cover with passcode, Face ID interruptions, revoked biometrics, iOS lifecycle, and accessibility. Do not implement a silent auth bypass.
- Add configured limits on audit collection edits, profiles, evidence size and imports. The app should not grow unbounded.
- Access-control audit: projects document scope and expiration but do not enforce it across independent tool tabs. Implement project-scoped execution policies if advertising enforcement.
- Data deletion should be tested end-to-end, including Keychain, notifications, checkpoints and exports. Shared/exported copies remain outside app control. No secure-erasure promises.

## Additional backlog direction

The complete conversational backlog is in Docs/FEATURE_BACKLOG.csv. Prioritize robust real functionality over the raw feature count. Planned features include DoH/DoT, richer certificate details, custom trust anchors, attachments, report revisions, checks catalog, JSON response assertions, custom report layouts and policy automation. Some items must be removed or constrained for platform/privacy/legal reasons. Wake-on-LAN remains conditional and is not implemented. Continuous background scanning and raw/ARP Wi-Fi capture must not be advertised.

## Build/project maintenance

The dependency-free project generator is Scripts/generate_project.py. Regenerate after adding Swift files; inspect the diff. Optional project.yml can instead be used with XcodeGen. Do not alternate generators without reviewing resulting build settings. Resources and Info.plist must remain in sync.

## Definition of done

A production release needs all Docs/RELEASE_GATES.md checks passing with evidence, unit tests and a clean Release build/archive on Mac, real-device testing, resolved security risks, correct permissions and privacy/export classification, usable accessibility, and honest feature descriptions. Do not label this handoff production-ready merely because it compiles.
