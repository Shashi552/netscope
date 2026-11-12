# App Store preparation — draft, not legal/compliance advice

- Purpose: graphical, local, authorized TCP and application-protocol network assessment. No exploit engine, covert background scanning, packet sniffing or runtime remote agent.
- All features free; no IAP/StoreKit product, ads or analytics SDKs.
- Local Network permission text explains actual connections; declared Bonjour types match browser choices. No custom multicast/broadcast entitlement requested.
- Camera permission only for user-requested QR scope import; no image upload or retention.
- Face ID/device passcode only for optional app lock. Device-only Keychain stores explicitly saved HTTPS credentials.
- Notifications requested only when user creates a certificate reminder; no push service.
- ATS `NSAllowsArbitraryLoads` is intentional so users can inspect authorized cleartext HTTP endpoints. HTTPS still evaluates Security framework trust/hostname and never bypasses failures. This exception requires review/justification.
- `PrivacyInfo.xcprivacy` is a draft: no tracking/SDK collection; UserDefaults app-specific preferences reason CA92.1. Audit all required-reason APIs on final binaries. Local/network data use must be correctly described in privacy policy and final App Store questionnaire.
- Encryption export compliance is deliberately not pre-answered in Info.plist. Standard CryptoKit AES-GCM and CommonCrypto PBKDF2 archive encryption need final classification/documentation review.
- Website privacy policy/support URLs, terms, screenshots, accessibility metadata, review-safe demonstration instructions and test resources are not supplied. Do not invent them.
- Do not market “every device,” exact server versions, complete vulnerability discovery, physical topology, compliance certification, desktop RustScan speeds or uninterrupted background monitoring.
- Check icon and user-facing name/trademarks before publication. This original code does not bundle RustScan/Nmap or third-party fingerprint databases.
