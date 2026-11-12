import Foundation
import LocalAuthentication
import Security
import CryptoKit
import CommonCrypto

@MainActor final class AppSecurity: ObservableObject {
    @Published var unlocked = false
    @Published var message = ""
    func unlock() async {
        let context = LAContext()
        do { unlocked = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock your network audit records") }
        catch { message = error.localizedDescription }
    }
}
enum SecretVault {
    static func put(_ value: String, account: String) throws {
        let query: [String:Any] = [kSecClass as String:kSecClassGenericPassword, kSecAttrService as String:"app.netscope.secrets", kSecAttrAccount as String:account]
        let updateAttrs: [String:Any] = [kSecValueData as String: Data(value.utf8)]
        let status = SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary)
        if status == errSecSuccess { return }
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = Data(value.utf8)
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw InputError.invalid("Keychain write failed.") }
        } else {
            throw InputError.invalid("Keychain write failed.")
        }
    }
    static func get(account: String) -> String? {
        let query: [String:Any] = [kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:"app.netscope.secrets",kSecAttrAccount as String:account,kSecReturnData as String:true,kSecMatchLimit as String:kSecMatchLimitOne]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    static func removeAll() {
        SecItemDelete([kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:"app.netscope.secrets"] as CFDictionary)
    }
    static func remove(account: String) { SecItemDelete([kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:"app.netscope.secrets",kSecAttrAccount as String:account] as CFDictionary) }
}
enum EncryptedArchive {
    // Versioned format: magic (5) + random salt (16) + AES.GCM combined ciphertext.
    // PBKDF2-HMAC-SHA256, 600,000 rounds; performed off the UI thread by callers.
    private static let magic = Data("NSAR1".utf8)
    private static func key(password: String, salt: Data) throws -> SymmetricKey {
        guard password.count >= 12, password.utf8.count <= 1024 else { throw InputError.invalid("Use a password of 12–1024 UTF-8 bytes (at least 12 characters).") }
        let pass = Array(password.utf8); let saltBytes = [UInt8](salt)
        var derived = [UInt8](repeating: 0, count: 32)
        let result = pass.withUnsafeBytes { p in saltBytes.withUnsafeBytes { s in derived.withUnsafeMutableBytes { out in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), p.baseAddress!.assumingMemoryBound(to: Int8.self), pass.count, s.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600_000, out.baseAddress!.assumingMemoryBound(to: UInt8.self), 32)
        } } }
        guard result == kCCSuccess else { throw InputError.invalid("Password key derivation failed.") }
        return SymmetricKey(data: derived)
    }
    static func seal(_ data: Data, password: String) throws -> Data {
        guard data.count <= 32*1024*1024 else { throw InputError.invalid("Archive input exceeds size limit.") }
        var salt = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess else { throw InputError.invalid("Secure random generation failed.") }
        let saltData = Data(salt)
        let box = try AES.GCM.seal(data, using: key(password: password, salt: saltData), authenticating: magic + saltData)
        guard let combined = box.combined else { throw InputError.invalid("Archive encryption failed.") }
        return magic + saltData + combined
    }
    static func open(_ data: Data, password: String) throws -> Data {
        guard data.count >= 49, data.count <= 33*1024*1024, data.prefix(5) == magic else { throw InputError.invalid("Invalid or oversized NetScope archive.") }
        let salt = Data(data[5..<21]); let key = try key(password: password, salt: salt)
        return try AES.GCM.open(AES.GCM.SealedBox(combined: Data(data.dropFirst(21))), using: key, authenticating: magic + salt)
    }
}
enum ExportFiles {
    static var folder: URL { FileManager.default.temporaryDirectory.appendingPathComponent("NetScopeExports", isDirectory: true) }
    static func write(_ data: Data, name: String) throws -> URL {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let file = folder.appendingPathComponent(name)
        try data.write(to: file, options: [.atomic, .completeFileProtection]); return file
    }
    static func clear() throws {
        if FileManager.default.fileExists(atPath: folder.path) { try FileManager.default.removeItem(at: folder) }
        // Clean first-version exports too.
        for url in try FileManager.default.contentsOfDirectory(at: FileManager.default.temporaryDirectory, includingPropertiesForKeys: nil) where url.lastPathComponent.hasPrefix("NetScope-") { try? FileManager.default.removeItem(at: url) }
    }
}
