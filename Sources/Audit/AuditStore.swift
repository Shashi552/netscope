import SwiftUI

@MainActor final class AuditStore: ObservableObject {
    @Published var database = AuditDatabase()
    @Published var error: String?
    private var canWrite = true
    private let url: URL
    init() {
        let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        url = folder.appendingPathComponent("audit-v1.json")
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            var excluded = folder; var values = URLResourceValues(); values.isExcludedFromBackup = true; try excluded.setResourceValues(values)
            if FileManager.default.fileExists(atPath: url.path) {
                let data = try Data(contentsOf: url)
                guard data.count <= 32*1024*1024 else { throw InputError.invalid("Audit database exceeds size limit.") }
                let loaded = try JSONDecoder().decode(AuditDatabase.self, from: data)
                guard loaded.schemaVersion == 1 else { throw InputError.invalid("Unsupported audit database version; original file preserved.") }
                database = loaded
            }
        } catch { canWrite = false; self.error = "Audit file could not be loaded; writes disabled to preserve original. Export/copy the file before recovery. " + error.localizedDescription }
    }
    func save(_ action: String) {
        guard canWrite else { error = "Audit writes disabled after a load error; recover or explicitly replace/delete data first."; return }
        database.events.insert(ActivityEvent(date: Date(), action: action), at: 0)
        database.events = Array(database.events.prefix(1000))
        do { try JSONEncoder().encode(database).write(to: url, options: [.atomic, .completeFileProtection]) }
        catch { self.error = error.localizedDescription }
    }
    func addObservation(_ observation: HTTPObservation) {
        // Bodies and arbitrary headers may contain secrets. Keep only a minimal explicit history.
        let safe = HTTPObservation(date: observation.date, url: observation.url, method: observation.method, status: observation.status, headers: observation.headers.filter { ["server","content-type","strict-transport-security","content-security-policy","x-content-type-options","referrer-policy"].contains($0.key) }, bodyPreview: "[not retained]", bodySHA256: observation.bodySHA256, bytesCaptured: observation.bytesCaptured, truncated: observation.truncated, elapsed: observation.elapsed, negotiatedProtocol: observation.negotiatedProtocol, tlsVersion: observation.tlsVersion, cipherSuite: observation.cipherSuite, certificates: observation.certificates, error: observation.error)
        database.http.insert(safe, at: 0); database.http = Array(database.http.prefix(100)); save("Saved HTTP/TLS observation")
    }
    func erase() { canWrite = true; database = AuditDatabase(); save("Audit data cleared") }
    func replace(from data: Data) throws {
        guard data.count <= 32*1024*1024 else { throw InputError.invalid("Import exceeds 32 MiB.") }
        let imported = try JSONDecoder().decode(AuditDatabase.self, from: data)
        guard imported.schemaVersion == 1, imported.events.count <= 1000, imported.http.count <= 100,
              imported.projects.count <= 1000, imported.devices.count <= 10000, imported.findings.count <= 10000, imported.profiles.count <= 1000 else { throw InputError.invalid("Unsupported version or import exceeds collection limits.") }
        var replacement = imported
        replacement.events.insert(ActivityEvent(date:Date(),action:"User replaced audit database from archive"),at:0)
        replacement.events = Array(replacement.events.prefix(1000))
        // Commit before publication: a disk failure leaves the previous in-memory and on-disk workspace intact.
        let encoded = try JSONEncoder().encode(replacement)
        try encoded.write(to:url,options:[.atomic,.completeFileProtection])
        canWrite = true; database = replacement
    }
}
