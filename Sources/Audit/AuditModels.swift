import Foundation

struct DeviceNote: Identifiable, Codable {
    var id = UUID()
    var host = ""
    var alias = ""
    var tags = ""
    var notes = ""
    var trusted = false
    var criticality = "Normal"
    var expectedPorts = ""
}
struct AuditProject: Identifiable, Codable {
    var id = UUID()
    var name = "New assessment"
    var client = ""
    var scope = ""
    var authorizationExpires = Date().addingTimeInterval(30*86400)
    var notes = ""
    var createdAt = Date()
    var checklist: [String:Bool] = ["Authorization confirmed": false, "Scope reviewed": false, "TCP coverage reviewed": false, "Services manually verified": false, "Remediation reviewed": false, "Report reviewed": false]
    var scanIDs: [UUID] = []
}
struct AuditFinding: Identifiable, Codable {
    var id = UUID()
    var title = ""
    var host = ""
    var evidence = ""
    var remediation = ""
    var severity = "Informational"
    var confidence = "Observed"
    var status = "Open"
    var createdAt = Date()
    var updatedAt = Date()
    var exceptionExpires: Date?
}
struct SavedProfile: Identifiable, Codable {
    var id = UUID()
    var name: String
    var targets: String
    var ports: String
    var concurrency: Int
    var timeout: Double
}
struct ActivityEvent: Identifiable, Codable {
    var id = UUID()
    let date: Date
    let action: String
}
struct AuditDatabase: Codable {
    var schemaVersion = 1
    var projects: [AuditProject] = []
    var devices: [DeviceNote] = []
    var findings: [AuditFinding] = []
    var profiles: [SavedProfile] = []
    var http: [HTTPObservation] = []
    var events: [ActivityEvent] = []
}
struct ScanDifference: Identifiable {
    var id: String { host + ":" + String(port) }
    let host: String
    let port: UInt16
    let change: String
}
enum ScanComparison {
    static func compare(old: ScanRecord, new: ScanRecord) -> [ScanDifference] {
        let oldMap = Dictionary(old.results.map { ("\($0.host):\($0.port)", $0) }, uniquingKeysWith: { _, last in last })
        let newMap = Dictionary(new.results.map { ("\($0.host):\($0.port)", $0) }, uniquingKeysWith: { _, last in last })
        return Set(oldMap.keys).union(newMap.keys).sorted().compactMap { key in
            let before = oldMap[key]; let after = newMap[key]
            if after?.state == .open && before?.state != .open, let after {
                return ScanDifference(host: after.host, port: after.port, change: before == nil ? "Open; not checked in baseline" : "Newly observed open")
            }
            if before?.state == .open && after?.state != .open, let before {
                return ScanDifference(host: before.host, port: before.port, change: after == nil ? "Previously open; not checked in new scan" : "Previously open; now \(after!.state.title.lowercased())")
            }
            return nil
        }
    }
}
