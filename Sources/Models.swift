import Foundation

enum PortState: String, Codable, CaseIterable {
    case open, refused, timedOut, unreachable, error
    var title: String {
        switch self {
        case .open: return "Open"
        case .refused: return "Refused"
        case .timedOut: return "No response"
        case .unreachable: return "Unreachable"
        case .error: return "Error"
        }
    }
}
struct PortResult: Identifiable, Codable {
    var id = UUID()
    let host: String
    let port: UInt16
    let state: PortState
    let duration: Double
    let detail: String
    var serviceHint: String {
        [21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",587:"SMTP submission",993:"IMAPS",995:"POP3S",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",6379:"Redis",8080:"HTTP alternate",8443:"HTTPS alternate"][Int(port)] ?? "TCP"
    }
}
struct ScanRecord: Identifiable, Codable {
    var id = UUID()
    let startedAt: Date
    var finishedAt: Date?
    let hosts: [String]
    let ports: [UInt16]
    var results: [PortResult]
    var cancelled: Bool
    var settings: ScanSettings? = nil
    var stopReason: String? = nil
    var openCount: Int { results.filter { $0.state == .open }.count }
    var plannedCount: Int { hosts.count * ports.count }
}
enum InputError: LocalizedError {
    case invalid(String)
    var errorDescription: String? { if case .invalid(let text) = self { return text }; return nil }
}
enum ScanInput {
    static let commonPorts = "21,22,25,53,80,110,139,143,443,445,587,993,995,1433,1883,3306,3389,5432,5900,6379,8000,8080,8443,9100"
    static func ports(_ text: String) throws -> [UInt16] {
        var output = Set<UInt16>()
        for raw in text.split(separator: ",", omittingEmptySubsequences: false) {
            let part = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            let ends = part.split(separator: "-", omittingEmptySubsequences: false)
            guard ends.count == 1 || ends.count == 2,
                  let first = UInt16(ends[0]), first > 0 else {
                throw InputError.invalid("Enter ports from 1 to 65535, such as 22,80,443 or 8000-8100.")
            }
            if ends.count == 2 {
                guard let last = UInt16(ends[1]), last >= first else { throw InputError.invalid("Invalid port range: \(part)") }
                for port in Int(first)...Int(last) { output.insert(UInt16(port)) }
            } else { output.insert(first) }
        }
        guard !output.isEmpty else { throw InputError.invalid("Select at least one port.") }
        return output.sorted()
    }
    static func hosts(_ text: String) throws -> [String] { try ScopeParser.expand(text) }
}
struct ScanSettings: Codable {
    var concurrency: Int = 16
    var timeout: Double = 2
    var retries: Int = 0
    var attemptsPerSecond: Int = 30
}
