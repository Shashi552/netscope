import SwiftUI

@MainActor final class ScanStore: ObservableObject {
    @Published var records: [ScanRecord] = []
    @Published var current: ScanRecord?
    @Published var running = false
    @Published var storageError: String?
    private var task: Task<Void, Never>?
    private var canWrite = true
    private let file: URL
    private let checkpoint: URL
    init() {
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        file = directory.appendingPathComponent("scans.json")
        checkpoint = directory.appendingPathComponent("checkpoint.json")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            var folder = directory; var flags = URLResourceValues(); flags.isExcludedFromBackup = true; try folder.setResourceValues(flags)
            if FileManager.default.fileExists(atPath: file.path) {
                let data = try Data(contentsOf:file)
                guard data.count <= 128*1024*1024 else { throw InputError.invalid("Stored history exceeds 128 MiB; recover data before continuing.") }
                records = try JSONDecoder().decode([ScanRecord].self, from:data)
            }
            if FileManager.default.fileExists(atPath: checkpoint.path) {
                var interrupted = try JSONDecoder().decode(ScanRecord.self, from: Data(contentsOf: checkpoint))
                interrupted.cancelled = true; interrupted.finishedAt = Date(); interrupted.stopReason = "Recovered after interruption; coverage is partial"
                current = interrupted
                if !records.contains(where: { $0.id == interrupted.id }) { records.insert(interrupted, at: 0); save() }
                try? FileManager.default.removeItem(at: checkpoint)
            }
        } catch { canWrite = false; storageError = "History could not be loaded (writes disabled to preserve original): \(error.localizedDescription)" }
    }
    func start(hosts: [String], ports: [UInt16], concurrency: Int, timeout: Double, retries: Int = 0, rate: Int = 30) {
        guard !running, canWrite else { return }
        current = ScanRecord(startedAt: Date(), hosts: hosts, ports: ports, results: [], cancelled: false,
                             settings: ScanSettings(concurrency: concurrency, timeout: timeout, retries: retries, attemptsPerSecond: rate))
        execute()
    }
    func resume(_ record: ScanRecord) {
        guard !running, canWrite else { return }
        current = record; current?.finishedAt = nil; current?.cancelled = false; current?.stopReason = nil
        execute()
    }
    private func execute() {
        guard let initial = current else { return }
        running = true; writeCheckpoint()
        let settings = initial.settings ?? ScanSettings()
        let completed = Set(initial.results.map { "\($0.host):\($0.port)" })
        task = Task {
            await TCPScanner().scan(hosts: initial.hosts, ports: initial.ports, concurrency: settings.concurrency, timeout: settings.timeout, retries: settings.retries, rate: settings.attemptsPerSecond, completed: completed) { [weak self] result in
                guard let self else { return }
                self.current?.results.append(result)
                if (self.current?.results.count ?? 0) % 512 == 0 { self.writeCheckpoint() }
            }
            current?.finishedAt = Date(); current?.cancelled = Task.isCancelled
            if let current {
                records.removeAll { $0.id == current.id }; records.insert(current, at: 0); save()
                try? FileManager.default.removeItem(at: checkpoint)
            }
            running = false; task = nil
        }
    }
    func cancel(reason: String = "Stopped by user") { current?.stopReason = reason; task?.cancel() }
    func delete(at offsets: IndexSet) { records.remove(atOffsets: offsets); save() }
    func clear() { canWrite = true; records.removeAll(); current = nil; save(); try? FileManager.default.removeItem(at: checkpoint) }
    func importRecord(_ data: Data) throws {
        guard data.count <= 64*1024*1024 else { throw InputError.invalid("Scan import exceeds 64 MiB.") }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let record = try decoder.decode(ScanRecord.self, from: data)
        guard !record.hosts.isEmpty, record.hosts.count <= 4096, !record.ports.isEmpty, record.ports.count <= 65535,
              record.hosts.count <= 262144 / record.ports.count, record.results.count <= 262144,
              Set(record.hosts).count == record.hosts.count, Set(record.ports).count == record.ports.count,
              record.hosts.allSatisfy(ScopeParser.validHost), record.ports.allSatisfy({ $0 > 0 }) else { throw InputError.invalid("Invalid imported scan scope.") }
        if let settings = record.settings {
            guard (1...64).contains(settings.concurrency), settings.timeout.isFinite, (0.5...10).contains(settings.timeout),
                  (0...2).contains(settings.retries), (1...100).contains(settings.attemptsPerSecond) else { throw InputError.invalid("Invalid imported scan settings.") }
        }
        let hosts = Set(record.hosts); let ports = Set(record.ports)
        let keys = record.results.map { "\($0.host):\($0.port)" }
        guard Set(keys).count == keys.count, record.results.allSatisfy({ hosts.contains($0.host) && ports.contains($0.port) && $0.duration.isFinite && $0.duration >= 0 }) else { throw InputError.invalid("Invalid imported observations.") }
        records.removeAll { $0.id == record.id }; records.insert(record, at: 0); save()
    }
    private func writeCheckpoint() {
        guard let current else { return }
        do { try JSONEncoder().encode(current).write(to: checkpoint, options: [.atomic, .completeFileProtection]) }
        catch { storageError = "Checkpoint failed: \(error.localizedDescription)" }
    }
    private func save() {
        guard canWrite else { return }
        var retained: [ScanRecord] = []; var observations = 0
        for record in records.prefix(20) {
            if observations + record.results.count > 262144 && !retained.isEmpty { break }
            retained.append(record); observations += record.results.count
        }
        records = retained
        do { try JSONEncoder().encode(records).write(to: file, options: [.atomic, .completeFileProtection]) }
        catch { storageError = "History could not be saved: \(error.localizedDescription)" }
    }
}
enum ScanExport {
    static func json(_ record: ScanRecord) throws -> URL {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try ExportFiles.write(encoder.encode(record), name: "NetScope-\(record.id).json")
    }
    static func csv(_ record: ScanRecord) throws -> URL {
        func cell(_ text: String) -> String {
            // Prevent spreadsheet formula interpretation for exported untrusted fields.
            let safe = ["=", "+", "-", "@", "\t", "\r"].contains(where: { text.hasPrefix($0) }) ? "'" + text : text
            return "\"" + safe.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        var lines = ["host,port,state,connection_seconds,port_based_hint,evidence"]
        lines += record.results.map { [cell($0.host), String($0.port), cell($0.state.title), String(format: "%.4f", $0.duration), cell($0.serviceHint), cell($0.detail)].joined(separator: ",") }
        return try ExportFiles.write(Data(lines.joined(separator: "\r\n").utf8), name: "NetScope-\(record.id).csv")
    }
}
