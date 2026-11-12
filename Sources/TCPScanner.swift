import Foundation
import Network

// A fresh connection per attempt; no raw sockets and no protocol payloads.
private final class TCPProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var finished = false
    private var continuation: CheckedContinuation<PortResult, Never>?
    private var connection: NWConnection?
    private var timer: DispatchWorkItem?
    private let host: String
    private let port: UInt16
    private let started = Date()
    private let queue = DispatchQueue.global(qos: .utility)
    init(host: String, port: UInt16) { self.host = host; self.port = port }
    func run(timeout: Double) async -> PortResult {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                lock.lock()
                if finished {
                    lock.unlock()
                    continuation.resume(returning: result(.error, "Cancelled"))
                    return
                }
                guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
                    lock.unlock()
                    continuation.resume(returning: result(.error, "Invalid port 0"))
                    return
                }
                self.continuation = continuation
                let parameters = NWParameters.tcp
                parameters.includePeerToPeer = false
                let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: parameters)
                self.connection = connection
                let timer = DispatchWorkItem { [weak self] in self?.finish(.timedOut, "No connection established within the configured timeout; not proof of a closed port.") }
                self.timer = timer
                connection.stateUpdateHandler = { [weak self] state in
                    guard let self else { return }
                    switch state {
                    case .ready: self.finish(.open, "TCP connection established. Service name is a port-based hint, not protocol verification.")
                    case .failed(let error): self.finish(Self.classify(error), error.localizedDescription)
                    case .waiting(let error):
                        // Waiting is not a definitive permission-denied signal. Preserve timeout semantics.
                        if case .posix(let code) = error, code == .EACCES || code == .EPERM {
                            self.finish(.error, "Access blocked: \(error.localizedDescription). Review Local Network permission and network policy.")
                        }
                    case .cancelled: self.finish(.error, "Connection cancelled")
                    default: break
                    }
                }
                // Start while holding the lock so cancellation cannot race ahead of start.
                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + timeout, execute: timer)
                lock.unlock()
            }
        } onCancel: { self.finish(.error, "Cancelled") }
    }
    private func result(_ state: PortState, _ detail: String) -> PortResult {
        PortResult(host: host, port: port, state: state, duration: Date().timeIntervalSince(started), detail: detail)
    }
    private func finish(_ state: PortState, _ detail: String) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let continuation = self.continuation
        self.continuation = nil
        let connection = self.connection
        self.connection = nil
        let timer = self.timer
        self.timer = nil
        lock.unlock()
        timer?.cancel()
        connection?.stateUpdateHandler = nil
        connection?.cancel()
        continuation?.resume(returning: result(state, detail))
    }
    private static func classify(_ error: NWError) -> PortState {
        guard case .posix(let code) = error else { return .error }
        switch code {
        case .ECONNREFUSED: return .refused
        case .ETIMEDOUT: return .timedOut
        case .ENETUNREACH, .EHOSTUNREACH, .ENETDOWN: return .unreachable
        default: return .error
        }
    }
}
private actor AttemptLimiter {
    private var next = Date.distantPast
    func wait(rate: Int) async throws {
        let now = Date()
        let reserved = max(now, next)
        next = reserved.addingTimeInterval(1 / Double(max(1, rate)))
        let delay = reserved.timeIntervalSince(now)
        if delay > 0 { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
        try Task.checkCancellation()
    }
}
struct TCPScanner {
    func scan(hosts: [String], ports: [UInt16], concurrency: Int, timeout: Double, retries: Int = 0, rate: Int = 30, completed: Set<String> = [],
              onResult: @escaping @MainActor (PortResult) -> Void) async {
        let total = hosts.count * ports.count
        guard total > 0 else { return }
        let limiter = AttemptLimiter()
        await withTaskGroup(of: PortResult.self) { group in
            var next = 0
            func nextIndex() -> Int? {
                while next < total {
                    let value = next; next += 1
                    if !completed.contains("\(hosts[value / ports.count]):\(ports[value % ports.count])") { return value }
                }
                return nil
            }
            func enqueue(_ index: Int) {
                let host = hosts[index / ports.count]
                let port = ports[index % ports.count]
                group.addTask {
                    var result = PortResult(host: host, port: port, state: .error, duration: 0, detail: "Cancelled before connection")
                    for attempt in 0...max(0, min(retries, 2)) {
                        do { try await limiter.wait(rate: rate) } catch { return result }
                        result = await TCPProbe(host: host, port: port).run(timeout: timeout)
                        if Task.isCancelled || result.state == .open || result.state == .refused { break }
                        if attempt < retries { try? await Task.sleep(nanoseconds: 200_000_000) }
                    }
                    return result
                }
            }
            for _ in 0..<min(max(concurrency, 1), total) { if let index = nextIndex() { enqueue(index) } }
            while let result = await group.next() {
                if Task.isCancelled { group.cancelAll(); break }
                await onResult(result)
                if let index = nextIndex() { enqueue(index) }
            }
        }
    }
}
