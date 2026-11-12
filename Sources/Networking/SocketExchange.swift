import Foundation
import Network

// Bounded, one-response transport for banner and DNS diagnostics. Single completion,
// explicit deadline and task cancellation; never sends arbitrary executable code.
final class SocketExchange: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    private var continuation: CheckedContinuation<Data, Error>?
    private var connection: NWConnection?
    private var timer: DispatchWorkItem?
    private let queue = DispatchQueue(label: "app.netscope.exchange.\(UUID())")
    func run(host: String, port: UInt16, payload: Data?, udp: Bool = false, timeout: Double = 5, maxBytes: Int = 8192, tcpDNS: Bool = false) async throws -> Data {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                guard !done else { lock.unlock(); continuation.resume(throwing: CancellationError()); return }
                self.continuation = continuation
                let connection = NWConnection(host: .init(host), port: .init(rawValue: port)!, using: udp ? .udp : .tcp)
                self.connection = connection
                let deadline = DispatchWorkItem { [weak self] in self?.finish(.failure(InputError.invalid("No response before the deadline."))) }
                timer = deadline
                connection.stateUpdateHandler = { [weak self] state in
                    guard let self else { return }
                    switch state {
                    case .ready:
                        if let payload {
                            connection.send(content: payload, completion: .contentProcessed { error in
                                if let error { self.finish(.failure(error)) }
                                else { self.receive(connection, maxBytes: maxBytes, tcpDNS: tcpDNS, buffer: Data()) }
                            })
                        } else { self.receive(connection, maxBytes: maxBytes, tcpDNS: tcpDNS, buffer: Data()) }
                    case .failed(let error): self.finish(.failure(error))
                    default: break
                    }
                }
                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + timeout, execute: deadline)
                lock.unlock()
            }
        } onCancel: { self.finish(.failure(CancellationError())) }
    }
    private func receive(_ connection: NWConnection, maxBytes: Int, tcpDNS: Bool, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: max(1, maxBytes - buffer.count)) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let error { self.finish(.failure(error)); return }
            var all = buffer; if let data { all.append(data) }
            if tcpDNS {
                if all.count >= 2 {
                    let count = Int(all[0]) * 256 + Int(all[1])
                    guard count + 2 <= maxBytes else { self.finish(.failure(InputError.invalid("DNS response exceeds limit."))); return }
                    if all.count >= count + 2 { self.finish(.success(Data(all.dropFirst(2).prefix(count)))); return }
                }
                if complete || all.count >= maxBytes { self.finish(.failure(InputError.invalid("Incomplete DNS-over-TCP response."))); return }
                self.receive(connection, maxBytes: maxBytes, tcpDNS: true, buffer: all)
            } else {
                if all.isEmpty { self.finish(.failure(InputError.invalid("Peer closed without a response."))) }
                else { self.finish(.success(all)) }
            }
        }
    }
    private func finish(_ result: Result<Data, Error>) {
        lock.lock(); guard !done else { lock.unlock(); return }; done = true
        let continuation = self.continuation; self.continuation = nil
        let connection = self.connection; self.connection = nil
        let timer = self.timer; self.timer = nil
        lock.unlock()
        timer?.cancel(); connection?.cancel(); continuation?.resume(with: result)
    }
}
