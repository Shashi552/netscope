import Foundation

public struct WebSocketObservation: Codable, Identifiable {
    public var id: String { url }
    public let url: String
    public let handshakeSuccessful: Bool
    public let subprotocol: String?
    public let roundTripMilliseconds: Double?
    public let error: String?

    public init(
        url: String,
        handshakeSuccessful: Bool,
        subprotocol: String? = nil,
        roundTripMilliseconds: Double? = nil,
        error: String? = nil
    ) {
        self.url = url
        self.handshakeSuccessful = handshakeSuccessful
        self.subprotocol = subprotocol
        self.roundTripMilliseconds = roundTripMilliseconds
        self.error = error
    }
}

final class WebSocketProbeRunner: NSObject, URLSessionWebSocketDelegate {
    private let lock = NSLock()
    private var didResume = false
    private var pingStart: Date?
    private var continuation: CheckedContinuation<WebSocketObservation, Never>?
    private var session: URLSession?
    private var task: URLSessionWebSocketTask?
    private let targetURL: String

    init(targetURL: String) {
        self.targetURL = targetURL
    }

    func start(url: URL, protocols: [String], origin: String?, timeout: TimeInterval) async -> WebSocketObservation {
        await withCheckedContinuation { cont in
            self.lock.lock()
            self.continuation = cont
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = timeout
            config.timeoutIntervalForResource = timeout
            let sess = URLSession(configuration: config, delegate: self, delegateQueue: nil)
            self.session = sess

            var req = URLRequest(url: url, timeoutInterval: timeout)
            if let origin = origin, !origin.isEmpty {
                req.setValue(origin, forHTTPHeaderField: "Origin")
            }
            if !protocols.isEmpty {
                req.setValue(protocols.joined(separator: ", "), forHTTPHeaderField: "Sec-WebSocket-Protocol")
            }

            let wsTask = sess.webSocketTask(with: req)
            self.task = wsTask
            self.lock.unlock()
            wsTask.resume()
        }
    }

    func cancel() {
        lock.lock()
        defer { lock.unlock() }
        task?.cancel(with: .goingAway, reason: nil)
        session?.invalidateAndCancel()
        finish(with: WebSocketObservation(
            url: targetURL,
            handshakeSuccessful: false,
            subprotocol: nil,
            roundTripMilliseconds: nil,
            error: "Inspection cancelled."
        ))
    }

    private func finish(with observation: WebSocketObservation) {
        guard !didResume, let cont = continuation else { return }
        didResume = true
        continuation = nil
        session?.finishTasksAndInvalidate()
        cont.resume(returning: observation)
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        lock.lock()
        guard !didResume else { lock.unlock(); return }
        pingStart = Date()
        webSocketTask.sendPing { [weak self] error in
            guard let self = self else { return }
            self.lock.lock()
            defer { self.lock.unlock() }
            let rtt: Double?
            if error == nil, let start = self.pingStart {
                rtt = Date().timeIntervalSince(start) * 1000.0
            } else {
                rtt = nil
            }
            webSocketTask.cancel(with: .normalClosure, reason: nil)
            self.finish(with: WebSocketObservation(
                url: self.targetURL,
                handshakeSuccessful: true,
                subprotocol: `protocol`,
                roundTripMilliseconds: rtt,
                error: error?.localizedDescription
            ))
        }
        lock.unlock()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        defer { lock.unlock() }
        guard !didResume else { return }
        finish(with: WebSocketObservation(
            url: targetURL,
            handshakeSuccessful: false,
            subprotocol: nil,
            roundTripMilliseconds: nil,
            error: error?.localizedDescription ?? "Connection terminated without completing handshake."
        ))
    }
}

public actor WebSocketInspector {
    private var activeRunner: WebSocketProbeRunner?

    public init() {}

    public func inspect(
        url: URL,
        protocols: [String] = [],
        origin: String? = nil,
        timeout: TimeInterval = 10.0
    ) async -> WebSocketObservation {
        guard let scheme = url.scheme?.lowercased(), ["ws", "wss"].contains(scheme) else {
            return WebSocketObservation(
                url: url.absoluteString,
                handshakeSuccessful: false,
                subprotocol: nil,
                roundTripMilliseconds: nil,
                error: "WebSocket URL must use ws:// or wss:// scheme."
            )
        }
        let runner = WebSocketProbeRunner(targetURL: url.absoluteString)
        self.activeRunner = runner

        let result = await runner.start(url: url, protocols: protocols, origin: origin, timeout: timeout)

        self.activeRunner = nil
        return result
    }

    public func cancel() {
        activeRunner?.cancel()
        activeRunner = nil
    }
}
