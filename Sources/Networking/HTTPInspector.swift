import Foundation
import Security
import CryptoKit

struct CertificateObservation: Codable, Identifiable {
    var id: String { sha256 }
    let subject: String
    let issuer: String
    let sha256: String
    let spkiSHA256: String?
    let san: [String]
    let derBase64: String
    let publicKeyType: String
    let publicKeyBits: Int
    let notBefore: Date?
    let notAfter: Date?
    let trustStatus: String

    enum CodingKeys: String, CodingKey {
        case subject, issuer, sha256, spkiSHA256, san, derBase64, publicKeyType, publicKeyBits, notBefore, notAfter, trustStatus
    }

    init(subject: String, issuer: String = "Evaluated chain", sha256: String, spkiSHA256: String? = nil, san: [String] = [], derBase64: String, publicKeyType: String, publicKeyBits: Int, notBefore: Date?, notAfter: Date?, trustStatus: String) {
        self.subject = subject
        self.issuer = issuer
        self.sha256 = sha256
        self.spkiSHA256 = spkiSHA256
        self.san = san
        self.derBase64 = derBase64
        self.publicKeyType = publicKeyType
        self.publicKeyBits = publicKeyBits
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.trustStatus = trustStatus
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        subject = try container.decode(String.self, forKey: .subject)
        issuer = try container.decodeIfPresent(String.self, forKey: .issuer) ?? "Evaluated chain"
        sha256 = try container.decode(String.self, forKey: .sha256)
        spkiSHA256 = try container.decodeIfPresent(String.self, forKey: .spkiSHA256)
        san = try container.decodeIfPresent([String].self, forKey: .san) ?? []
        derBase64 = try container.decode(String.self, forKey: .derBase64)
        publicKeyType = try container.decode(String.self, forKey: .publicKeyType)
        publicKeyBits = try container.decode(Int.self, forKey: .publicKeyBits)
        notBefore = try container.decodeIfPresent(Date.self, forKey: .notBefore)
        notAfter = try container.decodeIfPresent(Date.self, forKey: .notAfter)
        trustStatus = try container.decode(String.self, forKey: .trustStatus)
    }
}
// Minimal bounded DER reader used only to extract the X.509 validity sequence.
// Trust and hostname checks remain the responsibility of Apple's Security framework.
enum CertificateDates {
    static func read(_ data: Data) -> (Date?, Date?) {
        let bytes = [UInt8](data)
        func node(_ position: inout Int, limit: Int) -> (UInt8, Range<Int>)? {
            guard position + 2 <= limit, limit <= bytes.count else { return nil }
            let tag = bytes[position]; position += 1
            var length = Int(bytes[position]); position += 1
            if length & 128 != 0 {
                let count = length & 127
                guard count > 0, count <= 4, position+count <= limit else { return nil }
                length = 0
                for _ in 0..<count { length = length * 256 + Int(bytes[position]); position += 1 }
            }
            guard length <= limit-position else { return nil }
            let range = position..<(position+length); position += length
            return (tag, range)
        }
        func date(_ node: (UInt8, Range<Int>)) -> Date? {
            guard node.0 == 0x17 || node.0 == 0x18 else { return nil }
            let text = String(decoding: bytes[node.1], as: UTF8.self)
            let format = DateFormatter(); format.locale = Locale(identifier: "en_US_POSIX"); format.timeZone = TimeZone(secondsFromGMT: 0); format.isLenient = false
            format.dateFormat = node.0 == 0x17 ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'"
            if node.0 == 0x17 {
                // RFC 5280: years 50–99 are 1950–1999, 00–49 are 2000–2049.
                var calendar = Calendar(identifier: .gregorian); calendar.timeZone = TimeZone(secondsFromGMT: 0)!
                format.twoDigitStartDate = calendar.date(from: DateComponents(year: 1950, month: 1, day: 1))
            }
            return format.date(from: text)
        }
        var p = 0
        guard let root = node(&p, limit: bytes.count), root.0 == 0x30 else { return (nil,nil) }
        p = root.1.lowerBound
        guard let tbs = node(&p, limit: root.1.upperBound), tbs.0 == 0x30 else { return (nil,nil) }
        p = tbs.1.lowerBound
        if p < tbs.1.upperBound && bytes[p] == 0xa0 { guard node(&p, limit: tbs.1.upperBound) != nil else { return (nil,nil) } }
        for _ in 0..<3 { guard node(&p, limit: tbs.1.upperBound) != nil else { return (nil,nil) } }
        guard let validity = node(&p, limit: tbs.1.upperBound), validity.0 == 0x30 else { return (nil,nil) }
        p = validity.1.lowerBound
        guard let first = node(&p, limit: validity.1.upperBound), let second = node(&p, limit: validity.1.upperBound) else { return (nil,nil) }
        return (date(first), date(second))
    }
}
enum CertificateSANs {
    static func extract(from data: Data) -> [String] {
        let bytes = [UInt8](data)
        var sans: [String] = []
        guard bytes.count > 10 else { return [] }
        for i in 0..<(bytes.count - 3) {
            if bytes[i] == 0x55 && bytes[i+1] == 0x1d && bytes[i+2] == 0x11 {
                var j = i + 3
                let limit = min(bytes.count, j + 1024)
                while j + 2 < limit {
                    if bytes[j] == 0x82 {
                        let len = Int(bytes[j+1])
                        if len > 0 && len < 256 && j + 2 + len <= limit {
                            let dnsBytes = bytes[(j+2)..<(j+2+len)]
                            if let name = String(bytes: dnsBytes, encoding: .ascii),
                               name.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "*" }) {
                                let label = "DNS: \(name)"
                                if !sans.contains(label) { sans.append(label) }
                                j += 2 + len
                                continue
                            }
                        }
                    }
                    j += 1
                }
                break
            }
        }
        return sans
    }
}
struct HTTPObservation: Codable, Identifiable {
    var id = UUID()
    let date: Date
    let url: String
    let method: String
    let status: Int
    let headers: [String:String]
    let bodyPreview: String
    let bodySHA256: String
    let bytesCaptured: Int
    let truncated: Bool
    let elapsed: Double
    let negotiatedProtocol: String?
    let tlsVersion: UInt16?
    let cipherSuite: UInt16?
    let certificates: [CertificateObservation]
    let error: String?
    var title: String? {
        guard let range = bodyPreview.range(of: "(?is)<title[^>]*>(.*?)</title>", options: .regularExpression) else { return nil }
        return String(bodyPreview[range]).replacingOccurrences(of: "(?is)</?title[^>]*>", with: "", options: .regularExpression)
    }
    var reviewNotes: [String] {
        var notes: [String] = []
        if url.lowercased().hasPrefix("http:") { notes.append("Cleartext HTTP: requests and responses lack TLS protection.") }
        if status > 0 {
            for header in ["content-security-policy", "x-content-type-options", "referrer-policy"] where headers[header] == nil {
                notes.append("\(header) was not observed. Applicability depends on this endpoint's content and purpose.")
            }
            if url.lowercased().hasPrefix("https:"), headers["strict-transport-security"] == nil { notes.append("HSTS was not observed. Evaluate whether a policy is appropriate for this host.") }
        }
        if let location = headers["location"] { notes.append("Redirect observed: \(location). It was NOT followed; authorize a new request separately.") }
        if headers["access-control-allow-origin"] == "*" { notes.append("Wildcard CORS response observed; not proof of a vulnerability.") }
        if let hsts = headers["strict-transport-security"] {
            let directives = hsts.split(separator:";").map { $0.trimmingCharacters(in:.whitespaces).lowercased() }
            notes.append("HSTS directives: " + directives.joined(separator:"; ") + ". This is returned configuration, not a guarantee of browser protection.")
        }
        if let csp = headers["content-security-policy"] {
            let directives = csp.split(separator:";").map { $0.trimmingCharacters(in:.whitespaces) }.filter { !$0.isEmpty }
            notes.append("CSP contains \(directives.count) directive(s). Policy strength requires application-specific review.")
        }
        if headers["set-cookie"] != nil { notes.append("Set-Cookie values were redacted. Review cookie attributes on the server; this build does not parse combined cookie headers reliably.") }
        return notes
    }
}
final class HTTPInspector: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private var continuation: CheckedContinuation<HTTPObservation, Error>?
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var response: HTTPURLResponse?
    private var body = Data()
    private var certificates: [CertificateObservation] = []
    private var metrics: URLSessionTaskMetrics?
    private var started = Date()
    private var requestURL = ""
    private var method = "GET"
    private var truncated = false
    private let limit = 128 * 1024
    private let lock = NSLock()
    private var done = false
    private var cancelRequested = false
    func inspect(url: URL, method: String = "GET", headers: [String:String] = [:], body: Data? = nil) async throws -> HTTPObservation {
        guard ["http", "https"].contains(url.scheme?.lowercased() ?? ""), let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil, url.fragment == nil else { throw InputError.invalid("Enter an HTTP/HTTPS URL without embedded credentials or a fragment.") }
        guard url.absoluteString.utf8.count <= 8192, headers.count <= 32,
              headers.allSatisfy({ key, value in
                  !key.isEmpty && key.utf8.count <= 128 && value.utf8.count <= 4096 &&
                  key.utf8.allSatisfy({ (33...126).contains($0) && ![UInt8(58),32].contains($0) }) &&
                  !value.contains("\r") && !value.contains("\n")
              }) else { throw InputError.invalid("Request URL/headers exceed limits or contain invalid control characters.") }
        guard ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"].contains(method), (body?.count ?? 0) <= 65536 else { throw InputError.invalid("Unsupported method or request body exceeds 64 KiB.") }
        if headers.keys.contains(where: { ["authorization", "cookie"].contains($0.lowercased()) }), url.scheme?.lowercased() != "https" {
            throw InputError.invalid("Credentials are allowed only over HTTPS.")
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                if cancelRequested { lock.unlock(); continuation.resume(throwing: CancellationError()); return }
                self.continuation = continuation; started = Date(); requestURL = url.absoluteString; self.method = method
                let config = URLSessionConfiguration.ephemeral
                config.timeoutIntervalForRequest = 12; config.timeoutIntervalForResource = 20
                config.httpCookieStorage = nil; config.httpShouldSetCookies = false
                config.urlCredentialStorage = nil; config.urlCache = nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
                let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
                let session = URLSession(configuration: config, delegate: self, delegateQueue: queue)
                self.session = session
                var request = URLRequest(url: url); request.httpMethod = method; request.httpBody = body
                for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
                task = session.dataTask(with: request); task?.resume()
                lock.unlock()
            }
        } onCancel: {
            self.lock.lock(); self.cancelRequested = true; let task = self.task; self.lock.unlock(); task?.cancel()
        }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust, let trust = challenge.protectionSpace.serverTrust else { completionHandler(.performDefaultHandling, nil); return }
        var error: CFError?
        let trusted = SecTrustEvaluateWithError(trust, &error)
        let status = trusted ? "Trusted by iOS for this connection's hostname" : "Trust failed: \(error.map { CFErrorCopyDescription($0) as String } ?? "unknown reason")"
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
            certificates = chain.map { cert in
                let data = SecCertificateCopyData(cert) as Data
                var keyType = "Unknown"; var keyBits = 0
                var spkiSHA256: String? = nil
                if let key = SecCertificateCopyKey(cert) {
                    if let attributes = SecKeyCopyAttributes(key) as? [String:Any] {
                        keyType = String(describing: attributes[kSecAttrKeyType as String] ?? "Unknown")
                        keyBits = attributes[kSecAttrKeySizeInBits as String] as? Int ?? 0
                    }
                    if let keyData = SecKeyCopyExternalRepresentation(key, nil) as Data? {
                        spkiSHA256 = SHA256.hash(data: keyData).map { String(format: "%02x", $0) }.joined()
                    }
                }
                let dates = CertificateDates.read(data)
                let sanList = CertificateSANs.extract(from: data)
                let subject = SecCertificateCopySubjectSummary(cert) as String? ?? "Certificate"
                return CertificateObservation(subject: subject, issuer: "Chain certificate", sha256: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(), spkiSHA256: spkiSHA256, san: sanList, derBase64: data.base64EncodedString(), publicKeyType: keyType, publicKeyBits: keyBits, notBefore: dates.0, notAfter: dates.1, trustStatus: status)
            }
        }
        // Never bypass a failed certificate/hostname check, including for authenticated requests.
        if trusted { completionHandler(.useCredential, URLCredential(trust: trust)) }
        else { completionHandler(.cancelAuthenticationChallenge, nil) }
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        self.response = response as? HTTPURLResponse
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let remaining = max(0, limit - body.count)
        body.append(data.prefix(remaining))
        if data.count > remaining { truncated = true; dataTask.cancel() }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) { self.metrics = metrics }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock(); guard !done else { lock.unlock(); return }; done = true
        let continuation = self.continuation; self.continuation = nil
        let cancelled = cancelRequested
        lock.unlock()
        defer { session.invalidateAndCancel(); self.session = nil; self.task = nil }
        if cancelled { continuation?.resume(throwing: CancellationError()); return }
        var headers: [String:String] = [:]
        for (key,value) in response?.allHeaderFields ?? [:] {
            let name = String(describing: key).lowercased()
            headers[name] = ["set-cookie", "authorization", "proxy-authenticate"].contains(name) ? "[redacted]" : String(describing: value)
        }
        let last = metrics?.transactionMetrics.last
        let observation = HTTPObservation(date: started, url: requestURL, method: method, status: response?.statusCode ?? 0, headers: headers, bodyPreview: String(decoding: body.prefix(32768), as: UTF8.self), bodySHA256: SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined(), bytesCaptured: body.count, truncated: truncated, elapsed: Date().timeIntervalSince(started), negotiatedProtocol: last?.networkProtocolName, tlsVersion: last?.negotiatedTLSProtocolVersion.map { UInt16($0.rawValue) }, cipherSuite: last?.negotiatedTLSCipherSuite.map { UInt16($0.rawValue) }, certificates: certificates, error: truncated ? "Body capture stopped at 128 KiB; hash is of captured bytes only." : error?.localizedDescription)
        continuation?.resume(returning: observation)
    }
}
