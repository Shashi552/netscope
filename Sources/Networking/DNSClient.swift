import Foundation
import Darwin

struct DNSRecord: Identifiable {
    let id = UUID()
    let name: String
    let type: UInt16
    let ttl: UInt32
    let value: String
}
struct DNSResponse {
    let resolver: String
    let milliseconds: Double
    let responseCode: Int
    let truncated: Bool
    let records: [DNSRecord]
}
enum DNSCodec {
    static let types: [(String, UInt16)] = [("A",1),("AAAA",28),("CNAME",5),("MX",15),("NS",2),("TXT",16),("PTR",12),("SRV",33),("SOA",6),("CAA",257)]
    static func query(name: String, type: UInt16, id: UInt16) throws -> Data {
        let normalized = name.hasSuffix(".") ? String(name.dropLast()) : name
        guard !normalized.isEmpty, normalized.utf8.count <= 253 else { throw InputError.invalid("Invalid DNS name.") }
        var output = Data()
        func word(_ n: UInt16) { output.append(UInt8(n >> 8)); output.append(UInt8(n & 255)) }
        word(id); word(0x0100); word(1); word(0); word(0); word(0)
        for label in normalized.split(separator: ".", omittingEmptySubsequences: false) {
            guard !label.isEmpty, label.utf8.count <= 63, label.utf8.allSatisfy({ $0 >= 33 && $0 < 127 }) else { throw InputError.invalid("DNS labels must be 1–63 ASCII bytes. Use punycode for international names.") }
            output.append(UInt8(label.utf8.count)); output.append(contentsOf: label.utf8)
        }
        output.append(0); word(type); word(1)
        return output
    }
    static func parse(_ data: Data, expectedID: UInt16, expectedName: String? = nil, expectedType: UInt16? = nil) throws -> (Int, Bool, [DNSRecord]) {
        let b = [UInt8](data)
        func u16(_ p: Int) throws -> UInt16 {
            guard p >= 0, p + 1 < b.count else { throw InputError.invalid("Truncated DNS data.") }
            return UInt16(b[p]) << 8 | UInt16(b[p+1])
        }
        func name(_ position: inout Int) throws -> String {
            var p = position; var jumped = false; var visited = Set<Int>(); var labels: [String] = []
            while true {
                guard p < b.count, visited.insert(p).inserted, visited.count <= 128 else { throw InputError.invalid("Malformed DNS name compression.") }
                let length = Int(b[p])
                if length == 0 { if !jumped { position = p + 1 }; return labels.joined(separator: ".") }
                if length & 0xc0 == 0xc0 {
                    let pointer = Int(try u16(p) & 0x3fff)
                    if !jumped { position = p + 2; jumped = true }
                    p = pointer; continue
                }
                guard length <= 63, p + 1 + length <= b.count else { throw InputError.invalid("Malformed DNS label.") }
                labels.append(String(decoding: b[(p+1)..<(p+1+length)], as: UTF8.self))
                guard labels.joined(separator: ".").utf8.count <= 253 else { throw InputError.invalid("DNS name too long.") }
                p += length + 1; if !jumped { position = p }
            }
        }
        guard b.count >= 12, try u16(0) == expectedID else { throw InputError.invalid("DNS response transaction mismatch.") }
        let flags = try u16(2)
        guard flags & 0x8000 != 0, flags & 0x7800 == 0 else { throw InputError.invalid("Not a standard DNS response.") }
        let questions = Int(try u16(4)); let answers = Int(try u16(6))
        guard questions == 1, answers <= 2048 else { throw InputError.invalid("Unexpected DNS question/answer count.") }
        var p = 12
        let questionName = try name(&p); let questionType = try u16(p); let questionClass = try u16(p+2); p += 4
        if let expectedName {
            guard questionName.lowercased() == expectedName.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased() else { throw InputError.invalid("DNS question mismatch.") }
        }
        if let expectedType { guard expectedType == questionType else { throw InputError.invalid("DNS type mismatch.") } }
        guard questionClass == 1 else { throw InputError.invalid("Unexpected DNS class.") }
        var output: [DNSRecord] = []
        for _ in 0..<answers {
            let owner = try name(&p)
            let type = try u16(p); let recordClass = try u16(p+2)
            let ttl = UInt32(try u16(p+4)) << 16 | UInt32(try u16(p+6))
            let length = Int(try u16(p+8)); p += 10
            let end = p + length
            guard end <= b.count else { throw InputError.invalid("Truncated DNS record.") }
            var value = Data(b[p..<end]).map { String(format: "%02x", $0) }.joined()
            if type == 1 && length == 4 { value = b[p..<end].map(String.init).joined(separator: ".") }
            else if type == 28 && length == 16 {
                var addr = in6_addr(); withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: b[p..<end]) }
                var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                let capacity = socklen_t(text.count)
                _ = withUnsafePointer(to: &addr) { inet_ntop(AF_INET6, $0, &text, capacity) }
                value = String(cString: text)
            } else if [UInt16(2),5,12].contains(type) {
                var q = p; value = try name(&q); guard q <= end else { throw InputError.invalid("Invalid name record length.") }
            } else if type == 15 && length >= 3 {
                var q = p+2; value = "\(try u16(p)) \(try name(&q))"; guard q <= end else { throw InputError.invalid("Invalid MX record.") }
            } else if type == 33 && length >= 7 {
                var q = p+6; value = "priority=\(try u16(p)) weight=\(try u16(p+2)) port=\(try u16(p+4)) target=\(try name(&q))"
                guard q <= end else { throw InputError.invalid("Invalid SRV record.") }
            } else if type == 16 {
                var q = p; var strings: [String] = []
                while q < end { let n = Int(b[q]); q += 1; guard q+n <= end else { throw InputError.invalid("Malformed TXT record.") }; strings.append(String(decoding: b[q..<(q+n)], as: UTF8.self)); q += n }
                value = strings.joined(separator: " | ")
            } else if type == 257 && length >= 2 {
                let tagLength = Int(b[p+1]); guard p+2+tagLength <= end else { throw InputError.invalid("Malformed CAA record.") }
                value = "flags=\(b[p]) \(String(decoding: b[(p+2)..<(p+2+tagLength)], as: UTF8.self)) \(String(decoding: b[(p+2+tagLength)..<end], as: UTF8.self))"
            }
            if recordClass == 1 { output.append(DNSRecord(name: owner, type: type, ttl: ttl, value: value)) }
            p = end
        }
        return (Int(flags & 15), flags & 0x0200 != 0, output)
    }
}
enum DNSClient {
    static func query(name: String, type: UInt16, resolver: String, tcp: Bool) async throws -> DNSResponse {
        guard ScopeParser.validHost(resolver) else { throw InputError.invalid("Enter a valid resolver address.") }
        let id = UInt16.random(in: 0...65535)
        let request = try DNSCodec.query(name: name, type: type, id: id)
        var payload = Data()
        if tcp { payload.append(UInt8(request.count >> 8)); payload.append(UInt8(request.count & 255)) }
        payload.append(request)
        let started = Date()
        let response = try await SocketExchange().run(host: resolver, port: 53, payload: payload, udp: !tcp, maxBytes: 65537, tcpDNS: tcp)
        let parsed = try DNSCodec.parse(response, expectedID: id, expectedName: name, expectedType: type)
        return DNSResponse(resolver: resolver, milliseconds: Date().timeIntervalSince(started)*1000, responseCode: parsed.0, truncated: parsed.1, records: parsed.2)
    }
}
