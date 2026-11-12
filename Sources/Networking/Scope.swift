import Foundation
import Darwin

struct InterfaceAddress: Identifiable {
    var id: String { name + address }
    let name: String
    let address: String
    let netmask: String
}
enum LocalInterfaces {
    static func all() -> [InterfaceAddress] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return [] }
        defer { freeifaddrs(head) }
        var output: [InterfaceAddress] = []
        var cursor = head
        while let item = cursor {
            defer { cursor = item.pointee.ifa_next }
            guard let address = item.pointee.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET) || address.pointee.sa_family == UInt8(AF_INET6) else { continue }
            func numeric(_ pointer: UnsafePointer<sockaddr>?) -> String {
                guard let pointer else { return "" }
                var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let capacity = socklen_t(buffer.count)
                guard getnameinfo(pointer, socklen_t(pointer.pointee.sa_len), &buffer, capacity, nil, 0, NI_NUMERICHOST) == 0 else { return "" }
                return String(cString: buffer)
            }
            output.append(InterfaceAddress(name: String(cString: item.pointee.ifa_name), address: numeric(address), netmask: numeric(item.pointee.ifa_netmask)))
        }
        return output.sorted { $0.name < $1.name }
    }
}
enum ScopeParser {
    static func ipv4(_ value: String) -> UInt32? {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let byte = UInt8(part), !(part.count > 1 && part.first == "0") else { return nil }
            result = (result << 8) | UInt32(byte)
        }
        return result
    }
    static func text(_ ip: UInt32) -> String { "\((ip >> 24) & 255).\((ip >> 16) & 255).\((ip >> 8) & 255).\(ip & 255)" }
    static func expand(_ input: String, limit: Int = 4096) throws -> [String] {
        let entries = input.components(separatedBy: CharacterSet(charactersIn: ",; \n\r\t")).filter { !$0.isEmpty }
        guard !entries.isEmpty else { throw InputError.invalid("Enter a target scope.") }
        var hosts = Set<String>()
        for entry in entries {
            if entry.contains("/") {
                let parts = entry.split(separator: "/", omittingEmptySubsequences: false)
                guard parts.count == 2, let ip = ipv4(String(parts[0])), let prefix = Int(parts[1]), (20...32).contains(prefix) else {
                    throw InputError.invalid("IPv4 CIDR must use a prefix from /20 through /32 (maximum 4096 addresses).")
                }
                let mask = prefix == 32 ? UInt32.max : UInt32.max << (32 - prefix)
                let start = ip & mask
                let count = 1 << (32 - prefix)
                // Exclude subnet and broadcast addresses except for /31 and /32.
                let lower = count > 2 ? 1 : 0
                let upper = count > 2 ? count - 1 : count
                for offset in lower..<upper { hosts.insert(text(start + UInt32(offset))) }
            } else if entry.contains("-"), let firstPart = entry.split(separator: "-").first,
                      ipv4(String(firstPart)) != nil {
                let parts = entry.split(separator: "-", omittingEmptySubsequences: false)
                guard parts.count == 2, let start = ipv4(String(parts[0])), let end = ipv4(String(parts[1])), end >= start,
                      UInt64(end) - UInt64(start) < UInt64(limit) else { throw InputError.invalid("Use a bounded full IPv4 range such as 192.168.1.1-192.168.1.20.") }
                for ip in UInt64(start)...UInt64(end) { hosts.insert(text(UInt32(ip))) }
            } else {
                guard validHost(entry) else { throw InputError.invalid("Invalid target: \(entry). Enter an IP address or DNS hostname without a URL or port.") }
                hosts.insert(entry.lowercased())
            }
            guard hosts.count <= limit else { throw InputError.invalid("Scope exceeds \(limit) hosts.") }
        }
        return hosts.sorted()
    }
    static func validHost(_ value: String) -> Bool {
        if ipv4(value) != nil { return true }
        if value.contains(":") {
            let components = value.split(separator: "%", omittingEmptySubsequences: false)
            guard components.count <= 2 else { return false }
            if components.count == 2 && (components[1].isEmpty || !components[1].allSatisfy({ $0.isLetter || $0.isNumber })) { return false }
            var address = in6_addr()
            return String(components[0]).withCString { inet_pton(AF_INET6, $0, &address) } == 1
        }
        if value.allSatisfy({ $0.isNumber || $0 == "." }) { return false }
        let name = value.hasSuffix(".") ? String(value.dropLast()) : value
        guard !name.isEmpty, name.count <= 253 else { return false }
        return name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.count <= 63 && label.first != "-" && label.last != "-" && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }
    }
}
