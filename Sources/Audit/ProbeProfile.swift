import Foundation

// Non-executable request/response model; intentionally no scripting, shell or
// downloaded code. User must confirm scope and payload before sending.
struct ProbeProfile: Codable, Identifiable {
    var id = UUID()
    var name = "Custom protocol probe"
    var host = ""
    var port: UInt16 = 80
    var hexInput = false
    var request = ""
    var match = ""
    func payload() throws -> Data {
        if !hexInput {
            let data = Data(request.utf8)
            guard data.count <= 4096 else { throw InputError.invalid("Probe payload exceeds 4 KiB.") }; return data
        }
        let text = request.filter { !$0.isWhitespace }
        guard text.count <= 8192, text.count % 2 == 0 else { throw InputError.invalid("Hex must have an even number of digits, at most 8192.") }
        var bytes: [UInt8] = []; var p = text.startIndex
        while p < text.endIndex {
            let end = text.index(p,offsetBy:2)
            guard let byte = UInt8(text[p..<end],radix:16) else { throw InputError.invalid("Invalid hex digit.") }
            bytes.append(byte); p = end
        }
        return Data(bytes)
    }
}
