import UIKit
import CryptoKit

@MainActor enum ReportBuilder {
    static func pdf(record: ScanRecord, organization: String, redact: Bool) throws -> URL {
        let page = CGRect(x: 0, y: 0, width: 595, height: 842)
        let renderer = UIGraphicsPDFRenderer(bounds: page)
        let hostMap = Dictionary(uniqueKeysWithValues: record.hosts.enumerated().map { ($1, "Target \($0+1)") })
        let bodyFont = UIFont.monospacedSystemFont(ofSize: 10, weight: .regular)
        let paragraph = NSMutableParagraphStyle(); paragraph.lineBreakMode = .byCharWrapping
        let attributes: [NSAttributedString.Key:Any] = [.font:bodyFont,.foregroundColor:UIColor.black,.paragraphStyle:paragraph]
        var lines = ["NETSCOPE / NETWORK ASSESSMENT", organization, "Generated: \(Date().ISO8601Format())", "Scan: \(record.startedAt.ISO8601Format())", "Check version: TCP-connect / 0.2", "Coverage: \(record.results.count) of \(record.plannedCount) host-port checks", "Observed open: \(record.openCount)", "Status: \(record.cancelled ? "Partial / interrupted" : "Completed")", "", "METHODOLOGY & LIMITATIONS", "TCP connection attempts from an iPhone. Port names are hints, not verified services. No response does not prove absence, closure, or security. No exploitation or compliance certification is performed.", "", "OBSERVATIONS (first 5,000 results maximum; JSON/CSV contain all outcomes)"]
        for result in record.results.sorted(by: { $0.host == $1.host ? $0.port < $1.port : $0.host < $1.host }).prefix(5000) {
            let host = redact ? hostMap[result.host] ?? "Target" : result.host
            lines.append("\(host):\(result.port) | \(result.state.title) | \(String(format: "%.3fs", result.duration)) | \(result.serviceHint) (hint)")
            if result.state == .open { lines.append("Evidence: TCP connection established.") }
        }
        let data = renderer.pdfData { context in
            var y: CGFloat = 0
            func newPage() {
                context.beginPage(); y = 40
                ("NetScope · always free · \(redact ? "redacted identifiers" : "sensitive network identifiers")" as NSString).draw(at: CGPoint(x: 36,y: 810), withAttributes: [.font:UIFont.systemFont(ofSize: 8),.foregroundColor:UIColor.darkGray])
            }
            newPage()
            for line in lines {
                // Chunk extremely long labels so a single paragraph never overruns a page.
                let chunks = stride(from: 0, to: max(line.count,1), by: 180).map { offset -> String in
                    let start = line.index(line.startIndex, offsetBy: min(offset,line.count))
                    let end = line.index(start, offsetBy: min(180,line.distance(from:start,to:line.endIndex)))
                    return String(line[start..<end])
                }
                for chunk in chunks {
                    let text = chunk as NSString
                    let height = max(14, ceil(text.boundingRect(with: CGSize(width:523,height:1000), options:[.usesLineFragmentOrigin,.usesFontLeading], attributes:attributes,context:nil).height)+5)
                    if y+height > 790 { newPage() }
                    text.draw(in:CGRect(x:36,y:y,width:523,height:height),withAttributes:attributes); y += height
                }
            }
        }
        return try ExportFiles.write(data, name: "Assessment-\(UUID()).pdf")
    }
    static func manifest(for file: URL) throws -> URL {
        let data = try Data(contentsOf:file)
        let digest = SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined()
        return try ExportFiles.write(Data("SHA256 (\(file.lastPathComponent)) = \(digest)\nHash detects byte changes; it does not prove origin or collection time.\n".utf8),name:"Manifest-\(UUID()).txt")
    }
}
