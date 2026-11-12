import XCTest
@testable import NetScope
final class ScanInputTests: XCTestCase {
    func testPortsDeduplicateAndSort() throws { XCTAssertEqual(try ScanInput.ports("443,22,80-82,22"), [22,80,81,82,443]) }
    func testFullRange() throws { XCTAssertEqual(try ScanInput.ports("1-65535").count, 65535) }
    func testInvalidPorts() {
        for value in ["", "0", "65536", "90-80", "80,", "-1", "abc", "1-2-3"] { XCTAssertThrowsError(try ScanInput.ports(value), value) }
    }
    func testTargets() throws { XCTAssertEqual(try ScanInput.hosts("server.local,192.168.1.1 server.local"), ["192.168.1.1", "server.local"]) }
    func testIPv6() throws { XCTAssertEqual(try ScanInput.hosts("fe80::1%en0"), ["fe80::1%en0"]) }
    func testRejectURLAndOversizedCIDR() {
        for value in ["https://example.com", "192.168.1.0/19", "host:443", ""] { XCTAssertThrowsError(try ScanInput.hosts(value)) }
    }
    func testRecordRoundTrip() throws {
        let record = ScanRecord(startedAt: Date(), hosts: ["example.local"], ports: [443], results: [], cancelled: false)
        let decoded = try JSONDecoder().decode(ScanRecord.self, from: JSONEncoder().encode(record))
        XCTAssertEqual(decoded.id, record.id)
        XCTAssertEqual(decoded.plannedCount, 1)
    }
}
