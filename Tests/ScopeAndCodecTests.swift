import XCTest
@testable import NetScope
final class ScopeAndCodecTests: XCTestCase {
    func testSubnetExpansion() throws {
        XCTAssertEqual(try ScopeParser.expand("192.168.1.0/30"), ["192.168.1.1","192.168.1.2"])
        XCTAssertEqual(try ScopeParser.expand("10.0.0.1/32"), ["10.0.0.1"])
        XCTAssertEqual(try ScopeParser.expand("10.0.0.0/31").count,2)
    }
    func testRangeAndDeduplication() throws {
        XCTAssertEqual(try ScopeParser.expand("10.0.0.1-10.0.0.3,10.0.0.2").count,3)
    }
    func testRejectMalformedScope() {
        for input in ["10.0.0.0/19","999.1.1.1","01.2.3.4","https://host","host:443","bad..host","-host","::gg","10.0.0.3-10.0.0.1"] { XCTAssertThrowsError(try ScopeParser.expand(input),input) }
    }
    func testDNSQuery() throws {
        let query = try DNSCodec.query(name:"example.com",type:1,id:0x1234)
        XCTAssertEqual(Array(query.prefix(4)),[0x12,0x34,0x01,0x00])
        XCTAssertEqual(query.count,29)
    }
    func testDNSCompressedAnswer() throws {
        var data = try DNSCodec.query(name:"example.com",type:1,id:0x1234)
        data[2] = 0x81; data[3] = 0x80; data[7] = 1
        data.append(contentsOf:[0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x04,192,0,2,1])
        let result = try DNSCodec.parse(data,expectedID:0x1234,expectedName:"example.com",expectedType:1)
        XCTAssertEqual(result.2.first?.value,"192.0.2.1")
        XCTAssertEqual(result.2.first?.ttl,60)
        XCTAssertThrowsError(try DNSCodec.parse(data,expectedID:2))
        XCTAssertThrowsError(try DNSCodec.parse(data,expectedID:0x1234,expectedName:"different.test"))
    }
    func testMalformedDNSDoesNotParse() {
        for count in 0..<12 { XCTAssertThrowsError(try DNSCodec.parse(Data(repeating:0,count:count),expectedID:0)) }
        let loop = Data([0,1,0x80,0,0,1,0,0,0,0,0,0,0xc0,0x0c,0,1,0,1])
        XCTAssertThrowsError(try DNSCodec.parse(loop,expectedID:1))
    }
    func testHexProbe() throws {
        var profile = ProbeProfile(); profile.hexInput = true; profile.request = "48 65 6c 6c 6f"
        XCTAssertEqual(try profile.payload(),Data("Hello".utf8))
        profile.request = "a"; XCTAssertThrowsError(try profile.payload())
    }
    func testCertificateMalformedData() { let dates = CertificateDates.read(Data([0x30,0x82,0xff,0xff])); XCTAssertNil(dates.0); XCTAssertNil(dates.1) }
}
