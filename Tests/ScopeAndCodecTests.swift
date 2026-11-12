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
    func testDNSSOADecoding() throws {
        var soaData = try DNSCodec.query(name:"example.com",type:6,id:0x5678)
        soaData[2] = 0x81; soaData[3] = 0x80; soaData[7] = 1
        soaData.append(contentsOf: [
            0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 39,
            0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c,
            0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x0c,
            0x78, 0x94, 0xaf, 0x35,
            0x00, 0x00, 0x1c, 0x20,
            0x00, 0x00, 0x0e, 0x10,
            0x00, 0x12, 0x75, 0x00,
            0x00, 0x00, 0x01, 0x2c
        ])
        let soaResult = try DNSCodec.parse(soaData, expectedID: 0x5678, expectedName: "example.com", expectedType: 6)
        XCTAssertEqual(soaResult.2.count, 1)
        XCTAssertTrue(soaResult.2.first?.value.contains("ns1.example.com") ?? false)
        XCTAssertTrue(soaResult.2.first?.value.contains("serial=2023010101") ?? false)
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
    func testWebSocketObservationCodable() throws {
        let obs = WebSocketObservation(url: "wss://echo.example.com", handshakeSuccessful: true, subprotocol: "chat", roundTripMilliseconds: 15.2, error: nil)
        let encoded = try JSONEncoder().encode(obs)
        let decoded = try JSONDecoder().decode(WebSocketObservation.self, from: encoded)
        XCTAssertEqual(decoded.url, "wss://echo.example.com")
        XCTAssertTrue(decoded.handshakeSuccessful)
        XCTAssertEqual(decoded.subprotocol, "chat")
        XCTAssertEqual(decoded.roundTripMilliseconds, 15.2)
        XCTAssertNil(decoded.error)
    }
    func testWebSocketBadScheme() async {
        let inspector = WebSocketInspector()
        let obs = await inspector.inspect(url: URL(string: "http://example.com")!)
        XCTAssertFalse(obs.handshakeSuccessful)
        XCTAssertTrue(obs.error?.contains("ws:// or wss://") ?? false)
    }
}
