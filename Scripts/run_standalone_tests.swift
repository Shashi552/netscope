import Foundation
import Security
import CryptoKit
import CommonCrypto

@main
struct StandaloneTestRunner {
    static var totalTests = 0
    static var passedTests = 0
    static var failedTests = 0

    static func assertEqual<T: Equatable>(_ a: T, _ b: T, _ message: String = "", file: String = #file, line: Int = #line) {
        totalTests += 1
        if a == b {
            passedTests += 1
        } else {
            failedTests += 1
            print("FAIL: \(file):\(line): Expected \(b), got \(a). \(message)")
        }
    }

    static func assertTrue(_ a: Bool, _ message: String = "", file: String = #file, line: Int = #line) {
        totalTests += 1
        if a {
            passedTests += 1
        } else {
            failedTests += 1
            print("FAIL: \(file):\(line): Expected true, got false. \(message)")
        }
    }

    static func assertNil(_ a: Any?, _ message: String = "", file: String = #file, line: Int = #line) {
        totalTests += 1
        if a == nil {
            passedTests += 1
        } else {
            failedTests += 1
            print("FAIL: \(file):\(line): Expected nil, got \(String(describing: a)). \(message)")
        }
    }

    static func assertThrows<T>(_ block: () throws -> T, _ message: String = "", file: String = #file, line: Int = #line) {
        totalTests += 1
        do {
            _ = try block()
            failedTests += 1
            print("FAIL: \(file):\(line): Expected error thrown, but succeeded. \(message)")
        } catch {
            passedTests += 1
        }
    }

    static func main() async throws {
        print("=== Running NetScope Test Suite ===")

        // 1. ScanInputTests
        do {
            print("[RUN] ScanInputTests")
            assertEqual(try ScanInput.ports("443,22,80-82,22"), [22,80,81,82,443])
            assertEqual(try ScanInput.ports("1-65535").count, 65535)
            for value in ["", "0", "65536", "90-80", "80,", "-1", "abc", "1-2-3"] {
                assertThrows({ try ScanInput.ports(value) }, value)
            }
            assertEqual(try ScanInput.hosts("server.local,192.168.1.1 server.local"), ["192.168.1.1", "server.local"])
            assertEqual(try ScanInput.hosts("fe80::1%en0"), ["fe80::1%en0"])
            for value in ["https://example.com", "192.168.1.0/19", "host:443", ""] {
                assertThrows({ try ScanInput.hosts(value) }, value)
            }
            let record = ScanRecord(startedAt: Date(), hosts: ["example.local"], ports: [443], results: [], cancelled: false)
            let decoded = try JSONDecoder().decode(ScanRecord.self, from: JSONEncoder().encode(record))
            assertEqual(decoded.id, record.id)
            assertEqual(decoded.plannedCount, 1)
            assertEqual(decoded.openCount, 0)

            // Test legacy JSON without openCount / resumedAt
            let legacyJSON = """
            {"id":"00000000-0000-0000-0000-000000000001","startedAt":1700000000,"hosts":["192.168.1.1"],"ports":[80,443],"results":[{"id":"00000000-0000-0000-0000-000000000002","host":"192.168.1.1","port":80,"state":"open","duration":0.05,"detail":"connected"},{"id":"00000000-0000-0000-0000-000000000003","host":"192.168.1.1","port":443,"state":"refused","duration":0.02,"detail":"refused"}],"cancelled":false}
            """.data(using: .utf8)!
            let legacyDecoded = try JSONDecoder().decode(ScanRecord.self, from: legacyJSON)
            assertEqual(legacyDecoded.openCount, 1)
            assertEqual(legacyDecoded.resumeCount, 0)
            assertNil(legacyDecoded.resumedAt)
        }

        // 2. ScopeAndCodecTests
        do {
            print("[RUN] ScopeAndCodecTests")
            assertEqual(try ScopeParser.expand("192.168.1.0/30"), ["192.168.1.1","192.168.1.2"])
            assertEqual(try ScopeParser.expand("10.0.0.1/32"), ["10.0.0.1"])
            assertEqual(try ScopeParser.expand("10.0.0.0/31").count, 2)
            assertEqual(try ScopeParser.expand("10.0.0.1-10.0.0.3,10.0.0.2").count, 3)
            for input in ["10.0.0.0/19","999.1.1.1","01.2.3.4","https://host","host:443","bad..host","-host","::gg","10.0.0.3-10.0.0.1"] {
                assertThrows({ try ScopeParser.expand(input) }, input)
            }
            let query = try DNSCodec.query(name:"example.com",type:1,id:0x1234)
            assertEqual(Array(query.prefix(4)),[0x12,0x34,0x01,0x00])
            assertEqual(query.count,29)

            var data = try DNSCodec.query(name:"example.com",type:1,id:0x1234)
            data[2] = 0x81; data[3] = 0x80; data[7] = 1
            data.append(contentsOf:[0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x04,192,0,2,1])
            let result = try DNSCodec.parse(data,expectedID:0x1234,expectedName:"example.com",expectedType:1)
            assertEqual(result.2.first?.value,"192.0.2.1")
            assertEqual(result.2.first?.ttl,60)
            assertThrows({ try DNSCodec.parse(data,expectedID:2) })
            assertThrows({ try DNSCodec.parse(data,expectedID:0x1234,expectedName:"different.test") })

            // Test DNS SOA decoding
            var soaData = try DNSCodec.query(name:"example.com",type:6,id:0x5678)
            soaData[2] = 0x81; soaData[3] = 0x80; soaData[7] = 1
            // Answer: name pointer (0xc0,0x0c), type 6, class 1, ttl 3600, len 39
            soaData.append(contentsOf: [
                0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 39,
                // mname: ns1.example.com
                0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c,
                // rname: hostmaster.example.com
                0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x0c,
                // serial 2023010101 (0x7894af35)
                0x78, 0x94, 0xaf, 0x35,
                // refresh 7200
                0x00, 0x00, 0x1c, 0x20,
                // retry 3600
                0x00, 0x00, 0x0e, 0x10,
                // expire 1209600
                0x00, 0x12, 0x75, 0x00,
                // minimum 300
                0x00, 0x00, 0x01, 0x2c
            ])
            let soaResult = try DNSCodec.parse(soaData, expectedID: 0x5678, expectedName: "example.com", expectedType: 6)
            assertEqual(soaResult.2.count, 1)
            assertTrue(soaResult.2.first?.value.contains("ns1.example.com") ?? false)
            assertTrue(soaResult.2.first?.value.contains("serial=2023010101") ?? false)

            for count in 0..<12 {
                assertThrows({ try DNSCodec.parse(Data(repeating:0,count:count),expectedID:0) })
            }
            let loop = Data([0,1,0x80,0,0,1,0,0,0,0,0,0,0xc0,0x0c,0,1,0,1])
            assertThrows({ try DNSCodec.parse(loop,expectedID:1) })

            var profile = ProbeProfile(); profile.hexInput = true; profile.request = "48 65 6c 6c 6f"
            assertEqual(try profile.payload(),Data("Hello".utf8))
            profile.request = "a"; assertThrows({ try profile.payload() })

            let dates = CertificateDates.read(Data([0x30,0x82,0xff,0xff]))
            assertNil(dates.0)
            assertNil(dates.1)
        }

        // 3. ArchiveAndComparisonTests
        do {
            print("[RUN] ArchiveAndComparisonTests")
            let password = "correct horse battery staple"
            let input = Data("Sensitive audit data".utf8)
            let sealed = try EncryptedArchive.seal(input,password:password)
            assertEqual(try EncryptedArchive.open(sealed,password:password),input)
            var changed = sealed; changed[changed.count-1] ^= 1
            assertThrows({ try EncryptedArchive.open(changed,password:password) })
            assertThrows({ try EncryptedArchive.open(sealed,password:"wrong password long enough") })
            assertThrows({ try EncryptedArchive.seal(input,password:"short") })

            let open = PortResult(host:"192.0.2.1",port:443,state:.open,duration:0.1,detail:"TCP connected")
            let old = ScanRecord(startedAt:Date(),hosts:[open.host],ports:[443],results:[open],cancelled:false)
            let new = ScanRecord(startedAt:Date(),hosts:[open.host],ports:[80],results:[],cancelled:true)
            let diff = ScanComparison.compare(old:old,new:new)
            assertEqual(diff.count,1)
            assertTrue(diff[0].change.contains("not checked"))

            let record2 = ScanRecord(startedAt:Date(),hosts:["192.0.2.1"],ports:[443],results:[],cancelled:false)
            assertTrue(ScanComparison.compare(old:record2,new:record2).isEmpty)
        }

        // 4. WebSocketTests
        do {
            print("[RUN] WebSocketTests")
            let obs = WebSocketObservation(url: "wss://echo.example.com", handshakeSuccessful: true, subprotocol: "chat", roundTripMilliseconds: 15.2, error: nil)
            let encoded = try JSONEncoder().encode(obs)
            let decoded = try JSONDecoder().decode(WebSocketObservation.self, from: encoded)
            assertEqual(decoded.url, "wss://echo.example.com")
            assertTrue(decoded.handshakeSuccessful)
            assertEqual(decoded.subprotocol, "chat")
            assertEqual(decoded.roundTripMilliseconds, 15.2)
            assertNil(decoded.error)

            // Test non-ws scheme rejection
            let inspector = WebSocketInspector()
            let badSchemeObs = await inspector.inspect(url: URL(string: "http://example.com")!)
            assertTrue(!badSchemeObs.handshakeSuccessful)
            assertTrue(badSchemeObs.error?.contains("ws:// or wss://") ?? false)
        }

        // 5. BackgroundKeepAliveTests
        do {
            print("[RUN] BackgroundKeepAliveTests")
            let wav = BackgroundKeepAlive.generateSilentWAV(durationSeconds: 1, sampleRate: 8000)
            assertEqual(wav.count, 16044) // 44 bytes header + 16000 bytes PCM
            assertEqual(Array(wav[0..<4]), [0x52, 0x49, 0x46, 0x46]) // "RIFF"
            assertEqual(Array(wav[8..<12]), [0x57, 0x41, 0x56, 0x45]) // "WAVE"
            assertEqual(Array(wav[12..<16]), [0x66, 0x6D, 0x74, 0x20]) // "fmt "
            assertEqual(Array(wav[36..<40]), [0x64, 0x61, 0x74, 0x61]) // "data"

            // Verify all data bytes are zeros (silence)
            let audioPayload = wav[44..<wav.count]
            assertTrue(audioPayload.allSatisfy { $0 == 0 })

            // Test lifecycle state
            let keepAlive = BackgroundKeepAlive.shared
            assertTrue(!keepAlive.isActive)
            keepAlive.start()
            assertTrue(keepAlive.isActive)
            keepAlive.stop()
            assertTrue(!keepAlive.isActive)
        }

        print("\n=== Test Results Summary ===")
        print("Total Assertions: \(totalTests)")
        print("Passed: \(passedTests)")
        print("Failed: \(failedTests)")

        if failedTests > 0 {
            exit(1)
        } else {
            print("ALL TESTS PASSED SUCCESSFULLY!")
        }
    }
}
