import XCTest
@testable import NetScope
final class ArchiveAndComparisonTests: XCTestCase {
    func testEncryptedArchiveRoundTripAndTamperRejection() throws {
        let password = "correct horse battery staple"
        let input = Data("Sensitive audit data".utf8)
        let sealed = try EncryptedArchive.seal(input,password:password)
        XCTAssertEqual(try EncryptedArchive.open(sealed,password:password),input)
        var changed = sealed; changed[changed.count-1] ^= 1
        XCTAssertThrowsError(try EncryptedArchive.open(changed,password:password))
        XCTAssertThrowsError(try EncryptedArchive.open(sealed,password:"wrong password long enough"))
        XCTAssertThrowsError(try EncryptedArchive.seal(input,password:"short"))
    }
    func testNotCheckedIsNotClosed() {
        let open = PortResult(host:"192.0.2.1",port:443,state:.open,duration:0.1,detail:"TCP connected")
        let old = ScanRecord(startedAt:Date(),hosts:[open.host],ports:[443],results:[open],cancelled:false)
        let new = ScanRecord(startedAt:Date(),hosts:[open.host],ports:[80],results:[],cancelled:true)
        let result = ScanComparison.compare(old:old,new:new)
        XCTAssertEqual(result.count,1)
        XCTAssertTrue(result[0].change.contains("not checked"))
    }
    func testNoChange() {
        let record = ScanRecord(startedAt:Date(),hosts:["192.0.2.1"],ports:[443],results:[],cancelled:false)
        XCTAssertTrue(ScanComparison.compare(old:record,new:record).isEmpty)
    }
}
