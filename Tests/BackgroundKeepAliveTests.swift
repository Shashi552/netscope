import XCTest
@testable import NetScope

final class BackgroundKeepAliveTests: XCTestCase {
    func testSilentWAVStructure() {
        let wav = BackgroundKeepAlive.generateSilentWAV(durationSeconds: 1, sampleRate: 8000)
        XCTAssertEqual(wav.count, 16044) // 44 bytes header + 16000 bytes PCM
        XCTAssertEqual(Array(wav[0..<4]), [0x52, 0x49, 0x46, 0x46]) // "RIFF"
        XCTAssertEqual(Array(wav[8..<12]), [0x57, 0x41, 0x56, 0x45]) // "WAVE"
        XCTAssertEqual(Array(wav[12..<16]), [0x66, 0x6D, 0x74, 0x20]) // "fmt "
        XCTAssertEqual(Array(wav[36..<40]), [0x64, 0x61, 0x74, 0x61]) // "data"

        let audioPayload = wav[44..<wav.count]
        XCTAssertTrue(audioPayload.allSatisfy { $0 == 0 })
    }

    @MainActor
    func testKeepAliveLifecycle() {
        let keepAlive = BackgroundKeepAlive.shared
        XCTAssertFalse(keepAlive.isActive)
        keepAlive.start()
        XCTAssertTrue(keepAlive.isActive)
        keepAlive.stop()
        XCTAssertFalse(keepAlive.isActive)
    }
}
