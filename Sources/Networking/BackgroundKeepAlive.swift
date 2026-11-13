import Foundation
import AVFoundation
#if os(iOS)
import UIKit
import UserNotifications
#endif

/// Manages continuous execution when NetScope is backgrounded or the device screen is locked.
/// Utilizes the audio background mode with an inaudible, looped silent PCM audio stream,
/// keeping network sockets active until authorized scans complete.
@MainActor
public final class BackgroundKeepAlive: NSObject, ObservableObject {
    public static let shared = BackgroundKeepAlive()

    @Published public private(set) var isActive = false
    private var audioPlayer: AVAudioPlayer?

    private override init() {
        super.init()
    }

    /// Activates the background audio session and begins silent playback loop.
    public func start() {
        guard !isActive else { return }

        #if os(iOS)
        do {
            let session = AVAudioSession.sharedInstance()
            // .mixWithOthers allows user's existing music/podcasts to continue without interruption.
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)

            let silentWavData = Self.generateSilentWAV(durationSeconds: 1, sampleRate: 8000)
            let player = try AVAudioPlayer(data: silentWavData)
            player.numberOfLoops = -1 // Loop indefinitely
            player.volume = 0.0        // Completely silent
            player.prepareToPlay()

            if player.play() {
                self.audioPlayer = player
                self.isActive = true
            }
        } catch {
            self.isActive = false
        }
        #else
        self.isActive = true
        #endif
    }

    /// Stops background playback and deactivates the audio session.
    public func stop() {
        guard isActive else { return }

        #if os(iOS)
        audioPlayer?.stop()
        audioPlayer = nil
        isActive = false

        do {
            try AVAudioSession.sharedInstance().setActive(false, options: [.notifyOthersOnDeactivation])
        } catch {
            // Ignore deactivation errors
        }
        #else
        self.isActive = false
        #endif
    }

    /// Requests notification permissions for alerting upon background scan completion.
    public func requestNotificationPermission() {
        #if os(iOS)
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        #endif
    }

    /// Sends a local notification when a background scan finishes.
    public func notifyScanCompleted(hostsCount: Int, openPortsCount: Int) {
        #if os(iOS)
        let content = UNMutableNotificationContent()
        content.title = "NetScope Scan Complete"
        content.body = "Discovered \(openPortsCount) open port(s) across \(hostsCount) target host(s)."
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil // Deliver immediately
        )
        UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
        #endif
    }

    /// Generates a valid RIFF/WAVE header and silent 16-bit PCM buffer entirely in memory.
    public static func generateSilentWAV(durationSeconds: Int = 1, sampleRate: Int = 8000) -> Data {
        let numChannels: Int = 1
        let bitsPerSample: Int = 16
        let byteRate = sampleRate * numChannels * (bitsPerSample / 8)
        let blockAlign = numChannels * (bitsPerSample / 8)
        let dataSize = byteRate * durationSeconds
        let chunkSize = 36 + dataSize

        var data = Data()
        data.reserveCapacity(44 + dataSize)

        // RIFF header
        data.append(contentsOf: [0x52, 0x49, 0x46, 0x46]) // "RIFF"
        data.append(contentsOf: UInt32(chunkSize).littleEndianBytes)
        data.append(contentsOf: [0x57, 0x41, 0x56, 0x45]) // "WAVE"

        // "fmt " subchunk
        data.append(contentsOf: [0x66, 0x6D, 0x74, 0x20]) // "fmt "
        data.append(contentsOf: UInt32(16).littleEndianBytes) // Subchunk1Size = 16 for PCM
        data.append(contentsOf: UInt16(1).littleEndianBytes)  // AudioFormat = 1 (PCM)
        data.append(contentsOf: UInt16(numChannels).littleEndianBytes)
        data.append(contentsOf: UInt32(sampleRate).littleEndianBytes)
        data.append(contentsOf: UInt32(byteRate).littleEndianBytes)
        data.append(contentsOf: UInt16(blockAlign).littleEndianBytes)
        data.append(contentsOf: UInt16(bitsPerSample).littleEndianBytes)

        // "data" subchunk
        data.append(contentsOf: [0x64, 0x61, 0x74, 0x61]) // "data"
        data.append(contentsOf: UInt32(dataSize).littleEndianBytes)
        data.append(Data(repeating: 0, count: dataSize))

        return data
    }
}

private extension FixedWidthInteger {
    var littleEndianBytes: [UInt8] {
        withUnsafeBytes(of: self.littleEndian) { Array($0) }
    }
}
