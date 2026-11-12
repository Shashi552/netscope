import SwiftUI
import AVFoundation

// Optional user-initiated camera import. QR data is plain untrusted scope text;
// it is never executed and scanning still requires scope review/authorization.
struct QRScopeSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onImport: (String) -> Void
    @State private var value: String?
    @State private var error = ""
    var body: some View {
        NavigationStack {
            VStack(spacing:20) {
                if let value {
                    Text("Review QR target scope").font(.headline)
                    ScrollView { Text(value).font(.body.monospaced()).textSelection(.enabled) }
                    Button("Use these targets (does not scan)") {
                        do { _ = try ScopeParser.expand(value); onImport(value); dismiss() }
                        catch { self.error = error.localizedDescription }
                    }.buttonStyle(.borderedProminent)
                } else { CameraQRView { text in value = String(text.prefix(8192)) } onError: { error = $0 }.frame(maxHeight:400) }
                Text(error).foregroundStyle(.orange)
                Text("Use a QR code containing only IP addresses, hostnames or IPv4 CIDR scope. URLs and executable actions are rejected.").font(.caption)
            }.padding().navigationTitle("Import scope QR")
            .toolbar { Button("Close") { dismiss() } }
        }
    }
}
private struct CameraQRView: UIViewControllerRepresentable {
    let onCode: (String) -> Void
    let onError: (String) -> Void
    func makeUIViewController(context: Context) -> QRController {
        let controller = QRController(); controller.onCode = onCode; controller.onError = onError; return controller
    }
    func updateUIViewController(_ uiViewController: QRController, context: Context) {}
    static func dismantleUIViewController(_ controller: QRController, coordinator: ()) { controller.stop() }
}
private final class QRController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    var onError: ((String) -> Void)?
    private let capture = AVCaptureSession()
    private let queue = DispatchQueue(label:"app.netscope.camera")
    private var preview: AVCaptureVideoPreviewLayer?
    private var delivered = false
    private var stopped = false
    override func viewDidLoad() {
        super.viewDidLoad(); view.backgroundColor = .black
        AVCaptureDevice.requestAccess(for:.video) { [weak self] allowed in
            guard let self else { return }
            if !allowed { DispatchQueue.main.async { self.onError?("Camera access denied. Enter or import targets manually.") }; return }
            self.queue.async { self.configure() }
        }
    }
    private func configure() {
        guard !stopped else { return }
        guard let camera = AVCaptureDevice.default(for:.video), let input = try? AVCaptureDeviceInput(device:camera), capture.canAddInput(input) else { DispatchQueue.main.async { self.onError?("Camera is unavailable.") }; return }
        capture.beginConfiguration(); capture.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard capture.canAddOutput(output) else { capture.commitConfiguration(); return }
        capture.addOutput(output); output.setMetadataObjectsDelegate(self,queue:.main); output.metadataObjectTypes = [.qr]
        capture.commitConfiguration()
        DispatchQueue.main.async {
            let layer = AVCaptureVideoPreviewLayer(session:self.capture); layer.videoGravity = .resizeAspectFill; layer.frame = self.view.bounds
            self.view.layer.addSublayer(layer); self.preview = layer
        }
        capture.startRunning()
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    override func viewDidDisappear(_ animated: Bool) { super.viewDidDisappear(animated); stop() }
    func stop() { queue.async { self.stopped = true; if self.capture.isRunning { self.capture.stopRunning() } } }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !delivered, let value = (metadataObjects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        delivered = true; onCode?(value); stop()
    }
}
