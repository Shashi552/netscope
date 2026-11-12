import SwiftUI
struct CustomProbeView: View {
    @Environment(\.scenePhase) private var phase
    @State private var profile = ProbeProfile()
    @State private var port = "80"
    @State private var authorized = false
    @State private var confirmation = false
    @State private var output = ""
    @State private var busy = false
    @State private var task: Task<Void,Never>?
    var body: some View {
        Form {
            Section("Explicit single TCP request") {
                TextField("Host/IP",text:$profile.host).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("TCP port",text:$port).keyboardType(.numberPad)
                Toggle("Hex-encoded payload",isOn:$profile.hexInput)
                TextField("Payload (4 KiB maximum)",text:$profile.request,axis:.vertical).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("Optional literal response match",text:$profile.match).textInputAutocapitalization(.never).autocorrectionDisabled()
                Toggle("I authorize this exact target and payload",isOn:$authorized)
                Button("Review & send once") { confirmation = true }.disabled(!authorized || busy)
                if busy { Button("Cancel") { task?.cancel() } }
                Text("Raw TCP is unencrypted. Do not send credentials or destructive payloads. Response limited to the first received chunk, at most 8 KiB. No script engine or automatic retries.").font(.caption).foregroundStyle(.orange)
            }
            Section("Response / error") { Text(output).font(.caption.monospaced()).textSelection(.enabled) }
        }.navigationTitle("Custom TCP probe")
        .confirmationDialog("Send this user-defined payload once?",isPresented:$confirmation,titleVisibility:.visible) { Button("Send authorized payload") { send() } }
        .onDisappear { task?.cancel() }.onChange(of:phase) { _, value in if value == .background { task?.cancel() } }
    }
    private func send() {
        do {
            guard ScopeParser.validHost(profile.host), let number = UInt16(port), number > 0 else { throw InputError.invalid("Invalid host or port.") }
            let data = try profile.payload(); let host = profile.host; let match = profile.match
            busy = true
            task = Task {
                defer { busy = false }
                do {
                    let response = try await SocketExchange().run(host:host,port:number,payload:data)
                    let text = String(decoding:response,as:UTF8.self)
                    output = text + (match.isEmpty ? "" : "\n\nLiteral match: \(text.contains(match) ? "observed" : "not observed in captured chunk")")
                } catch { output = error.localizedDescription }
            }
        } catch { output = error.localizedDescription }
    }
}
