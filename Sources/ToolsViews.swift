import SwiftUI
import UniformTypeIdentifiers
import Charts
import UserNotifications

struct ToolsView: View {
    var body: some View {
        NavigationStack {
            List {
                Section("Discovery") {
                    NavigationLink { InterfacesView() } label: { Label("Local interfaces", systemImage:"wifi") }
                    NavigationLink { BonjourView() } label: { Label("Bonjour services", systemImage:"dot.radiowaves.left.and.right") }
                }
                Section("Inspect authorized targets") {
                    NavigationLink { HTTPToolView() } label: { Label("HTTP / API / TLS inspector", systemImage:"globe") }
                    NavigationLink { BannerToolView() } label: { Label("Service greeting reader", systemImage:"text.bubble") }
                    NavigationLink { DNSToolView() } label: { Label("DNS diagnostics", systemImage:"point.3.connected.trianglepath.dotted") }
                    NavigationLink { HealthToolView() } label: { Label("Endpoint health session", systemImage:"waveform.path.ecg") }
                    NavigationLink { CustomProbeView() } label: { Label("Bounded custom TCP probe",systemImage:"terminal") }
                    NavigationLink { OpenAPIView() } label: { Label("OpenAPI endpoint explorer", systemImage:"curlybraces") }
                }
                Section { Text("Tools send real network requests. Use only authorized targets. Redirects are never automatically followed. Sessions stop when you leave the tool; scans are foreground-only.").font(.caption).foregroundStyle(.secondary) }
            }.navigationTitle("Network tools")
        }
    }
}
struct InterfacesView: View {
    @State private var interfaces = LocalInterfaces.all()
    var body: some View {
        List {
            ForEach(interfaces) { item in
                VStack(alignment:.leading,spacing:6) {
                    Text(item.name).font(.headline)
                    Text(item.address).font(.body.monospaced()).textSelection(.enabled)
                    Text("Netmask: \(item.netmask)").font(.caption).foregroundStyle(.secondary)
                }
            }
            Text("Interface names and addresses do not prove the router address, SSID, subnet ownership, or physical topology.").font(.caption)
        }.navigationTitle("Local interfaces").toolbar { Button("Refresh") { interfaces = LocalInterfaces.all() } }
    }
}
struct BonjourView: View {
    @Environment(\.scenePhase) private var phase
    @StateObject private var discovery = BonjourDiscovery()
    @State private var selected = BonjourDiscovery.types[0]
    var body: some View {
        List {
            Section {
                Picker("Service type",selection:$selected) { ForEach(BonjourDiscovery.types,id:\.self) { Text($0) } }
                Button("Browse selected type") { discovery.start(type:selected) }
                Button("Stop") { discovery.stop() }
                Text(discovery.status).font(.caption)
            }
            Section("Advertised services") {
                ForEach(discovery.services) { service in
                    VStack(alignment:.leading) { Text(service.name).font(.headline); Text("\(service.type) · \(service.domain)").font(.caption).foregroundStyle(.secondary) }
                }
            }
            Text("This view lists advertised Bonjour service instances, not resolved IP addresses or a complete device inventory.").font(.caption)
        }.navigationTitle("Bonjour").onDisappear { discovery.stop() }.onChange(of:phase) { _, value in if value == .background { discovery.stop() } }
    }
}
struct HTTPToolView: View {
    @EnvironmentObject private var audit: AuditStore
    @Environment(\.scenePhase) private var phase
    @State private var address = ""
    @State private var method = "GET"
    @State private var requestBody = ""
    @State private var token = ""
    @State private var authMode = "None"
    @State private var username = ""
    @State private var password = ""
    @State private var origin = ""
    @State private var authorized = false
    @State private var confirm = false
    @State private var observation: HTTPObservation?
    @State private var error: String?
    @State private var task: Task<Void,Never>?
    @State private var busy = false
    @State private var saved = false
    @State private var expectedStatus = ""
    @State private var expectedText = ""
    @State private var export: URL?
    var body: some View {
        List {
            Section("Explicit request · no automatic redirects") {
                TextField("https://192.168.1.10/",text:$address).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                Picker("Method",selection:$method) { ForEach(["GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"],id:\.self) { Text($0) } }
                if !["GET","HEAD","OPTIONS"].contains(method) { TextField("Request body (maximum 64 KiB)",text:$requestBody,axis:.vertical); Text("This method can change or delete server data.").foregroundStyle(.orange) }
                Picker("Authentication",selection:$authMode) { ForEach(["None","Bearer","Basic"],id:\.self) { Text($0) } }
                if authMode == "Bearer" { SecureField("Bearer token · HTTPS only",text:$token).textInputAutocapitalization(.never).autocorrectionDisabled() }
                if authMode == "Basic" {
                    TextField("Username",text:$username).textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField("Password · HTTPS only",text:$password)
                }
                if authMode != "None" {
                    Button("Save credentials for this HTTPS origin") { credentialAction("save") }
                    Button("Load credentials for this HTTPS origin") { credentialAction("load") }
                    Button("Forget saved credentials for this origin",role:.destructive) { credentialAction("delete") }
                    Text("Saving is optional. Keychain records are bound to HTTPS host + port and excluded from project archives. No credentials are forwarded to redirects.").font(.caption)
                }
                TextField("Optional Origin header for CORS inspection",text:$origin).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("Optional expected status (e.g. 200)",text:$expectedStatus).keyboardType(.numberPad)
                TextField("Optional literal body match",text:$expectedText).textInputAutocapitalization(.never).autocorrectionDisabled()
                Toggle("I am authorized to inspect this endpoint",isOn:$authorized)
                Button(busy ? "Request in progress…" : "Review & send") { confirm = true }.disabled(!authorized || busy)
                if busy { Button("Cancel",role:.destructive) { task?.cancel() } }
            }.disabled(false)
            if let error { Section("Error") { Text(error).foregroundStyle(.orange) } }
            if let value = observation {
                Section("Observed response") {
                    LabeledContent("Status",value:String(value.status))
                    LabeledContent("Elapsed",value:String(format:"%.3f s",value.elapsed))
                    LabeledContent("Captured",value:"\(value.bytesCaptured) bytes\(value.truncated ? " · partial" : "")")
                    if let title = value.title { LabeledContent("HTML title",value:title) }
                    if let protocolName = value.negotiatedProtocol { LabeledContent("Protocol",value:protocolName) }
                    if let version = value.tlsVersion { LabeledContent("Negotiated TLS code",value:String(format:"0x%04x",version)) }
                    if let cipher = value.cipherSuite { LabeledContent("Negotiated cipher code",value:String(format:"0x%04x",cipher)) }
                    if let issue = value.error { Text(issue).foregroundStyle(.orange) }
                    Text("Captured body SHA-256: \(value.bodySHA256)").font(.caption.monospaced()).textSelection(.enabled)
                }
                if !expectedStatus.isEmpty || !expectedText.isEmpty {
                    Section("User-defined assertions") {
                        if !expectedStatus.isEmpty { Text("Status assertion: \(Int(expectedStatus) == value.status ? "matched" : "not matched")") }
                        if !expectedText.isEmpty { Text("Literal match in text preview: \(value.bodyPreview.contains(expectedText) ? "observed" : "not observed in captured preview")") }
                        Text("Preview is limited to 32 KiB; absence of text in the preview does not prove absence in the complete response.").font(.caption)
                    }
                }
                Section("Review notes · not verified vulnerabilities") { ForEach(value.reviewNotes,id:\.self) { Text($0).font(.subheadline) } }
                Section("Response headers · cookie values redacted") {
                    ForEach(value.headers.keys.sorted(),id:\.self) { key in VStack(alignment:.leading) { Text(key).font(.caption.bold()); Text(value.headers[key] ?? "").font(.caption.monospaced()).textSelection(.enabled) } }
                }
                Section("Certificates · system trust evaluation") {
                    ForEach(value.certificates) { certificate in NavigationLink { CertificateView(certificate:certificate) } label: { VStack(alignment:.leading) { Text(certificate.subject); Text(certificate.trustStatus).font(.caption).foregroundStyle(.secondary) } } }
                    if value.certificates.isEmpty { Text("No certificate captured. Use HTTPS; trust data may not be available for every failed connection.").font(.caption) }
                }
                Section("Safe text preview · no scripts executed") { Text(value.bodyPreview).font(.caption.monospaced()).textSelection(.enabled) }
                Section("Save intentionally") {
                    Button(saved ? "Observation saved" : "Save minimal HTTP/TLS history") { audit.addObservation(value); saved = true }.disabled(saved)
                    Text("Saved history omits body text and most headers. URL paths/query strings and certificate metadata remain sensitive.").font(.caption)
                    Button("Prepare full observation JSON") {
                        do { export = try ExportFiles.write(JSONEncoder().encode(value),name:"HTTP-\(UUID()).json") } catch { self.error = error.localizedDescription }
                    }
                    if let export { ShareLink(item:export) { Label("Share JSON · may contain sensitive response text",systemImage:"square.and.arrow.up") } }
                }
            }
        }.navigationTitle("HTTP / API / TLS")
        .confirmationDialog("Send \(method) to this exact endpoint?",isPresented:$confirm,titleVisibility:.visible) { Button("Send authorized request",role: ["GET","HEAD","OPTIONS"].contains(method) ? nil : .destructive) { run() } } message: { Text(address + "\nNo redirects will be followed. Do not put secrets in URLs.") }
        .onChange(of:address) { _, _ in token = ""; password = "" }
        .onDisappear { task?.cancel(); token = ""; password = "" }
        .onChange(of:phase) { _, value in if value == .background { task?.cancel(); token = ""; password = "" } }
    }
    private func credentialAction(_ action: String) {
        guard let url = URL(string:address), url.scheme?.lowercased() == "https", let host = url.host else { error = "Enter a valid HTTPS URL before managing credentials."; return }
        let account = "https://\(host.lowercased()):\(url.port ?? 443)"
        do {
            if action == "delete" { SecretVault.remove(account:account); token = ""; password = ""; error = "Saved credentials removed for this origin."; return }
            if action == "save" {
                let values = ["mode":authMode,"username":username,"password":password,"token":token]
                let data = try JSONEncoder().encode(values)
                guard let text = String(data:data,encoding:.utf8) else { return }
                try SecretVault.put(text,account:account); error = "Credentials saved to this device's Keychain."
            } else if let text = SecretVault.get(account:account) {
                let values = try JSONDecoder().decode([String:String].self,from:Data(text.utf8))
                authMode = values["mode"] ?? "None"; username = values["username"] ?? ""; password = values["password"] ?? ""; token = values["token"] ?? ""
                error = "Loaded credentials for this HTTPS origin."
            } else { error = "No saved credentials for this HTTPS origin." }
        } catch { self.error = error.localizedDescription }
    }
    private func run() {
        guard let url = URL(string:address) else { error = "Invalid URL"; return }
        var headers: [String:String] = [:]
        if authMode == "Bearer", !token.isEmpty { headers["Authorization"] = "Bearer " + token }
        if authMode == "Basic" { headers["Authorization"] = "Basic " + Data("\(username):\(password)".utf8).base64EncodedString() }
        if !origin.isEmpty { headers["Origin"] = origin }
        if !requestBody.isEmpty { headers["Content-Type"] = "application/json" }
        let body = ["GET","HEAD","OPTIONS"].contains(method) ? nil : Data(requestBody.utf8)
        busy = true; error = nil; saved = false; export = nil
        let requestMethod = method
        task = Task {
            defer { busy = false }
            do { observation = try await HTTPInspector().inspect(url:url,method:requestMethod,headers:headers,body:body) }
            catch { self.error = error.localizedDescription }
        }
    }
}
struct CertificateView: View {
    let certificate: CertificateObservation
    @State private var file: URL?
    @State private var message = ""
    var body: some View {
        List {
            Section("Observed certificate") {
                Text(certificate.subject).font(.headline)
                Text(certificate.trustStatus)
                Text("SHA-256: \(certificate.sha256)").font(.caption.monospaced()).textSelection(.enabled)
                LabeledContent("Key type",value:certificate.publicKeyType)
                LabeledContent("Key size",value:"\(certificate.publicKeyBits) bits")
                if let date = certificate.notBefore { LabeledContent("Not before",value:date.formatted()) }
                if let date = certificate.notAfter { LabeledContent("Not after",value:date.formatted()); Text(date < Date() ? "Certificate is expired." : "Certificate expiry: \(date.formatted(date:.abbreviated,time:.omitted))") }
            }
            Section {
                Button("Export public certificate (DER)") {
                    do { guard let data = Data(base64Encoded:certificate.derBase64) else { return }; file = try ExportFiles.write(data,name:"Certificate-\(UUID()).cer") } catch { message = error.localizedDescription }
                }
                if let file { ShareLink(item:file) }
                Button("Set expiry reminder") { reminder() }.disabled(certificate.notAfter == nil)
                Text(message).font(.caption)
            }
            Text("The evaluated chain is not necessarily identical to the certificates sent by the server. This is a connection observation, not exhaustive TLS/cipher enumeration.").font(.caption)
        }.navigationTitle("Certificate")
    }
    private func reminder() {
        guard let expiry = certificate.notAfter else { return }
        let date = expiry.addingTimeInterval(-7*86400)
        guard date > Date() else { message = "The seven-day reminder time has already passed."; return }
        Task {
            do {
                let center = UNUserNotificationCenter.current()
                guard try await center.requestAuthorization(options:[.alert,.sound]) else { message = "Notification permission not granted."; return }
                let content = UNMutableNotificationContent(); content.title = "Certificate expiry review"; content.body = "A saved certificate expires in approximately seven days. Open NetScope to review."
                let trigger = UNCalendarNotificationTrigger(dateMatching:Calendar.current.dateComponents([.year,.month,.day,.hour,.minute],from:date),repeats:false)
                try await center.add(UNNotificationRequest(identifier:"cert-"+certificate.sha256,content:content,trigger:trigger)); message = "Reminder scheduled from saved expiry; not continuous monitoring."
            } catch { message = error.localizedDescription }
        }
    }
}
struct BannerToolView: View {
    @Environment(\.scenePhase) private var phase
    @State private var host = ""
    @State private var port = "22"
    @State private var authorized = false
    @State private var response = ""
    @State private var busy = false
    @State private var task: Task<Void,Never>?
    var body: some View {
        List {
            Section("Read a server's initial greeting") {
                TextField("Host/IP",text:$host).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("TCP port",text:$port).keyboardType(.numberPad)
                Toggle("Authorized target",isOn:$authorized)
                Button("Connect & read up to 8 KiB") { read() }.disabled(!authorized || busy)
                if busy { Button("Cancel") { task?.cancel() } }
                Text("Sends no application payload. SSH, FTP and SMTP often send greetings; many other protocols remain silent. Only the first received chunk is shown, so banners can be incomplete.").font(.caption)
            }
            Section("Untrusted text · not executed") { Text(response).font(.caption.monospaced()).textSelection(.enabled) }
        }.navigationTitle("Service greeting").onDisappear { task?.cancel() }.onChange(of:phase) { _, value in if value == .background { task?.cancel() } }
    }
    private func read() {
        guard ScopeParser.validHost(host), let number = UInt16(port), number > 0 else { response = "Invalid host or port"; return }
        busy = true; response = "Connecting…"
        task = Task {
            defer { busy = false }
            do { let data = try await SocketExchange().run(host:host,port:number,payload:nil); response = String(decoding:data,as:UTF8.self) }
            catch { response = error.localizedDescription }
        }
    }
}
struct DNSToolView: View {
    @Environment(\.scenePhase) private var phase
    @State private var name = ""
    @State private var resolver = ""
    @State private var secondResolver = ""
    @State private var type: UInt16 = 1
    @State private var tcp = false
    @State private var authorized = false
    @State private var responses: [DNSResponse] = []
    @State private var error = ""
    @State private var busy = false
    @State private var task: Task<Void,Never>?
    var body: some View {
        List {
            Section("Explicit resolver queries") {
                TextField("DNS name (PTR: enter reverse name)",text:$name).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("Resolver IP / hostname",text:$resolver).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("Optional comparison resolver",text:$secondResolver).textInputAutocapitalization(.never).autocorrectionDisabled()
                Picker("Record",selection:$type) { ForEach(DNSCodec.types,id:\.1) { Text($0.0).tag($0.1) } }
                Toggle("DNS over TCP",isOn:$tcp)
                Toggle("I authorize these resolver requests",isOn:$authorized)
                Button("Query resolver(s)") { run() }.disabled(busy || !authorized)
                if busy { Button("Cancel") { task?.cancel() } }
                Text("Resolvers receive the queried name. Queries are not encrypted. SOA data is currently shown as raw hex; authority/additional sections are not displayed.").font(.caption)
            }
            if !error.isEmpty { Text(error).foregroundStyle(.orange) }
            ForEach(responses.indices,id:\.self) { index in
                let value = responses[index]
                Section(value.resolver) {
                    Text("\(value.milliseconds,specifier:"%.1f") ms · RCODE \(value.responseCode)\(value.truncated ? " · truncated; try TCP" : "")")
                    ForEach(value.records) { record in VStack(alignment:.leading,spacing:4) { Text(record.name).font(.caption.bold()); Text(record.value).font(.caption.monospaced()).textSelection(.enabled); Text("TTL \(record.ttl) s · TYPE \(record.type)").font(.caption2).foregroundStyle(.secondary) } }
                }
            }
            if responses.count == 2 { Section("Comparison") { Text(Set(responses[0].records.map(\.value)) == Set(responses[1].records.map(\.value)) ? "Returned answer values match." : "Returned answer values differ. Caching, geography, filtering, or split DNS may explain differences; this is not proof of tampering.") } }
        }.navigationTitle("DNS diagnostics").onDisappear { task?.cancel() }.onChange(of:phase) { _, value in if value == .background { task?.cancel() } }
    }
    private func run() {
        busy = true; responses = []; error = ""
        let servers = [resolver,secondResolver].filter { !$0.isEmpty }
        task = Task {
            defer { busy = false }
            for server in servers {
                do { try Task.checkCancellation(); responses.append(try await DNSClient.query(name:name,type:type,resolver:server,tcp:tcp)) }
                catch { self.error += "\(server): \(error.localizedDescription)\n" }
            }
        }
    }
}
struct HealthSample: Identifiable {
    let id = UUID()
    let date: Date
    let milliseconds: Double
    let status: Int
    let succeeded: Bool
}
struct HealthToolView: View {
    @Environment(\.scenePhase) private var phase
    @State private var url = ""
    @State private var expected = "200"
    @State private var authorized = false
    @State private var count = 5
    @State private var interval = 5.0
    @State private var samples: [HealthSample] = []
    @State private var busy = false
    @State private var task: Task<Void,Never>?
    var body: some View {
        List {
            Section("Bounded foreground session") {
                TextField("https://host/health",text:$url).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("Expected HTTP status",text:$expected).keyboardType(.numberPad)
                Stepper("Checks: \(count)",value:$count,in:1...30)
                Stepper("Interval: \(Int(interval)) seconds",value:$interval,in:2...60,step:1)
                Toggle("Authorized endpoint",isOn:$authorized)
                Button("Start session") { start() }.disabled(!authorized || busy)
                if busy { Button("Stop") { task?.cancel() } }
            }
            if !samples.isEmpty {
                Section("HTTP duration · not ICMP latency") {
                    Chart(samples) { item in LineMark(x:.value("Time",item.date),y:.value("Milliseconds",item.milliseconds)); PointMark(x:.value("Time",item.date),y:.value("Milliseconds",item.milliseconds)).foregroundStyle(item.succeeded ? Color.mint : Color.orange) }.frame(height:180)
                    Text("\(samples.filter(\.succeeded).count)/\(samples.count) checks matched the expected status")
                    ForEach(samples) { sample in Text("\(sample.date.formatted(date:.omitted,time:.standard)) · status \(sample.status) · \(sample.milliseconds,specifier:"%.0f") ms").font(.caption.monospaced()) }
                }
            }
        }.navigationTitle("Health session").onDisappear { task?.cancel() }.onChange(of:phase) { _, value in if value == .background { task?.cancel() } }
    }
    private func start() {
        guard let endpoint = URL(string:url), let expectedStatus = Int(expected), (100...599).contains(expectedStatus) else { return }
        let attempts = count; let delay = interval
        samples = []; busy = true
        task = Task {
            defer { busy = false }
            for index in 0..<attempts {
                if Task.isCancelled { break }
                let began = Date()
                do {
                    let observation = try await HTTPInspector().inspect(url:endpoint,method:"HEAD")
                    samples.append(HealthSample(date:began,milliseconds:observation.elapsed*1000,status:observation.status,succeeded:observation.status == expectedStatus && observation.error == nil))
                } catch { if Task.isCancelled { break }; samples.append(HealthSample(date:began,milliseconds:Date().timeIntervalSince(began)*1000,status:0,succeeded:false)) }
                if index+1 < attempts { do { try await Task.sleep(nanoseconds:UInt64(delay*1_000_000_000)) } catch { break } }
            }
        }
    }
}
struct OpenAPIEndpoint: Identifiable { var id: String { method+path }; let method: String; let path: String; let summary: String }
struct OpenAPIView: View {
    @State private var importing = false
    @State private var endpoints: [OpenAPIEndpoint] = []
    @State private var message = "Import a local OpenAPI JSON file (maximum 2 MiB). No network requests are made, no external references fetched. YAML is not supported in this build."
    var body: some View {
        List {
            Section { Button("Import OpenAPI JSON") { importing = true }; Text(message).font(.caption) }
            ForEach(endpoints) { endpoint in VStack(alignment:.leading) { Text("\(endpoint.method) \(endpoint.path)").font(.subheadline.monospaced()); Text(endpoint.summary).font(.caption); if !["GET","HEAD","OPTIONS"].contains(endpoint.method) { Text("State-changing method — never automatically executed").font(.caption).foregroundStyle(.orange) } } }
        }.navigationTitle("OpenAPI explorer")
        .fileImporter(isPresented:$importing,allowedContentTypes:[.json]) { result in
            do {
                let url = try result.get(); let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
                let size = try url.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? 0
                guard size <= 2*1024*1024 else { throw InputError.invalid("Specification exceeds 2 MiB.") }
                let data = try Data(contentsOf:url); guard data.count <= 2*1024*1024 else { throw InputError.invalid("Specification exceeds 2 MiB.") }
                guard let root = try JSONSerialization.jsonObject(with:data) as? [String:Any], let paths = root["paths"] as? [String:[String:Any]], paths.count <= 2000 else { throw InputError.invalid("Expected bounded OpenAPI paths object.") }
                var output: [OpenAPIEndpoint] = []
                for path in paths.keys.sorted() { for method in ["get","head","options","post","put","patch","delete"] { if let operation = paths[path]?[method] as? [String:Any] { output.append(OpenAPIEndpoint(method:method.uppercased(),path:path,summary:operation["summary"] as? String ?? "")) } } }
                endpoints = output; message = "\(output.count) operations. Review and manually enter authorized endpoints in the HTTP inspector. Imported operations never execute automatically."
            } catch { message = error.localizedDescription }
        }
    }
}
