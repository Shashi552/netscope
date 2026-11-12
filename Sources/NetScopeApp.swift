import SwiftUI
import UniformTypeIdentifiers
import UserNotifications

@main struct NetScopeApp: App {
    @StateObject private var store = ScanStore()
    @StateObject private var audit = AuditStore()
    var body: some Scene {
        WindowGroup { AppShell().environmentObject(store).environmentObject(audit) }
    }
}
struct AppShell: View {
    @EnvironmentObject private var store: ScanStore
    @Environment(\.scenePhase) private var phase
    @StateObject private var security = AppSecurity()
    @StateObject private var path = PathObserver()
    @AppStorage("appLock") private var lockEnabled = false
    @AppStorage("theme") private var theme = "System"
    var body: some View {
        ZStack {
            TabView {
                ScanView().tabItem { Label("Scan",systemImage:"dot.radiowaves.left.and.right") }
                ToolsView().tabItem { Label("Tools",systemImage:"wrench.and.screwdriver") }
                AuditHubView().tabItem { Label("Audit",systemImage:"folder") }
                HistoryView().tabItem { Label("History",systemImage:"clock.arrow.circlepath") }
                AboutView().tabItem { Label("Settings",systemImage:"gearshape") }
            }.tint(.mint)
            if lockEnabled && !security.unlocked {
                Color(uiColor:.systemBackground).ignoresSafeArea()
                VStack(spacing:20) {
                    Image(systemName:"lock.shield.fill").font(.system(size:64)).foregroundStyle(.mint)
                    Text("NetScope is locked").font(.title2.bold())
                    Button("Unlock with device authentication") { Task { await security.unlock() } }.buttonStyle(.borderedProminent)
                    Text(security.message).font(.caption)
                }.padding()
            }
            if phase != .active {
                Color(uiColor:.systemBackground).ignoresSafeArea()
                Label("NetScope · private workspace",systemImage:"shield.fill").font(.headline)
            }
        }
        .preferredColorScheme(theme == "Dark" ? .dark : theme == "Light" ? .light : nil)
        .task {
            try? ExportFiles.clear()
            path.onChange = { if store.running { store.cancel(reason:"Network path changed; review scope before resuming") } }
            if lockEnabled { await security.unlock() }
        }
        .onChange(of:phase) { _, value in
            if value == .background { if store.running { store.cancel(reason:"App moved to background") }; security.unlocked = false }
        }
        .onChange(of:lockEnabled) { _, enabled in if enabled { security.unlocked = false; Task { await security.unlock() } } }
    }
}
struct ScanView: View {
    @EnvironmentObject var store: ScanStore
    @EnvironmentObject private var audit: AuditStore
    @Environment(\.scenePhase) private var phase
    @State private var targets = ""
    @State private var ports = ScanInput.commonPorts
    @State private var concurrency = 16
    @State private var timeout = 2.0
    @State private var authorized = false
    @State private var error: String?
    @State private var pendingHosts: [String] = []
    @State private var pendingPorts: [UInt16] = []
    @State private var confirm = false
    @State private var excludedHosts = ""
    @State private var excludedPorts = ""
    @State private var retries = 0
    @State private var rate = 30
    @State private var privateOnly = false
    @State private var profileName = ""
    @State private var saveProfile = false
    @State private var importTargets = false
    @State private var qrImport = false
    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("YOUR NETWORK. YOUR VISIBILITY.", systemImage: "shield.checkered").font(.caption.weight(.bold)).foregroundStyle(.mint)
                        Text("See what’s open.").font(.largeTitle.bold())
                        Text("Real TCP checks. On your iPhone. Always free.").foregroundStyle(.secondary)
                    }.padding(.vertical, 12)
                }.listRowBackground(Color.mint.opacity(0.07))
                Section("01 · Choose targets") {
                    TextField("192.168.1.1 or server.local", text: $targets, axis: .vertical)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.asciiCapable)
                        .accessibilityLabel("Target IP addresses or hostnames")
                    Text("Individual IPv4/IPv6 addresses, DNS hostnames, IPv4 CIDR (/20–/32), or full IPv4 ranges. Excludes subnet/broadcast for /20–/30.").font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Button("Import target text") { importTargets = true }
                        Spacer()
                        Button("Scan target QR") { qrImport = true }
                    }.buttonStyle(.borderless)
                }.disabled(store.running)
                Section("Saved profiles & exclusions") {
                    if !audit.database.profiles.isEmpty {
                        Menu("Load saved profile") {
                            ForEach(audit.database.profiles) { profile in Button(profile.name) { targets = profile.targets; ports = profile.ports; concurrency = profile.concurrency; timeout = profile.timeout } }
                        }
                    }
                    TextField("Excluded hosts / CIDRs (optional)",text:$excludedHosts).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Excluded ports (optional)",text:$excludedPorts)
                    Toggle("Require private IPv4 literals only",isOn:$privateOnly)
                    Text("Private-only mode rejects DNS names, IPv6, public and loopback addresses; it permits RFC1918 IPv4 literals only.").font(.caption)
                    Button("Save current targets & port profile") { saveProfile = true }
                }.disabled(store.running)
                Section("02 · Configure scan") {
                    TextField("22,80,443 or 1-1024", text: $ports, axis: .vertical)
                        .keyboardType(.asciiCapable).accessibilityLabel("TCP ports")
                    HStack {
                        Button("Common") { ports = ScanInput.commonPorts }
                        Spacer()
                        Button("Web") { ports = "80,443,8000,8080,8443" }
                        Spacer()
                        Button("All TCP") { ports = "1-65535" }
                    }.buttonStyle(.borderless)
                    Stepper("Concurrent checks: \(concurrency)", value: $concurrency, in: 1...64)
                    Stepper("Retries after ambiguous failures: \(retries)",value:$retries,in:0...2)
                    Stepper("Maximum attempt starts / second: \(rate)",value:$rate,in:1...100,step:1)
                    VStack(alignment: .leading) {
                        Text("Timeout: \(timeout, specifier: "%.1f") seconds")
                        Slider(value: $timeout, in: 0.5...10, step: 0.5)
                    }
                    Button("Use gentle settings") { concurrency = 4; timeout = 4 }
                        .buttonStyle(.borderless)
                }.disabled(store.running)
                Section {
                    Toggle("I own these targets or have permission to test them", isOn: $authorized).font(.subheadline)
                        .disabled(store.running)
                    if store.running {
                        Button(role: .destructive) { store.cancel() } label: { Label("Stop scan & save partial results", systemImage: "stop.circle.fill") }
                    } else {
                        Button { prepare() } label: {
                            HStack { Spacer(); Label("Review & start scan", systemImage: "arrow.right.circle.fill").font(.headline); Spacer() }
                        }.disabled(!authorized)
                    }
                }
                if let record = store.current {
                    Section("Live open ports · first 200") {
                        ScanSummary(record: record)
                        ForEach(Array(record.results.filter { $0.state == .open }.sorted { $0.port < $1.port }.prefix(200))) { result in
                            NavigationLink { ResultDetail(result: result) } label: { ResultRow(result: result) }
                        }
                        if record.openCount == 0 {
                            Text(store.running ? "Checking targets… Open connections appear here." : "No open TCP connections observed. This does not prove the targets are absent or secure.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if let storageError = store.storageError { Section { Text(storageError).foregroundStyle(.orange) } }
            }
            .navigationTitle("NetScope")
            .alert("Check your input", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) { Button("OK") { error = nil } } message: { Text(error ?? "") }
            .confirmationDialog("Start \(pendingHosts.count * pendingPorts.count) TCP checks?", isPresented: $confirm, titleVisibility: .visible) {
                Button("Start authorized scan") { store.start(hosts: pendingHosts, ports: pendingPorts, concurrency: concurrency, timeout: timeout, retries: retries, rate: rate) }
            } message: { Text("\(pendingHosts.count) target(s) × \(pendingPorts.count) port(s). Keep the app open. Scanning may trigger network alerts or affect fragile devices.") }
            .sheet(isPresented:$qrImport) { QRScopeSheet { targets = $0 } }
            .fileImporter(isPresented:$importTargets,allowedContentTypes:[.plainText,.commaSeparatedText,.json]) { result in
                do {
                    let url = try result.get(); let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
                    guard (try url.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? 0) <= 65536 else { throw InputError.invalid("Target file exceeds 64 KiB.") }
                    let data = try Data(contentsOf:url)
                    guard data.count <= 65536 else { throw InputError.invalid("Target file exceeds 64 KiB.") }
                    let text: String
                    if url.pathExtension.lowercased() == "json" { text = try JSONDecoder().decode([String].self,from:data).joined(separator:"\n") }
                    else { guard let decoded = String(data:data,encoding:.utf8) else { throw InputError.invalid("Expected UTF-8 text.") }; text = decoded }
                    _ = try ScopeParser.expand(text); targets = text
                } catch { self.error = error.localizedDescription }
            }
            .alert("Save scan profile",isPresented:$saveProfile) {
                TextField("Profile name",text:$profileName)
                Button("Save") {
                    if !profileName.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty {
                        audit.database.profiles.append(SavedProfile(name:profileName,targets:targets,ports:ports,concurrency:concurrency,timeout:timeout)); audit.save("Saved scan profile"); profileName = ""
                    }
                }
                Button("Cancel",role:.cancel) {}
            } message: { Text("Saves target/port lists, concurrency and timeout. Exclusions, retries and rate are not included; review them when loading a profile.") }
            .onChange(of: phase) { _, phase in
                if phase == .background && store.running { store.cancel() }
            }
        }
    }
    private func prepare() {
        do {
            pendingHosts = try ScanInput.hosts(targets)
            pendingPorts = try ScanInput.ports(ports)
            if !excludedHosts.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty { let excluded = Set(try ScopeParser.expand(excludedHosts)); pendingHosts.removeAll { excluded.contains($0) } }
            if !excludedPorts.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty { let excluded = Set(try ScanInput.ports(excludedPorts)); pendingPorts.removeAll { excluded.contains($0) } }
            guard !pendingHosts.isEmpty, !pendingPorts.isEmpty else { throw InputError.invalid("Exclusions removed all targets or ports.") }
            if privateOnly {
                guard pendingHosts.allSatisfy({ value in
                    guard let ip = ScopeParser.ipv4(value) else { return false }
                    return ip >> 24 == 10 || ip >> 20 == 0xac1 || ip >> 16 == 0xc0a8
                }) else { throw InputError.invalid("Private-only mode accepts only RFC1918 IPv4 literals.") }
            }
            guard pendingHosts.count * pendingPorts.count <= 262_144 else { throw InputError.invalid("This build limits scans to 262,144 checks. Narrow the scope or split the scan.") }
            confirm = true
        } catch { self.error = error.localizedDescription }
    }
}
struct ScanSummary: View {
    let record: ScanRecord
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                metric("OPEN", "\(record.openCount)", .mint)
                Spacer()
                metric("CHECKED", "\(record.results.count)", .primary)
                Spacer()
                metric("PLANNED", "\(record.plannedCount)", .secondary)
            }
            ProgressView(value: Double(record.results.count), total: Double(max(record.plannedCount, 1)))
            Text(record.finishedAt == nil ? "Foreground scan · TCP connect" : record.cancelled ? "Interrupted · partial coverage" : "Completed · inspect full outcomes in History")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(.vertical, 8)
    }
    private func metric(_ title: String, _ value: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) { Text(title).font(.caption2.weight(.semibold)).foregroundStyle(.secondary); Text(value).font(.title2.monospacedDigit().bold()).foregroundStyle(color) }
    }
}
struct ResultRow: View {
    let result: PortResult
    var body: some View {
        HStack {
            Image(systemName: result.state == .open ? "circle.inset.filled" : "circle.dotted")
                .foregroundStyle(result.state == .open ? .mint : .secondary)
            VStack(alignment: .leading, spacing: 3) {
                Text("\(result.host):\(Int(result.port))").font(.subheadline.monospaced()).lineLimit(1)
                Text("\(result.serviceHint) · port hint only").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Text(result.state.title).font(.caption.weight(.medium)).foregroundStyle(result.state == .open ? .mint : .secondary)
        }.padding(.vertical, 3)
    }
}
struct ResultDetail: View {
    let result: PortResult
    var body: some View {
        List {
            Section("Connection observation") {
                LabeledContent("Host", value: result.host)
                LabeledContent("TCP port", value: String(result.port))
                LabeledContent("Outcome", value: result.state.title)
                LabeledContent("Elapsed", value: String(format: "%.3f seconds", result.duration))
            }
            Section("Evidence") { Text(result.detail).textSelection(.enabled) }
            Section("Not a verified service") { Text("\(result.serviceHint) is a conventional port mapping, not a confirmed protocol, product, or version. An open port alone is not a vulnerability.") }
        }.navigationTitle("Port \(result.port)")
    }
}
struct HistoryView: View {
    @EnvironmentObject var store: ScanStore
    var body: some View {
        NavigationStack {
            List {
                if store.records.isEmpty { ContentUnavailableView("No scans yet", systemImage: "clock", description: Text("Completed and cancelled scans are saved here on this iPhone.")) }
                ForEach(store.records) { record in
                    NavigationLink {
                        RecordView(record: record)
                    } label: {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(record.hosts.joined(separator: ", ")).font(.headline).lineLimit(1)
                            Text(record.startedAt.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.secondary)
                            Text("\(record.openCount) open · \(record.results.count)/\(record.plannedCount) checked\(record.cancelled ? " · Partial" : "")").font(.caption).foregroundStyle(.mint)
                        }.padding(.vertical, 5)
                    }
                }.onDelete(perform: store.delete)
            }.navigationTitle("Scan history")
            .toolbar { EditButton() }
        }
    }
}
struct RecordView: View {
    @EnvironmentObject private var store: ScanStore
    let record: ScanRecord
    @State private var openOnly = true
    @State private var exportURL: URL?
    @State private var exportError: String?
    @State private var organization = ""
    @State private var redact = true
    @State private var resumeConfirm = false
    @State private var query = ""
    var body: some View {
        List {
            Section { ScanSummary(record: record) }
            if record.results.count < record.plannedCount {
                Section("Resume unfinished checks") {
                    Button("Review & resume remaining scope") { resumeConfirm = true }.disabled(store.running)
                    Text("Keeps the original scan ID and start time. Observations may span multiple sessions. Results already recorded are not rechecked.").font(.caption)
                }
            }
            Section("Export · contains network identifiers") {
                TextField("Report organization/title",text:$organization)
                Toggle("Redact target identifiers in PDF",isOn:$redact)
                Button("Prepare PDF assessment") { do { exportURL = try ReportBuilder.pdf(record:record,organization:organization,redact:redact) } catch { exportError = error.localizedDescription } }
                if let exportURL { Button("Prepare SHA-256 manifest of current export") { do { self.exportURL = try ReportBuilder.manifest(for:exportURL) } catch { exportError = error.localizedDescription } } }
                Button("Prepare JSON export") { prepare(csv: false) }
                Button("Prepare CSV export") { prepare(csv: true) }
                if let exportURL { ShareLink(item: exportURL) { Label("Share prepared file", systemImage: "square.and.arrow.up") } }
                if let exportError { Text(exportError).foregroundStyle(.orange) }
            }
            Section {
                Toggle("Open ports only", isOn: $openOnly)
                ForEach(Array(record.results.filter { (!openOnly || $0.state == .open) && (query.isEmpty || "\($0.host):\($0.port) \($0.state.title)".localizedCaseInsensitiveContains(query)) }.sorted { $0.host == $1.host ? $0.port < $1.port : $0.host < $1.host }.prefix(500))) { result in
                    NavigationLink { ResultDetail(result: result) } label: { ResultRow(result: result) }
                }
            } header: { Text("Connection outcomes") } footer: { Text("Showing up to 500 matching results. JSON/CSV exports include all outcomes. No response does not establish that a port is closed. Observations reflect the time and network path of this scan.") }
        }.navigationTitle("Scan details").searchable(text:$query)
        .confirmationDialog("Reconfirm authorization for the saved scope?",isPresented:$resumeConfirm,titleVisibility:.visible) {
            Button("Resume authorized scan") { store.resume(record) }
        } message: { Text("\(record.hosts.count) target(s), \(record.ports.count) port(s). Verify network and authorization before continuing. UI displays up to 500 matching outcomes; exports contain all outcomes.") }
    }
    private func prepare(csv: Bool) {
        do { exportURL = try csv ? ScanExport.csv(record) : ScanExport.json(record); exportError = nil }
        catch { exportError = error.localizedDescription }
    }
}
struct AboutView: View {
    @EnvironmentObject var store: ScanStore
    @EnvironmentObject private var audit: AuditStore
    @AppStorage("appLock") private var appLock = false
    @AppStorage("theme") private var theme = "System"
    @State private var confirmDelete = false
    @State private var importScan = false
    @State private var message = ""
    var body: some View {
        NavigationStack {
            List {
                Section("Always free · iPhone only") {
                    Label("No subscriptions, ads, analytics SDKs or agents",systemImage:"heart.fill")
                    Toggle("Require device authentication",isOn:$appLock)
                    Picker("Appearance",selection:$theme) { ForEach(["System","Dark","Light"],id:\.self) { Text($0) } }
                    Text("App-switcher privacy cover is enabled. Device lock requires a configured passcode; enable only after testing authentication on your device.").font(.caption)
                }
                Section("Privacy & storage") {
                    Text("Data stays in Application Support with iOS file protection and backup exclusion. Scan history keeps the most recent 20 records. Audit history keeps up to 100 saved HTTP observations and 1000 activity events. Hostnames may be resolved by your DNS provider. Target devices receive real requests.")
                    Text("HTTP redirects are blocked. Failed TLS trust is never bypassed. HTTP response bodies may contain secrets; saving minimal observations omits body text, but URL paths/query strings remain sensitive.")
                    Button("Import NetScope scan JSON") { importScan = true }.disabled(store.running)
                    Button("Clear temporary exports") { do { try ExportFiles.clear(); message = "Temporary app export files cleared. Shared copies remain." } catch { message = error.localizedDescription } }
                    Button("Delete all local scans & audit data",role:.destructive) { confirmDelete = true }.disabled(store.running)
                    Text(message).font(.caption)
                }
                Section("Limits & authorization") {
                    NavigationLink("Feature status and unimplemented items") { ReleaseStatusView() }
                    Text("Keep the app open. Backgrounding stops network sessions. Path changes cancel TCP scans, but Wi-Fi roaming/subnet changes may not always be visible to NWPathMonitor. Review scope before every scan. Permission denial may appear as a timeout.")
                    Text("This is source handoff 0.2, not a certified production binary. Only inspect systems you own or have explicit authorization to assess.").font(.caption)
                }
            }.navigationTitle("Settings & privacy")
            .confirmationDialog("Delete local scans and audit data?",isPresented:$confirmDelete,titleVisibility:.visible) {
                Button("Delete all local data",role:.destructive) { store.clear(); audit.erase(); SecretVault.removeAll(); UNUserNotificationCenter.current().removeAllPendingNotificationRequests(); UNUserNotificationCenter.current().removeAllDeliveredNotifications(); try? ExportFiles.clear(); message = "Local records, app credentials and reminders cleared; shared copies remain. No secure-erasure guarantee." }
            }
            .fileImporter(isPresented:$importScan,allowedContentTypes:[.json]) { result in
                do {
                    let url = try result.get(); let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
                    guard (try url.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? 0) <= 64*1024*1024 else { throw InputError.invalid("Scan exceeds import limit.") }
                    try store.importRecord(Data(contentsOf:url)); message = "Scan imported. No targets were contacted."
                } catch { message = error.localizedDescription }
            }
        }
    }
}
