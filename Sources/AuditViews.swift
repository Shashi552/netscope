import SwiftUI
import UniformTypeIdentifiers

struct AuditHubView: View {
    @EnvironmentObject private var audit: AuditStore
    var body: some View {
        NavigationStack {
            List {
                Section("Assessment workspace") {
                    NavigationLink { ProjectsView() } label: { Label("Audit projects",systemImage:"folder") }
                    NavigationLink { InventoryView() } label: { Label("Inventory & expected ports",systemImage:"server.rack") }
                    NavigationLink { FindingsView() } label: { Label("Findings & remediation",systemImage:"checklist") }
                    NavigationLink { ComparisonView() } label: { Label("Compare scans",systemImage:"arrow.left.arrow.right") }
                    NavigationLink { ExposureView() } label: { Label("Service exposure matrix",systemImage:"tablecells") }
                    NavigationLink { SavedObservationsView() } label: { Label("Saved HTTP/TLS observations",systemImage:"lock.doc") }
                }
                Section("Data & activity") {
                    NavigationLink { ArchiveView() } label: { Label("Encrypted audit archive",systemImage:"externaldrive.badge.lock") }
                    NavigationLink { ActivityView() } label: { Label("Local activity history",systemImage:"list.bullet.rectangle") }
                    NavigationLink { ReleaseStatusView() } label: { Label("Feature status & limits",systemImage:"info.circle") }
                }
                if let error = audit.error { Section("Storage issue") { Text(error).foregroundStyle(.orange) } }
                Section { Text("All features are free. No compliance certification, verified physical topology, or guaranteed vulnerability detection is claimed.").font(.caption).foregroundStyle(.secondary) }
            }.navigationTitle("Audit workspace")
        }
    }
}
struct ProjectsView: View {
    @EnvironmentObject private var audit: AuditStore
    @State private var edit: AuditProject?
    var body: some View {
        List {
            if audit.database.projects.isEmpty { ContentUnavailableView("No audit projects",systemImage:"folder",description:Text("Keep authorization, scope, linked scans and checklist notes together.")) }
            ForEach(audit.database.projects) { project in
                Button { edit = project } label: {
                    VStack(alignment:.leading,spacing:5) {
                        Text(project.name).font(.headline)
                        Text(project.client).font(.caption)
                        Text(project.authorizationExpires < Date() ? "Authorization period expired · review before new testing" : "Authorization review: \(project.authorizationExpires.formatted(date:.abbreviated,time:.omitted))").font(.caption).foregroundStyle(project.authorizationExpires < Date() ? .orange : .secondary)
                        Text("\(project.scanIDs.count) linked scans · \(project.checklist.values.filter { $0 }.count)/\(project.checklist.count) checklist items").font(.caption)
                    }
                }.buttonStyle(.plain)
            }.onDelete { offsets in audit.database.projects.remove(atOffsets:offsets); audit.save("Deleted audit project") }
        }.navigationTitle("Projects").toolbar { Button { edit = AuditProject() } label: { Image(systemName:"plus") } }
        .sheet(item:$edit) { project in ProjectEditor(project:project) }
    }
}
struct ProjectEditor: View {
    @EnvironmentObject private var audit: AuditStore
    @EnvironmentObject private var scans: ScanStore
    @Environment(\.dismiss) private var dismiss
    @State var project: AuditProject
    var body: some View {
        NavigationStack {
            Form {
                Section("Engagement") { TextField("Project name",text:$project.name); TextField("Client/site",text:$project.client); DatePicker("Authorization expires",selection:$project.authorizationExpires,displayedComponents:.date) }
                Section("Authorized scope · documentation only") { TextField("Scope",text:$project.scope,axis:.vertical); TextField("Notes",text:$project.notes,axis:.vertical); Text("This field records authorization; it does not automatically enforce scan scope. Confirm each scan separately.").font(.caption) }
                Section("Manual checklist · not certification") {
                    ForEach(project.checklist.keys.sorted(),id:\.self) { key in Toggle(key,isOn:Binding(get:{ project.checklist[key] ?? false },set:{ project.checklist[key] = $0 })) }
                }
                Section("Link saved scans") {
                    ForEach(scans.records) { record in
                        Toggle("\(record.startedAt.formatted(date:.abbreviated,time:.shortened)) · \(record.hosts.count) targets",isOn:Binding(get:{ project.scanIDs.contains(record.id) },set:{ enabled in if enabled { project.scanIDs.append(record.id) } else { project.scanIDs.removeAll { $0 == record.id } } }))
                    }
                }
            }.navigationTitle("Project")
            .toolbar { ToolbarItem(placement:.cancellationAction) { Button("Cancel") { dismiss() } }; ToolbarItem(placement:.confirmationAction) { Button("Save") { if let i = audit.database.projects.firstIndex(where:{ $0.id == project.id }) { audit.database.projects[i] = project } else { audit.database.projects.append(project) }; audit.save("Saved audit project"); dismiss() }.disabled(project.name.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty) } }
        }
    }
}
struct InventoryView: View {
    @EnvironmentObject private var audit: AuditStore
    @EnvironmentObject private var scans: ScanStore
    @State private var query = ""
    @State private var editing: DeviceNote?
    private var observedHosts: [String] { Array(Set(scans.records.flatMap { $0.results.filter { $0.state == .open }.map(\.host) })).sorted() }
    var body: some View {
        List {
            Section("Saved device notes") {
                ForEach(audit.database.devices.filter { query.isEmpty || "\($0.host) \($0.alias) \($0.tags)".localizedCaseInsensitiveContains(query) }) { device in
                    Button { editing = device } label: {
                        VStack(alignment:.leading) { Text(device.alias.isEmpty ? device.host : device.alias).font(.headline); Text("\(device.host) · \(device.criticality) · \(device.trusted ? "User-trusted" : "Unclassified")").font(.caption).foregroundStyle(.secondary); Text(device.tags).font(.caption) }
                    }.buttonStyle(.plain)
                }.onDelete { offsets in
                    let filtered = audit.database.devices.filter { query.isEmpty || "\($0.host) \($0.alias) \($0.tags)".localizedCaseInsensitiveContains(query) }
                    let ids = Set(offsets.map { filtered[$0].id }); audit.database.devices.removeAll { ids.contains($0.id) }; audit.save("Deleted device notes")
                }
            }
            Section("Hosts observed with open TCP connections") {
                ForEach(observedHosts.filter { query.isEmpty || $0.localizedCaseInsensitiveContains(query) },id:\.self) { host in
                    Button(host) { editing = audit.database.devices.first(where: { $0.host == host }) ?? DeviceNote(host:host) }.font(.body.monospaced())
                }
            }
            Text("An address is not a stable device identity. Hosts can change addresses; unknown does not mean malicious. First/last observation times are available in scan history.").font(.caption)
        }.navigationTitle("Inventory").searchable(text:$query)
        .toolbar { Button { editing = DeviceNote() } label: { Image(systemName:"plus") } }
        .sheet(item:$editing) { device in DeviceEditor(device:device) }
    }
}
struct DeviceEditor: View {
    @EnvironmentObject private var audit: AuditStore
    @EnvironmentObject private var scans: ScanStore
    @Environment(\.dismiss) private var dismiss
    @State var device: DeviceNote
    @State private var error = ""
    private var latest: ScanRecord? { scans.records.first { $0.hosts.contains(device.host) } }
    var body: some View {
        NavigationStack {
            Form {
                TextField("Host/IP",text:$device.host).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("Alias",text:$device.alias); TextField("Tags",text:$device.tags)
                Toggle("Trusted by me",isOn:$device.trusted)
                Picker("Criticality",selection:$device.criticality) { ForEach(["Low","Normal","High","Critical"],id:\.self) { Text($0) } }
                TextField("Expected TCP ports, e.g. 22,443",text:$device.expectedPorts)
                TextField("Notes",text:$device.notes,axis:.vertical)
                if let latest {
                    Section("Latest scan baseline review") {
                        Text("Observed: \(latest.startedAt.formatted())")
                        let open = Set(latest.results.filter { $0.host == device.host && $0.state == .open }.map(\.port))
                        if let expected = try? ScanInput.ports(device.expectedPorts) {
                            Text("Unexpected observed open: \(open.subtracting(Set(expected)).sorted().map(String.init).joined(separator:", "))")
                            Text("Expected but not observed open: \(Set(expected).subtracting(open).sorted().map(String.init).joined(separator:", "))")
                            Text("Missing observations may mean ports were not checked or did not respond; they are not proof of closure.").font(.caption)
                        } else { Text("Enter expected ports to compare.").font(.caption) }
                    }
                }
                if !error.isEmpty { Text(error).foregroundStyle(.orange) }
            }.navigationTitle("Device notes").toolbar {
                ToolbarItem(placement:.cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement:.confirmationAction) { Button("Save") {
                    guard ScopeParser.validHost(device.host) else { error = "Invalid host"; return }
                    if !device.expectedPorts.isEmpty { do { _ = try ScanInput.ports(device.expectedPorts) } catch { self.error = error.localizedDescription; return } }
                    if let i = audit.database.devices.firstIndex(where:{ $0.id == device.id }) { audit.database.devices[i] = device } else { audit.database.devices.append(device) }
                    audit.save("Saved device notes"); dismiss()
                } }
            }
        }
    }
}
struct FindingsView: View {
    @EnvironmentObject private var audit: AuditStore
    @State private var editing: AuditFinding?
    @State private var query = ""
    var body: some View {
        List {
            ForEach(audit.database.findings.filter { query.isEmpty || "\($0.title) \($0.host) \($0.status)".localizedCaseInsensitiveContains(query) }) { finding in
                Button { editing = finding } label: { VStack(alignment:.leading,spacing:5) { Text(finding.title).font(.headline); Text("\(finding.host) · \(finding.severity) · \(finding.status)").font(.caption); Text("Confidence: \(finding.confidence)").font(.caption).foregroundStyle(.secondary) } }.buttonStyle(.plain)
            }
            if audit.database.findings.isEmpty { ContentUnavailableView("No findings",systemImage:"checklist",description:Text("Record evidence-based observations, not assumptions from port numbers.")) }
        }.navigationTitle("Findings").searchable(text:$query)
        .toolbar { Button { editing = AuditFinding() } label: { Image(systemName:"plus") } }
        .sheet(item:$editing) { finding in FindingEditor(finding:finding) }
    }
}
struct FindingEditor: View {
    @EnvironmentObject private var audit: AuditStore
    @Environment(\.dismiss) private var dismiss
    @State var finding: AuditFinding
    @State private var confirmDelete = false
    var body: some View {
        NavigationStack {
            Form {
                TextField("Finding title",text:$finding.title)
                TextField("Target",text:$finding.host).textInputAutocapitalization(.never).autocorrectionDisabled()
                Picker("Severity",selection:$finding.severity) { ForEach(["Informational","Low","Medium","High","Critical"],id:\.self) { Text($0) } }
                Picker("Confidence",selection:$finding.confidence) { ForEach(["Observed","Potential","Manually verified"],id:\.self) { Text($0) } }
                Picker("Status",selection:$finding.status) { ForEach(["Open","Acknowledged","Accepted risk","Retest needed","Resolved (manual)"],id:\.self) { Text($0) } }
                Section("Evidence") { TextEditor(text:$finding.evidence).frame(minHeight:100) }
                Section("Remediation") { TextEditor(text:$finding.remediation).frame(minHeight:100) }
                Text("Severity, confidence, and resolution are user assertions. This app does not automatically verify exploitability or resolution.").font(.caption)
                if audit.database.findings.contains(where:{ $0.id == finding.id }) { Button("Delete finding",role:.destructive) { confirmDelete = true } }
            }.navigationTitle("Finding").toolbar {
                ToolbarItem(placement:.cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement:.confirmationAction) { Button("Save") { finding.updatedAt = Date(); if let i = audit.database.findings.firstIndex(where:{ $0.id == finding.id }) { audit.database.findings[i] = finding } else { audit.database.findings.append(finding) }; audit.save("Saved finding"); dismiss() }.disabled(finding.title.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty) }
            }.confirmationDialog("Delete this finding?",isPresented:$confirmDelete,titleVisibility:.visible) { Button("Delete",role:.destructive) { audit.database.findings.removeAll { $0.id == finding.id }; audit.save("Deleted finding"); dismiss() } }
        }
    }
}
struct ComparisonView: View {
    @EnvironmentObject private var scans: ScanStore
    @State private var oldID: UUID?
    @State private var newID: UUID?
    var body: some View {
        List {
            Section {
                Picker("Baseline",selection:$oldID) { Text("Select").tag(nil as UUID?); ForEach(scans.records) { Text($0.startedAt.formatted()).tag(Optional($0.id)) } }
                Picker("New scan",selection:$newID) { Text("Select").tag(nil as UUID?); ForEach(scans.records) { Text($0.startedAt.formatted()).tag(Optional($0.id)) } }
            }
            if let old = scans.records.first(where:{ $0.id == oldID }), let new = scans.records.first(where:{ $0.id == newID }) {
                Section("Open-port observation changes") {
                    let differences = ScanComparison.compare(old:old,new:new)
                    if differences.isEmpty { Text("No open-port differences in the recorded observations.") }
                    ForEach(differences) { difference in VStack(alignment:.leading) { Text("\(difference.host):\(difference.port)").font(.body.monospaced()); Text(difference.change).font(.caption) } }
                    Text("Different scan scopes, retries, network paths, and incomplete scans can explain changes. Not checked is not closed.").font(.caption)
                }
            }
        }.navigationTitle("Compare scans")
    }
}
struct ExposureView: View {
    @EnvironmentObject private var scans: ScanStore
    var body: some View {
        List {
            if let record = scans.records.first {
                Section("Most recent scan · observed open TCP") {
                    ForEach(record.hosts,id:\.self) { host in
                        let results = record.results.filter { $0.host == host && $0.state == .open }.sorted { $0.port < $1.port }
                        if !results.isEmpty {
                            VStack(alignment:.leading,spacing:6) {
                                Text(host).font(.headline.monospaced())
                                Text(results.map { "\($0.port) / \($0.serviceHint)" }.joined(separator:" · ")).font(.caption)
                                if results.contains(where:{ [UInt16(22),3389,5900,445].contains($0.port) }) { Text("Review administrative/file-service exposure. Port hints are unverified.").font(.caption).foregroundStyle(.orange) }
                            }
                        }
                    }
                }
            } else { ContentUnavailableView("No saved scans",systemImage:"tablecells") }
        }.navigationTitle("Exposure matrix")
    }
}
struct SavedObservationsView: View {
    @EnvironmentObject private var audit: AuditStore
    var body: some View {
        List {
            ForEach(audit.database.http) { value in
                Section(value.date.formatted()) {
                    Text(value.url).textSelection(.enabled)
                    Text("Status \(value.status) · \(value.elapsed,specifier:"%.3f") s")
                    ForEach(value.certificates) { cert in NavigationLink(cert.subject) { CertificateView(certificate:cert) } }
                    ForEach(value.reviewNotes,id:\.self) { Text($0).font(.caption) }
                }
            }
            Text("Up to 100 explicitly saved observations. Compare certificate SHA-256 values to review certificate changes; no automatic identity matching or renewal validation.").font(.caption)
        }.navigationTitle("HTTP / TLS history")
    }
}
struct ActivityView: View {
    @EnvironmentObject private var audit: AuditStore
    var body: some View {
        List {
            Section { Text("Local, editable-device activity history; not tamper-proof, signed, or independently timestamped. Scan execution is documented in scan history, not every event is duplicated here.").font(.caption) }
            ForEach(audit.database.events) { event in VStack(alignment:.leading) { Text(event.action); Text(event.date.formatted()).font(.caption).foregroundStyle(.secondary) } }
        }.navigationTitle("Activity")
    }
}
struct ArchiveView: View {
    @EnvironmentObject private var audit: AuditStore
    @State private var password = ""
    @State private var importing = false
    @State private var confirm = false
    @State private var incoming: Data?
    @State private var output: URL?
    @State private var message = ""
    @State private var busy = false
    var body: some View {
        List {
            Section("Encrypted audit data archive") {
                Text("Includes projects, device notes, findings, profiles and saved HTTP/TLS observations. TCP scan history is exported separately. No password recovery is possible.").font(.caption)
                SecureField("Password · at least 12 characters",text:$password)
                Button("Create AES-GCM archive") { export() }.disabled(busy || password.count < 12)
                if let output { ShareLink(item:output) { Label("Share encrypted archive",systemImage:"square.and.arrow.up") } }
            }
            Section("Import replaces current audit workspace") {
                Button("Choose encrypted archive") { importing = true }.disabled(busy)
                if incoming != nil { Button("Decrypt & replace workspace",role:.destructive) { confirm = true }.disabled(busy || password.count < 12) }
                Text(message).font(.caption)
            }
            if busy { ProgressView("Deriving password key…") }
        }.navigationTitle("Encrypted archive")
        .fileImporter(isPresented:$importing,allowedContentTypes:[.data]) { result in
            do {
                let url = try result.get(); let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
                guard (try url.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? 0) <= 33*1024*1024 else { throw InputError.invalid("Archive exceeds 33 MiB.") }
                incoming = try Data(contentsOf:url); message = "Archive loaded. Enter its password and confirm replacement."
            } catch { message = error.localizedDescription }
        }
        .confirmationDialog("Replace all current audit data?",isPresented:$confirm,titleVisibility:.visible) { Button("Decrypt & replace",role:.destructive) { restore() } }
        .onDisappear { password = ""; incoming = nil }
    }
    private func export() {
        do {
            let data = try JSONEncoder().encode(audit.database); let secret = password; busy = true
            Task {
                defer { busy = false }
                do { let sealed = try await Task.detached(priority:.userInitiated) { try EncryptedArchive.seal(data,password:secret) }.value; output = try ExportFiles.write(sealed,name:"Audit-\(UUID()).nsarchive"); message = "Archive ready. Keep the password separately."; audit.save("Exported encrypted audit archive") }
                catch { message = error.localizedDescription }
            }
        } catch { message = error.localizedDescription }
    }
    private func restore() {
        guard let incoming else { return }; let secret = password; busy = true
        Task {
            defer { busy = false }
            do { let data = try await Task.detached(priority:.userInitiated) { try EncryptedArchive.open(incoming,password:secret) }.value; try audit.replace(from:data); message = "Audit workspace replaced."; self.incoming = nil }
            catch { message = "Import failed; workspace was not replaced: \(error.localizedDescription)" }
        }
    }
}
struct ReleaseStatusView: View {
    var body: some View {
        List {
            Section("Source handoff · 0.2") { Text("No feature paywalls. This source has not been compiled or device-tested in the Linux authoring workspace. Production release requires the Mac verification checklist.") }
            Section("Implemented source modules") {
                ForEach(["TCP scans, rate limits, retries, exclusions, checkpoint/resume", "IPv4 CIDR/range expansion; explicit IPv6 targets", "Bonjour advertisements and local interfaces", "Bounded HTTP/API requests; redirect blocking", "System TLS trust, certificate dates, fingerprints, export", "DNS over UDP/TCP, typed answers and resolver comparison", "Greeting reads; bounded foreground health charts", "Local projects, inventory, manual findings and baselines", "Scan comparisons, exposure view, JSON/CSV/PDF reporting", "Target-file and QR scope import; bounded user-defined TCP probes", "App lock, protected storage and encrypted audit archives"],id:\.self) { Text($0) }
            }
            Section("Not implemented / not promised") {
                Text("No exhaustive discovery, MAC/ARP inventory, raw SYN scans, OS fingerprinting, Wi-Fi capture, exploit execution, CVE database, background monitoring, Wake-on-LAN, DNS-over-HTTPS, custom CA evaluation, full X.509 SAN/issuer viewer, attachments, automatic severity scoring, multi-user collaboration, verified report snapshots, or automatic compliance assessment.")
                Text("OpenAPI is a JSON-only local explorer, not automatic API execution. SOA records are raw hex. HTTP tools do not enumerate all TLS versions/ciphers. This is not all 180 planning items shipped.")
            }
        }.navigationTitle("Feature status")
    }
}
