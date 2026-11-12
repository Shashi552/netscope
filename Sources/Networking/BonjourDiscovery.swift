import Foundation
import Network

struct DiscoveredService: Identifiable {
    let id: String
    let name: String
    let type: String
    let domain: String
}
@MainActor final class BonjourDiscovery: ObservableObject {
    static let types = ["_http._tcp", "_https._tcp", "_ssh._tcp", "_ipp._tcp", "_smb._tcp"]
    @Published var services: [DiscoveredService] = []
    @Published var status = "Stopped"
    private var browser: NWBrowser?
    func start(type: String) {
        stop(); services = []; status = "Browsing declared Bonjour service…"
        let browser = NWBrowser(for: .bonjour(type: type, domain: nil), using: .tcp)
        browser.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                switch state {
                case .ready: self?.status = "Browsing · absence of results does not prove absence of devices"
                case .failed(let error): self?.status = error.localizedDescription
                case .waiting(let error): self?.status = "Waiting: \(error.localizedDescription)"
                default: break
                }
            }
        }
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            let values = results.compactMap { result -> DiscoveredService? in
                guard case let .service(name, type, domain, _) = result.endpoint else { return nil }
                return DiscoveredService(id: "\(name)|\(type)|\(domain)", name: name, type: type, domain: domain)
            }.sorted { $0.name < $1.name }
            Task { @MainActor in self?.services = values }
        }
        self.browser = browser
        browser.start(queue: .global(qos: .utility))
    }
    func stop() { browser?.cancel(); browser = nil; status = "Stopped" }
}
