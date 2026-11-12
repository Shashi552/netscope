import Foundation
import Network

@MainActor final class PathObserver: ObservableObject {
    @Published var description = "Checking connectivity…"
    private let monitor = NWPathMonitor()
    var onChange: (() -> Void)?
    private var signature: String?
    init() {
        monitor.pathUpdateHandler = { [weak self] path in
            let text = "\(path.status)|\(path.availableInterfaces.map { $0.name }.sorted().joined(separator: ","))|\(path.isExpensive)|\(path.isConstrained)"
            Task { @MainActor in
                guard let self else { return }
                let changed = self.signature != nil && self.signature != text
                self.signature = text
                self.description = path.status == .satisfied ? "Network available\(path.isExpensive ? " · metered" : "")" : "No usable network path"
                if changed { self.onChange?() }
            }
        }
        monitor.start(queue: .global(qos: .utility))
    }
    deinit { monitor.cancel() }
}
