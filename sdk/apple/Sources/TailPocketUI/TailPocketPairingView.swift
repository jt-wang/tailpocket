#if os(iOS)
import AVFoundation
import SwiftUI
import TailPocket

/// A ready-made pairing screen: computers on this Wi-Fi, a QR scanner, and a paste field. It returns
/// the TailPocketHostLink through `onPaired`; storing it (e.g. `TailPocketKeychainStore`) and the look of your app stay yours.
/// Build your own screen from `TailPocketNearbyHosts`, `TailPocketLocalPairing`, `TailPocketQRScanner` and `TailPocket.pair` instead
/// if this one does not fit.
@available(iOS 16.0, *)
public struct TailPocketPairingView: View {
    public struct Options {
        public var service: String?
        public var prefix: String = TailPocket.defaultPrefix
        public var label: String = ""
        public var device: String = UIDevice.current.name
        public init(service: String? = nil) { self.service = service }
    }

    private let options: Options
    private let phoneKey: String
    private let onPaired: (TailPocketHostLink) -> Void
    @StateObject private var model = PairingModel(camera: Self.camera())
    @State private var browser: TailPocketNearbyHosts?
    @Environment(\.scenePhase) private var scenePhase

    public init(options: Options, phoneKey: String, onPaired: @escaping (TailPocketHostLink) -> Void) {
        self.options = options
        self.phoneKey = phoneKey
        self.onPaired = onPaired
    }

    /// Read at each action, so the latest arguments from the parent are used.
    private var inputs: PairingModel.Inputs {
        let (options, phoneKey) = (options, phoneKey)
        return .init(
            prefix: options.prefix,
            pair: { try await TailPocket.pair($0, phoneKey: phoneKey, device: options.device) },
            beginLocal: { host in
                let pending = try await TailPocketLocalPairing.begin(with: host, device: options.device, label: options.label)
                return .init(code: pending.code, finish: { try await pending.finish() })
            },
            onPaired: onPaired)
    }

    public var body: some View {
        PairingContent(model: model, inputs: inputs, showsNearby: options.service != nil)
            .onAppear {
                guard let service = options.service, browser == nil else { return }
                let b = TailPocketNearbyHosts(service: service)
                b.start(onChange: { list in Task { @MainActor in model.hosts = list } })
                browser = b
            }
            .onDisappear { browser?.stop(); browser = nil }
            // Back from Settings with the camera allowed (or taken away).
            .onChange(of: scenePhase) { phase in if phase == .active { model.camera = Self.camera() } }
    }

    static func camera() -> PairingModel.Camera {
        .init(supported: TailPocketQRScanner.isSupported, authorization: AVCaptureDevice.authorizationStatus(for: .video))
    }
}

/// The pairing screen for a model, without the nearby browser and camera checks.
@available(iOS 16.0, *)
struct PairingContent: View {
    @ObservedObject var model: PairingModel
    let inputs: PairingModel.Inputs
    let showsNearby: Bool

    var body: some View {
        List {
            if case let .code(code, host) = model.status {
                Section("Confirm on \(host)") {
                    Text(code).font(.system(size: 40, weight: .semibold, design: .monospaced)).frame(maxWidth: .infinity)
                    Text("Check that the computer shows the same code, then approve it there.").font(.footnote).foregroundStyle(.secondary)
                }
            }
            if case let .working(text) = model.status { Section { HStack { ProgressView(); Text(text) } } }
            if case let .failed(text) = model.status { Section { Text(text).foregroundStyle(.red) } }
            if showsNearby {
                Section("On this Wi-Fi") {
                    if model.hosts.isEmpty { Text("Looking for computers…").foregroundStyle(.secondary) }
                    ForEach(model.hosts) { host in
                        Button(host.name) { Task { await model.pairNearby(host, inputs) } }
                    }
                }
            }
            Section("Pairing code") {
                switch model.camera {
                case .available:
                    Button("Scan QR code") {
                        Task {
                            await model.scan(requestAccess: {
                                await AVCaptureDevice.requestAccess(for: .video) && TailPocketQRScanner.isAvailable
                            })
                        }
                    }
                case .denied:
                    Text("Camera access is needed to scan the code.")
                    Button("Open Settings") {
                        if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
                    }
                case .unsupported:
                    EmptyView()
                }
                TextField("Paste code", text: $model.pasted).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .onSubmit { Task { await model.pairText(model.pasted, inputs) } }
            }
        }
        .sheet(isPresented: $model.scanning) {
            TailPocketQRScanner(prefix: inputs.prefix) { text in Task { await model.scanned(text, inputs) } }
                .ignoresSafeArea()
        }
    }
}
#endif
