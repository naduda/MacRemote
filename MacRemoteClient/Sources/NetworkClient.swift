import Foundation
import Network

/// TCP Client that connects to a MacRemote server
final class NetworkClient: ObservableObject {

    @Published var isConnected = false
    @Published var connectionError: String?
    @Published private(set) var isUnlockAvailable = false
    @Published private(set) var pairingState: PairingState = .unpaired
    var hasUnlockPairingKey: Bool { pairingState != .unpaired }
    @Published var unlockStatus: String?
    @Published var isAuthenticatingForUnlock = false

    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "com.macremote.client", qos: .userInteractive)
    private let pairingStore = RemoteUnlockService.livePairingStore
    private var connectedEndpoint: NWEndpoint?
    private var connectedServerName: String?
    private var connectedServerId: String?

    init() {
        pairingState = pairingStore.state()
    }

    // MARK: - Connection

    func connect(to endpoint: NWEndpoint, name: String) {
        disconnect()
        connectedEndpoint = endpoint
        connectedServerName = name

        connection = NWConnection(to: endpoint, using: .tcp)

        connection?.stateUpdateHandler = { [weak self, weak currentConnection = connection] state in
            DispatchQueue.main.async {
                guard let self, self.connection === currentConnection else { return }
                switch state {
                case .ready:
                    self.isConnected = true
                    self.connectionError = nil
                    self.startReceiving()
                    print("[Client] Connected")

                case .failed(let error):
                    self.disconnect()
                    self.connectionError = error.localizedDescription
                    print("[Client] Failed: \(error)")

                case .cancelled:
                    self.clearConnectedServer()
                    self.isConnected = false
                    print("[Client] Cancelled")

                default:
                    break
                }
            }
        }

        connection?.start(queue: queue)
    }

    func disconnect() {
        connection?.cancel()
        connection = nil
        isConnected = false
        clearConnectedServer()
    }

    private func clearConnectedServer() {
        connectedEndpoint = nil
        connectedServerName = nil
        connectedServerId = nil
        isUnlockAvailable = false
    }

    // MARK: - Sending Messages

    func send(_ message: RemoteMessage) {
        guard let connection = connection, isConnected else { return }

        do {
            let data = try MessageFrame.encode(message)
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    print("[Client] Send error: \(error)")
                }
            })
        } catch {
            print("[Client] Encode error: \(error)")
        }
    }

    @discardableResult
    func saveUnlockPairingKey(_ pairingKey: String) -> Bool {
        guard let serverId = connectedServerId else {
            unlockStatus = String(localized: "unlock_pairing_server_outdated")
            return false
        }
        let token: Data
        do {
            token = try UnlockCredentialStore.parsePairingKey(pairingKey)
        } catch {
            unlockStatus = String(localized: "unlock_invalid_pairing_key")
            return false
        }
        do {
            try pairingStore.pair(token: token, serverId: serverId, displayName: connectedServerName ?? "Mac")
            pairingState = pairingStore.state()
            unlockStatus = nil
            return true
        } catch {
            pairingState = pairingStore.state()
            unlockStatus = String(localized: "unlock_pairing_save_failed")
            return false
        }
    }

    func removeUnlockPairingKey() {
        do {
            try pairingStore.unpair()
            unlockStatus = nil
        } catch {
            unlockStatus = String(localized: "unlock_pairing_save_failed")
        }
        pairingState = pairingStore.state()
    }

    func requestUnlock() {
        guard !isAuthenticatingForUnlock else { return }
        guard let endpoint = connectedEndpoint else {
            unlockStatus = String(localized: "unlock_outcome_connection_lost")
            return
        }
        let name = connectedServerName ?? "Mac"
        isAuthenticatingForUnlock = true
        Task {
            let outcome = await RemoteUnlockService.shared.unlock(
                route: .directSession(NetworkUnlockSession(endpoint: endpoint, name: name), displayName: name),
                reason: String(localized: "unlock_auth_reason")
            )
            await MainActor.run {
                unlockStatus = String(localized: String.LocalizationValue(outcome.localizationKey))
                isAuthenticatingForUnlock = false
            }
        }
    }

    // MARK: - Receiving

    private func startReceiving() {
        guard let connection = connection else { return }

        connection.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] data, _, isComplete, error in
            guard let self = self, self.connection === connection else { return }

            if isComplete || error != nil {
                DispatchQueue.main.async {
                    self.disconnect()
                }
                return
            }

            guard let lengthData = data, lengthData.count == 4 else {
                self.startReceiving()
                return
            }

            let length = lengthData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            print("[Client] Expecting message of \(length) bytes")

            connection.receive(minimumIncompleteLength: Int(length), maximumLength: Int(length)) { [weak self] messageData, _, _, error in
                guard let self = self else { return }

                if let error = error {
                    print("[Client] Receive error: \(error)")
                }

                if let data = messageData {
                    print("[Client] Received \(data.count) bytes")
                    do {
                        let message = try MessageFrame.decode(data, as: ServerMessage.self)
                        DispatchQueue.main.async {
                            self.handleMessage(message)
                        }
                    } catch {
                        print("[Client] Decode error: \(error)")
                    }
                } else {
                    print("[Client] No data received")
                }

                self.startReceiving()
            }
        }
    }

    private func handleMessage(_ message: ServerMessage) {
        switch message {
        case .connected(_, _, _, let unlockAvailable, let serverId):
            connectedServerId = serverId
            isUnlockAvailable = unlockAvailable

        case .pong:
            print("[Client] Pong received")

        case .error(let message):
            connectionError = message

        case .unlockResult, .unlockChallenge:
            break
        }
    }
}
