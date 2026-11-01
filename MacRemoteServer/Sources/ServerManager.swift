import Foundation
import AppKit
import Network

/// Main controller that coordinates the server, Bonjour, and input handling
@MainActor
final class ServerManager: ObservableObject {

    private let server = NetworkServer()
    private let advertiser = BonjourAdvertiser()
    private let inputController = InputController()
    private let remoteUnlockStore = RemoteUnlockStore()
    private let serverIdentity = ServerIdentity()
    private let hookRunner = UnlockHookRunner.live()
    private let unlockTypingQueue = DispatchQueue(label: "com.macremote.unlock-typing", qos: .userInitiated)
    private lazy var unlockVerifier = UnlockVerifier<ObjectIdentifier>(
        loadSecrets: { [remoteUnlockStore] in
            guard let token = remoteUnlockStore.token,
                  let password = remoteUnlockStore.password else { return nil }
            return UnlockSecrets(token: token, password: password)
        },
        inputPermitted: { AXIsProcessTrusted() },
        lockState: CGSessionLockStateProvider(),
        typePassword: { [inputController, unlockTypingQueue] password in
            await withCheckedContinuation { continuation in
                unlockTypingQueue.async {
                    let result = inputController.unlockScreen(
                        password: password,
                        lockState: CGSessionLockStateProvider()
                    )
                    continuation.resume(returning: result)
                }
            }
        },
        authDialog: CGWindowListAuthDialogDetector(),
        submitAuthDialog: { @Sendable [inputController, unlockTypingQueue] password in
            await withCheckedContinuation { c in
                unlockTypingQueue.async {
                    c.resume(returning: inputController.submitAuthDialog(
                        password: password,
                        lockState: CGSessionLockStateProvider(),
                        detector: CGWindowListAuthDialogDetector()
                    ))
                }
            }
        },
        randomChallenge: { RemoteUnlockStore.randomBytes(count: 32) },
        sleep: { interval in
            try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
        },
        now: { Date() }
    )

    @Published var isRunning = false
    @Published var connectedClients = 0
    @Published var hasAccessibilityPermission = false
    @Published var lastError: String?
    @Published private(set) var hookCommand = HookCommandStore().load() ?? ""
    @Published private(set) var hookForeignScript = HookCommandStore().hasForeignScript()
    @Published private(set) var isRemoteUnlockConfigured = false
    @Published private(set) var pairingKey: String?

    init() {
        refreshRemoteUnlockConfiguration()
        setupServerCallbacks()
        checkPermissions()
        start()
    }

    // MARK: - Remote Unlock

    @discardableResult
    func configureRemoteUnlock(password: String) -> Bool {
        let configured = remoteUnlockStore.configure(password: password)
        refreshRemoteUnlockConfiguration()
        return configured
    }

    func disableRemoteUnlock() {
        remoteUnlockStore.removeConfiguration()
        refreshRemoteUnlockConfiguration()
    }

    private func refreshRemoteUnlockConfiguration() {
        isRemoteUnlockConfigured = remoteUnlockStore.isConfigured
        pairingKey = remoteUnlockStore.formattedPairingKey
    }

    // MARK: - Unlock Hook

    @discardableResult
    func saveHookCommand(_ command: String) -> Bool {
        let store = HookCommandStore()
        do {
            try store.save(command)
            hookCommand = store.load() ?? ""
            hookForeignScript = store.hasForeignScript()
            return true
        } catch {
            lastError = "Could not save hook: \(error.localizedDescription)"
            print("[Server] Failed to save hook command: \(error)")
            return false
        }
    }

    // MARK: - Server Control

    func start() {
        guard hasAccessibilityPermission else {
            lastError = "Accessibility permission required"
            _ = InputController.checkAccessibilityPermission(prompt: true)
            return
        }

        do {
            try server.start()

            // Wait a bit for the server to be ready, then advertise
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
                guard let self = self, self.server.isRunning else { return }
                self.advertiser.startAdvertising(port: self.server.port)
                self.isRunning = true
            }
        } catch {
            lastError = error.localizedDescription
            print("[ServerManager] Failed to start: \(error)")
        }
    }

    func stop() {
        advertiser.stopAdvertising()
        server.stop()
        isRunning = false
        connectedClients = 0
    }

    func toggle() {
        if isRunning {
            stop()
        } else {
            start()
        }
    }

    // MARK: - Permissions

    func checkPermissions() {
        hasAccessibilityPermission = InputController.checkAccessibilityPermission(prompt: false)
    }

    func requestAccessibilityPermission() {
        // Registers the app in the Accessibility list (system prompt), then opens the pane
        _ = InputController.checkAccessibilityPermission(prompt: true)
        InputController.openAccessibilityPreferences()
    }

    // MARK: - Private

    private func setupServerCallbacks() {
        server.onClientConnected = { [weak self] connection in
            guard let self = self else { return }
            self.connectedClients = self.server.connectedClientsCount

            let challenge = self.unlockVerifier.issueChallenge(for: ObjectIdentifier(connection))
            let screenSize = NSScreen.main?.frame.size ?? .zero
            self.server.send(
                .connected(
                    screenWidth: screenSize.width,
                    screenHeight: screenSize.height,
                    unlockChallenge: self.isRemoteUnlockConfigured ? challenge : nil,
                    unlockAvailable: self.isRemoteUnlockConfigured,
                    serverId: self.serverIdentity.id
                ),
                to: connection
            )
        }

        server.onClientDisconnected = { [weak self] connection in
            guard let self = self else { return }
            self.connectedClients = self.server.connectedClientsCount

            self.unlockVerifier.removeConnection(ObjectIdentifier(connection))
        }

        server.onMessageReceived = { [weak self] message, connection in
            self?.handleMessage(message, from: connection)
        }

        server.onError = { [weak self] error in
            self?.lastError = error.localizedDescription
            self?.isRunning = false
        }
    }

    private func handleMessage(_ message: RemoteMessage, from connection: NWConnection) {
        switch message {
        case .ping:
            server.send(.pong, to: connection)

        case .unlock(let signature):
            let clientId = ObjectIdentifier(connection)
            Task { @MainActor in
                let result = await unlockVerifier.handleUnlock(signature: signature, from: clientId)
                // The hook fires after the reply was handed to the network or is known
                // undeliverable, whatever the outcome, because the Mac-side effect already
                // happened. It fires only for verified and authDialogSubmitted.
                var completion: (@Sendable (NetworkServer.SendOutcome) -> Void)?
                if let event = UnlockHookEvent(code: result.code) {
                    let once = HookDispatchOnce()
                    let runner = hookRunner
                    let trigger: @Sendable (String) -> Void = { reason in
                        if once.fire(reason) {
                            print("[Server] Unlock succeeded (\(event.rawValue)); response \(reason); running on-unlock hook")
                            runner.run(event)
                        }
                    }
                    completion = { outcome in trigger("\(outcome)") }
                    DispatchQueue.global().asyncAfter(deadline: .now() + UnlockHookPolicy.sendFallback) {
                        trigger("fallback timeout")
                    }
                }
                server.send(
                    .unlockResult(success: result.code.isSuccess, message: diagnostic(result.code), code: result.code),
                    to: connection,
                    completion: completion
                )
                if let challenge = result.nextChallenge {
                    server.send(.unlockChallenge(challenge), to: connection)
                }
            }
        }
    }

    private func diagnostic(_ code: UnlockResultCode) -> String {
        switch code {
        case .verified: return "Mac unlocked."
        case .alreadyUnlocked: return "Mac was already unlocked."
        case .inProgress: return "Another unlock is in progress."
        case .lockStateUnknown: return "Mac lock state could not be confirmed."
        case .invalidSignature: return "The unlock request was invalid."
        case .notConfigured: return "Remote unlock is not configured on this Mac."
        case .inputNotPermitted: return "Accessibility permission is required."
        case .postFailed: return "The Mac could not post unlock events."
        case .notVerified: return "The Mac did not confirm an unlock."
        case .authDialogSubmitted: return "Password entered into the authentication dialog; the dialog closed."
        case .authDialogRefused: return "Authentication dialog is not safely focused; nothing was typed."
        case .authDialogInterrupted: return "Typing stopped because focus or lock state changed; the dialog was not submitted."
        case .authDialogRetryBlocked: return "A previous authentication dialog attempt failed; retry is paused for a minute."
        case .unrecognized: return "Unknown unlock result."
        }
    }
}
