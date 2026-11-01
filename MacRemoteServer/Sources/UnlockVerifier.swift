import Foundation
import CryptoKit

struct UnlockSecrets: Sendable {
    let token: Data
    let password: String
}

@MainActor
final class UnlockVerifier<ConnectionID: Hashable & Sendable> {
    private(set) var isInProgress = false
    private var challenges: [ConnectionID: Data] = [:]
    private var liveConnections: Set<ConnectionID> = []

    private let loadSecrets: () throws -> UnlockSecrets?
    private let inputPermitted: () -> Bool
    private let lockState: SessionLockStateProviding
    private let typePassword: (String) async -> UnlockTypingResult
    private let authDialog: AuthDialogDetecting
    private let submitAuthDialog: @Sendable (String) async -> AuthDialogTypingResult
    private let randomChallenge: () -> Data
    private let sleep: (TimeInterval) async -> Void
    private let now: () -> Date
    private let verifyDeadline: TimeInterval
    private let pollInterval: TimeInterval
    private let authDialogCooldown: TimeInterval
    private var authDialogBlockedUntil: Date?

    init(
        loadSecrets: @escaping () throws -> UnlockSecrets?,
        inputPermitted: @escaping () -> Bool,
        lockState: SessionLockStateProviding,
        typePassword: @escaping (String) async -> UnlockTypingResult,
        authDialog: AuthDialogDetecting,
        submitAuthDialog: @escaping @Sendable (String) async -> AuthDialogTypingResult,
        randomChallenge: @escaping () -> Data,
        sleep: @escaping (TimeInterval) async -> Void,
        now: @escaping () -> Date,
        verifyDeadline: TimeInterval = UnlockWire.verifyDeadline,
        pollInterval: TimeInterval = UnlockWire.verifyPollInterval,
        authDialogCooldown: TimeInterval = 60
    ) {
        self.loadSecrets = loadSecrets
        self.inputPermitted = inputPermitted
        self.lockState = lockState
        self.typePassword = typePassword
        self.authDialog = authDialog
        self.submitAuthDialog = submitAuthDialog
        self.randomChallenge = randomChallenge
        self.sleep = sleep
        self.now = now
        self.verifyDeadline = verifyDeadline
        self.pollInterval = pollInterval
        self.authDialogCooldown = authDialogCooldown
    }

    /// Returns the first non-nil value produced by `step` before `verifyDeadline`, or nil.
    private func poll<T>(_ step: () -> T?) async -> T? {
        let deadline = now().addingTimeInterval(verifyDeadline)
        while true {
            if let value = step() { return value }
            if now() >= deadline { return nil }
            await sleep(pollInterval)
        }
    }

    /// The cooldown applies only after Return was posted, to avoid account lockout
    /// from repeated wrong-password submissions. Refusals, interruptions and post
    /// failures submitted nothing and never start it.
    private func handleAuthDialog(password: String) async -> UnlockResultCode {
        switch authDialog.scan() {
        case .failed:
            print("[Server] Window scan failed; cannot tell whether an auth dialog is open")
            return .authDialogRefused
        case .windows(let w) where w.isEmpty:
            return .alreadyUnlocked
        case .windows:
            break
        }
        if let until = authDialogBlockedUntil, until > now() { return .authDialogRetryBlocked }

        switch await submitAuthDialog(password) {
        case .noDialog: return .alreadyUnlocked
        case .sessionNotUnlocked: return .lockStateUnknown
        case .multipleDialogs, .detectionFailed, .notFocused, .notPasswordField,
             .fieldNotEmpty, .fieldContentUnknown, .accessibilityError:
            return .authDialogRefused
        case .interrupted: return .authDialogInterrupted
        case .postFailed: return .postFailed
        case .typed(let id):
            var tracker = AuthDialogCloseTracker(target: id)
            let status = await poll { () -> AuthDialogCloseTracker.Status? in
                let s = tracker.observe(lockState: lockState.currentState(), scan: authDialog.scan())
                return s == .pending ? nil : s
            }
            if status == .closed {
                authDialogBlockedUntil = nil
                return .authDialogSubmitted
            }
            authDialogBlockedUntil = now().addingTimeInterval(authDialogCooldown)
            return .notVerified
        }
    }

    func issueChallenge(for id: ConnectionID) -> Data {
        liveConnections.insert(id)
        let challenge = randomChallenge()
        challenges[id] = challenge
        return challenge
    }

    func removeConnection(_ id: ConnectionID) {
        liveConnections.remove(id)
        challenges.removeValue(forKey: id)
    }

    func handleUnlock(signature: Data, from id: ConnectionID) async -> (code: UnlockResultCode, nextChallenge: Data?) {
        guard !isInProgress else { return (.inProgress, nil) }
        isInProgress = true
        defer { isInProgress = false }

        let code: UnlockResultCode
        if let challenge = challenges.removeValue(forKey: id) {
            if let secrets = try? loadSecrets() {
                let expected = UnlockWire.signature(challenge: challenge, token: secrets.token)
                if signature.constantTimeEquals(expected) {
                    if inputPermitted() {
                        switch lockState.currentState() {
                        case .unlocked: code = await handleAuthDialog(password: secrets.password)
                        case .unknown: code = .lockStateUnknown
                        case .locked:
                            switch await typePassword(secrets.password) {
                            case .skippedAlreadyUnlocked: code = .alreadyUnlocked
                            case .skippedLockStateUnknown: code = .lockStateUnknown
                            case .postFailed: code = .postFailed
                            case .typed:
                                let unlocked: Bool? = await poll { lockState.currentState() == .unlocked ? true : nil }
                                code = unlocked == true ? .verified : .notVerified
                            }
                        }
                    } else {
                        code = .inputNotPermitted
                    }
                } else {
                    code = .invalidSignature
                }
            } else {
                code = .notConfigured
            }
        } else {
            code = .invalidSignature
        }

        guard liveConnections.contains(id) else { return (code, nil) }
        let nextChallenge = randomChallenge()
        challenges[id] = nextChallenge
        return (code, nextChallenge)
    }
}

extension Data {
    func constantTimeEquals(_ other: Data) -> Bool {
        guard count == other.count else { return false }
        return zip(self, other).reduce(UInt8(0)) { result, pair in
            result | (pair.0 ^ pair.1)
        } == 0
    }
}
