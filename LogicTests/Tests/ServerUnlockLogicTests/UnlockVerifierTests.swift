import Foundation
import Testing
@testable import ServerUnlockLogic

private final class ScriptedState: SessionLockStateProviding, @unchecked Sendable {
    var states: [SessionLockState]
    var fallback: SessionLockState
    init(_ states: [SessionLockState], fallback: SessionLockState = .locked) {
        self.states = states
        self.fallback = fallback
    }
    func currentState() -> SessionLockState {
        states.isEmpty ? fallback : states.removeFirst()
    }
}

private final class ScriptedDetector: AuthDialogDetecting, @unchecked Sendable {
    private let lock = NSLock()
    private var queue: [AuthDialogScan]
    private var last: AuthDialogScan
    init(_ scans: [AuthDialogScan] = [], fallback: AuthDialogScan = .windows([])) {
        queue = scans
        last = fallback
    }
    func script(_ scans: [AuthDialogScan], fallback: AuthDialogScan? = nil) {
        lock.lock(); defer { lock.unlock() }
        queue = scans
        if let fallback { last = fallback }
    }
    func scan() -> AuthDialogScan {
        lock.lock(); defer { lock.unlock() }
        if !queue.isEmpty { last = queue.removeFirst() }
        return last
    }
}

private final class TyperRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var _result: AuthDialogTypingResult = .typed(windowID: 7)
    private var _passwords: [String] = []
    var result: AuthDialogTypingResult {
        get { lock.lock(); defer { lock.unlock() }; return _result }
        set { lock.lock(); defer { lock.unlock() }; _result = newValue }
    }
    var passwords: [String] { lock.lock(); defer { lock.unlock() }; return _passwords }
    func type(_ p: String) -> AuthDialogTypingResult {
        lock.lock(); defer { lock.unlock() }
        _passwords.append(p)
        return _result
    }
}

private func dialog(_ id: UInt32) -> AuthDialogWindow {
    AuthDialogWindow(windowID: id, ownerPID: 100, bounds: CGRect(x: 0, y: 0, width: 300, height: 200))
}

@MainActor
private final class Fixture {
    let token = Data(repeating: 7, count: 32)
    let password = "secret"
    let state: ScriptedState
    var typerResult: UnlockTypingResult = .typed
    var typedPasswords: [String] = []
    var permitted = true
    var secretMode = 0 // 0: present, 1: nil, 2: throws
    let detector: ScriptedDetector
    let recorder = TyperRecorder()
    var dialogTyperResult: AuthDialogTypingResult {
        get { recorder.result }
        set { recorder.result = newValue }
    }
    var dialogPasswords: [String] { recorder.passwords }
    var authDialogCooldown: TimeInterval = 60
    var elapsed: TimeInterval = 0
    var challengeNumber: UInt8 = 0
    lazy var verifier = UnlockVerifier<Int>(
        loadSecrets: {
            if self.secretMode == 2 { throw FixtureError.failure }
            if self.secretMode == 1 { return nil }
            return UnlockSecrets(token: self.token, password: self.password)
        },
        inputPermitted: { self.permitted },
        lockState: state,
        typePassword: { password in
            self.typedPasswords.append(password)
            return self.typerResult
        },
        authDialog: detector,
        submitAuthDialog: { [recorder] password in recorder.type(password) },
        randomChallenge: {
            self.challengeNumber &+= 1
            return Data(repeating: self.challengeNumber, count: 32)
        },
        sleep: { interval in self.elapsed += interval },
        now: { Date(timeIntervalSince1970: self.elapsed) },
        authDialogCooldown: authDialogCooldown
    )
    init(_ states: [SessionLockState] = [.locked, .unlocked], fallback: SessionLockState = .locked,
         scans: [AuthDialogScan] = [], scanFallback: AuthDialogScan = .windows([]),
         cooldown: TimeInterval = 60) {
        state = ScriptedState(states, fallback: fallback)
        detector = ScriptedDetector(scans, fallback: scanFallback)
        authDialogCooldown = cooldown
    }
    func signature(_ challenge: Data, token: Data? = nil) -> Data {
        UnlockWire.signature(challenge: challenge, token: token ?? self.token)
    }
}
private enum FixtureError: Error { case failure }

@Test @MainActor func verifiedAndReplay() async {
    let f = Fixture()
    let challenge = f.verifier.issueChallenge(for: 1)
    let signature = f.signature(challenge)
    let first = await f.verifier.handleUnlock(signature: signature, from: 1)
    #expect(first.code == .verified)
    #expect(first.nextChallenge != challenge)
    #expect(f.typedPasswords == ["secret"])
    let replay = await f.verifier.handleUnlock(signature: signature, from: 1)
    #expect(replay.code == .invalidSignature)
    #expect(f.typedPasswords.count == 1)
    #expect(!f.verifier.isInProgress)
}

@Test @MainActor func invalidSignaturesAndUnknownID() async {
    let f = Fixture()
    let challenge = f.verifier.issueChallenge(for: 1)
    let wrong = await f.verifier.handleUnlock(signature: f.signature(challenge, token: Data(repeating: 8, count: 32)), from: 1)
    #expect(wrong.code == .invalidSignature)
    let unknown = await f.verifier.handleUnlock(signature: f.signature(challenge), from: 999)
    #expect(unknown.code == .invalidSignature)
    #expect(unknown.nextChallenge == nil)
    #expect(f.typedPasswords.isEmpty)
    #expect(!f.verifier.isInProgress)
}

@Test @MainActor func prechecks() async {
    for (state, permitted, expected) in [
        (SessionLockState.locked, false, UnlockResultCode.inputNotPermitted),
        (.unlocked, true, .alreadyUnlocked),
        (.unknown, true, .lockStateUnknown)
    ] {
        let f = Fixture([state])
        f.permitted = permitted
        let c = f.verifier.issueChallenge(for: 1)
        let result = await f.verifier.handleUnlock(signature: f.signature(c), from: 1)
        #expect(result.code == expected)
        #expect(f.typedPasswords.isEmpty)
        #expect(!f.verifier.isInProgress)
    }
}

@Test @MainActor func typingOutcomes() async {
    for (typing, expected) in [
        (UnlockTypingResult.skippedAlreadyUnlocked, UnlockResultCode.alreadyUnlocked),
        (.skippedLockStateUnknown, .lockStateUnknown),
        (.postFailed, .postFailed)
    ] {
        let f = Fixture()
        f.typerResult = typing
        let c = f.verifier.issueChallenge(for: 1)
        let result = await f.verifier.handleUnlock(signature: f.signature(c), from: 1)
        #expect(result.code == expected)
        #expect(f.typedPasswords == ["secret"])
        #expect(!f.verifier.isInProgress)
    }
}

@Test @MainActor func deadlineAndMissingSecrets() async {
    let f = Fixture([.locked], fallback: .locked)
    let c = f.verifier.issueChallenge(for: 1)
    let result = await f.verifier.handleUnlock(signature: f.signature(c), from: 1)
    #expect(result.code == .notVerified)
    #expect(f.elapsed >= 6)
    #expect(f.typedPasswords == ["secret"])
    #expect(!f.verifier.isInProgress)
    for mode in [1, 2] {
        let missing = Fixture()
        missing.secretMode = mode
        let c = missing.verifier.issueChallenge(for: 1)
        let result = await missing.verifier.handleUnlock(signature: missing.signature(c), from: 1)
        #expect(result.code == .notConfigured)
        #expect(missing.typedPasswords.isEmpty)
        #expect(!missing.verifier.isInProgress)
    }
}

@Test @MainActor func nextChallengeIsAccepted() async {
    let f = Fixture([.unlocked, .unlocked])
    let first = f.verifier.issueChallenge(for: 1)
    let result1 = await f.verifier.handleUnlock(signature: f.signature(first), from: 1)
    #expect(result1.code == .alreadyUnlocked)
    let next = try! #require(result1.nextChallenge)
    #expect(next != first)
    let result2 = await f.verifier.handleUnlock(signature: f.signature(next), from: 1)
    #expect(result2.code == .alreadyUnlocked)
    #expect(!f.verifier.isInProgress)
}

@MainActor
private final class Suspension {
    var continuation: CheckedContinuation<UnlockTypingResult, Never>?
    var calls = 0
    func type(_ password: String) async -> UnlockTypingResult {
        calls += 1
        return await withCheckedContinuation { continuation = $0 }
    }
    func finish() {
        continuation?.resume(returning: .typed)
        continuation = nil
    }
}

@Test @MainActor func concurrencyAndDisconnect() async {
    let state = ScriptedState([.locked, .unlocked, .locked, .unlocked])
    let suspension = Suspension()
    var number: UInt8 = 0
    let token = Data(repeating: 7, count: 32)
    let verifier = UnlockVerifier<Int>(
        loadSecrets: { UnlockSecrets(token: token, password: "secret") },
        inputPermitted: { true }, lockState: state,
        typePassword: { password in await suspension.type(password) },
        authDialog: ScriptedDetector(),
        submitAuthDialog: { _ in .noDialog },
        randomChallenge: { number &+= 1; return Data(repeating: number, count: 32) },
        sleep: { _ in }, now: { Date() }
    )
    let c1 = verifier.issueChallenge(for: 1)
    let c2 = verifier.issueChallenge(for: 2)
    let sig1 = UnlockWire.signature(challenge: c1, token: token)
    let sig2 = UnlockWire.signature(challenge: c2, token: token)
    let first = Task { await verifier.handleUnlock(signature: sig1, from: 1) }
    while suspension.continuation == nil { await Task.yield() }
    #expect(verifier.isInProgress)
    let concurrent = await verifier.handleUnlock(signature: sig2, from: 2)
    #expect(concurrent.code == .inProgress)
    #expect(concurrent.nextChallenge == nil)
    let replay = await verifier.handleUnlock(signature: sig1, from: 1)
    #expect(replay.code == .inProgress)
    #expect(suspension.calls == 1)
    verifier.removeConnection(1)
    #expect(verifier.isInProgress)
    suspension.finish()
    let completed = await first.value
    #expect(completed.code == .verified)
    #expect(completed.nextChallenge == nil)
    #expect(!verifier.isInProgress)
    let second = Task { await verifier.handleUnlock(signature: sig2, from: 2) }
    while suspension.continuation == nil { await Task.yield() }
    #expect(suspension.calls == 2)
    suspension.finish()
    let secondResult = await second.value
    #expect(secondResult.code == .verified)
    #expect(!verifier.isInProgress)
    let removedReplay = await verifier.handleUnlock(signature: sig1, from: 1)
    #expect(removedReplay.code == .invalidSignature)
    #expect(removedReplay.nextChallenge == nil)
    #expect(!verifier.isInProgress)
}

// MARK: - Auth dialog path

@MainActor
private func attempt(_ f: Fixture, id: Int = 1) async -> UnlockResultCode {
    let c = f.verifier.issueChallenge(for: id)
    return await f.verifier.handleUnlock(signature: f.signature(c), from: id).code
}

private let w7 = AuthDialogScan.windows([dialog(7)])
private let none = AuthDialogScan.windows([])

@Test @MainActor func dialogClosedIsSubmitted() async {
    let f = Fixture([.unlocked], fallback: .unlocked, scans: [w7, none, none])
    #expect(await attempt(f) == .authDialogSubmitted)
    #expect(f.dialogPasswords == ["secret"])
    #expect(f.typedPasswords.isEmpty)
}

@Test @MainActor func dialogPersistsNotVerified() async {
    let f = Fixture([.unlocked], fallback: .unlocked, scanFallback: w7)
    #expect(await attempt(f) == .notVerified)
    #expect(f.elapsed >= 6)
    #expect(f.dialogPasswords == ["secret"])
}

@Test @MainActor func dialogGoneButLockedNotVerifiedEarly() async {
    let f = Fixture([.unlocked, .locked], fallback: .locked, scans: [w7, none, none])
    #expect(await attempt(f) == .notVerified)
    #expect(f.elapsed < 6)
}

@Test @MainActor func dialogReplacedNotVerified() async {
    let f = Fixture([.unlocked], fallback: .unlocked, scans: [w7, .windows([dialog(9)])], scanFallback: .windows([dialog(9)]))
    #expect(await attempt(f) == .notVerified)
    #expect(f.dialogPasswords == ["secret"])
}

@Test @MainActor func scansFailingDuringVerificationNotVerified() async {
    let f = Fixture([.unlocked], fallback: .unlocked, scans: [w7], scanFallback: .failed)
    #expect(await attempt(f) == .notVerified)
    #expect(f.elapsed >= 6)
}

@Test @MainActor func initialScanFailedRefused() async {
    let f = Fixture([.unlocked], fallback: .unlocked, scans: [.failed])
    #expect(await attempt(f) == .authDialogRefused)
    #expect(f.dialogPasswords.isEmpty)
    #expect(f.typedPasswords.isEmpty)
}

@Test @MainActor func typerResultMapping() async {
    let cases: [(AuthDialogTypingResult, UnlockResultCode)] = [
        (.noDialog, .alreadyUnlocked),
        (.sessionNotUnlocked, .lockStateUnknown),
        (.multipleDialogs, .authDialogRefused),
        (.detectionFailed, .authDialogRefused),
        (.notFocused, .authDialogRefused),
        (.notPasswordField, .authDialogRefused),
        (.fieldNotEmpty, .authDialogRefused),
        (.fieldContentUnknown, .authDialogRefused),
        (.accessibilityError(1), .authDialogRefused),
        (.interrupted(charactersPosted: 2), .authDialogInterrupted),
        (.postFailed, .postFailed),
    ]
    for (typing, expected) in cases {
        let f = Fixture([.unlocked], fallback: .unlocked, scanFallback: w7)
        f.dialogTyperResult = typing
        #expect(await attempt(f) == expected)
        #expect(f.dialogPasswords == ["secret"])
        #expect(f.typedPasswords.isEmpty)
    }
}

@Test @MainActor func cooldownAfterNotVerified() async {
    let f = Fixture([.unlocked], fallback: .unlocked, scanFallback: w7)
    #expect(await attempt(f) == .notVerified)
    #expect(f.dialogPasswords.count == 1)
    f.elapsed += 30
    #expect(await attempt(f) == .authDialogRetryBlocked)
    #expect(f.dialogPasswords.count == 1)
    f.elapsed += 61
    #expect(await attempt(f) == .notVerified)
    #expect(f.dialogPasswords.count == 2)
}

@Test @MainActor func nonSubmissionsDoNotStartCooldown() async {
    for typing in [AuthDialogTypingResult.interrupted(charactersPosted: 1), .postFailed, .notFocused] {
        let f = Fixture([.unlocked], fallback: .unlocked, scanFallback: w7)
        f.dialogTyperResult = typing
        _ = await attempt(f)
        _ = await attempt(f)
        #expect(f.dialogPasswords.count == 2)
    }
    let f = Fixture([.unlocked], fallback: .unlocked, scans: [.failed, w7])
    #expect(await attempt(f) == .authDialogRefused)
    #expect(await attempt(f) == .notVerified)
    #expect(f.dialogPasswords.count == 1)
}

@Test @MainActor func successClearsCooldown() async {
    let f = Fixture([.unlocked], fallback: .unlocked, scanFallback: w7)
    #expect(await attempt(f) == .notVerified)
    f.elapsed += 61
    f.detector.script([w7, none, none], fallback: none)
    #expect(await attempt(f) == .authDialogSubmitted)
    f.detector.script([], fallback: w7)
    #expect(await attempt(f) == .notVerified)
    #expect(f.dialogPasswords.count == 3)
}

@Test @MainActor func cooldownDoesNotAffectLockScreenPath() async {
    let f = Fixture([.unlocked], fallback: .unlocked, scanFallback: w7)
    #expect(await attempt(f) == .notVerified)
    f.state.states = [.locked, .unlocked]
    f.detector.script([], fallback: none)
    #expect(await attempt(f) == .verified)
    #expect(f.typedPasswords == ["secret"])
    #expect(f.dialogPasswords.count == 1)
}

@Test @MainActor func lockedWithDialogUsesLockScreenPathOnly() async {
    let f = Fixture([.locked, .unlocked], scanFallback: w7)
    #expect(await attempt(f) == .verified)
    #expect(f.typedPasswords == ["secret"])
    #expect(f.dialogPasswords.isEmpty)
}

@Test @MainActor func inputNotPermittedWithDialogTypesNothing() async {
    let f = Fixture([.unlocked], fallback: .unlocked, scanFallback: w7)
    f.permitted = false
    #expect(await attempt(f) == .inputNotPermitted)
    #expect(f.typedPasswords.isEmpty)
    #expect(f.dialogPasswords.isEmpty)
}
