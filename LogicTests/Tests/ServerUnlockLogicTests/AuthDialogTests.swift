import Foundation
import Testing
@testable import ServerUnlockLogic

// MARK: - Helpers

private let display = CGRect(x: 0, y: 0, width: 1920, height: 1080)

private func validWindow(number: Int = 10, pid: Int = 100) -> [String: Any] {
    [
        "kCGWindowOwnerName": "SecurityAgent",
        "kCGWindowIsOnscreen": true,
        "kCGWindowAlpha": 1.0,
        "kCGWindowLayer": 0,
        "kCGWindowBounds": ["X": 400.0, "Y": 300.0, "Width": 400.0, "Height": 250.0] as [String: Any],
        "kCGWindowOwnerPID": pid,
        "kCGWindowNumber": number,
    ]
}

private func win(_ id: UInt32, pid: Int32 = 100) -> AuthDialogWindow {
    AuthDialogWindow(windowID: id, ownerPID: pid, bounds: CGRect(x: 400, y: 300, width: 400, height: 250))
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func hit() { lock.lock(); n += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return n }
}

private final class Script<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [T]
    private var last: T
    let calls = Counter()
    init(_ items: [T], fallback: T) { self.items = items; last = fallback }
    func next() -> T {
        calls.hit()
        lock.lock(); defer { lock.unlock() }
        if !items.isEmpty { last = items.removeFirst() }
        return last
    }
}

private func gate(
    lock: [SessionLockState] = [.unlocked],
    scan: [AuthDialogScan] = [.windows([win(7)])],
    focus: [AuthDialogFocus] = [.passwordField(.empty)]
) -> (AuthDialogGate, Script<SessionLockState>, Script<AuthDialogScan>, Script<AuthDialogFocus>) {
    let l = Script(lock, fallback: lock.last ?? .unlocked)
    let s = Script(scan, fallback: scan.last ?? .windows([]))
    let f = Script(focus, fallback: focus.last ?? .otherElement)
    return (AuthDialogGate(lockState: { l.next() }, scan: { s.next() }, focus: { _ in f.next() }), l, s, f)
}

// MARK: - (a) qualifying

@Test func validWindowQualifies() {
    let r = AuthDialogWindowFilter.qualifying(in: [validWindow()], displays: [display])
    #expect(r.count == 1)
    #expect(r[0].windowID == 10)
    #expect(r[0].ownerPID == 100)
}

@Test func eachFilterFailsIndividually() {
    let mutations: [(String, (inout [String: Any]) -> Void)] = [
        ("owner", { $0["kCGWindowOwnerName"] = "Finder" }),
        ("onscreen missing", { $0["kCGWindowIsOnscreen"] = nil }),
        ("onscreen false", { $0["kCGWindowIsOnscreen"] = false }),
        ("alpha missing", { $0["kCGWindowAlpha"] = nil }),
        ("alpha 0", { $0["kCGWindowAlpha"] = 0.0 }),
        ("layer missing", { $0["kCGWindowLayer"] = nil }),
        ("layer -1", { $0["kCGWindowLayer"] = -1 }),
        ("small", { $0["kCGWindowBounds"] = ["X": 400.0, "Y": 300.0, "Width": 40.0, "Height": 40.0] as [String: Any] }),
        ("offscreen", { $0["kCGWindowBounds"] = ["X": 5000.0, "Y": 300.0, "Width": 400.0, "Height": 250.0] as [String: Any] }),
        ("pid missing", { $0["kCGWindowOwnerPID"] = nil }),
        ("number missing", { $0["kCGWindowNumber"] = nil }),
    ]
    for (name, mutate) in mutations {
        var w = validWindow()
        mutate(&w)
        #expect(AuthDialogWindowFilter.qualifying(in: [w], displays: [display]).isEmpty, "\(name)")
    }
}

@Test func emptyListReturnsNothing() {
    #expect(AuthDialogWindowFilter.qualifying(in: [], displays: [display]).isEmpty)
}

@Test func hiddenSecurityAgentPlusFinderReturnsNothing() {
    var hidden = validWindow()
    hidden["kCGWindowIsOnscreen"] = false
    var finder = validWindow(number: 11)
    finder["kCGWindowOwnerName"] = "Finder"
    #expect(AuthDialogWindowFilter.qualifying(in: [hidden, finder], displays: [display]).isEmpty)
}

@Test func twoQualifyingWindowsReturnBoth() {
    let r = AuthDialogWindowFilter.qualifying(in: [validWindow(number: 10), validWindow(number: 11)], displays: [display])
    #expect(r.map(\.windowID) == [10, 11])
}

// MARK: - (b) framesMatch

@Test func framesMatchTolerance() {
    let cg = CGRect(x: 100, y: 100, width: 300, height: 200)
    #expect(AuthDialogWindowFilter.framesMatch(CGRect(x: 101, y: 99, width: 301, height: 199), cg))
    #expect(!AuthDialogWindowFilter.framesMatch(CGRect(x: 102, y: 100, width: 300, height: 200), cg))
    #expect(!AuthDialogWindowFilter.framesMatch(CGRect(x: 100, y: 100, width: 300, height: 202), cg))
}

// MARK: - (c) initialCheck

@Test func nonUnlockedNeverScansOrFocuses() {
    for state in [SessionLockState.locked, .unknown] {
        let (g, _, s, f) = gate(lock: [state])
        #expect(g.initialCheck() == .failure(.sessionNotUnlocked))
        #expect(s.calls.count == 0)
        #expect(f.calls.count == 0)
    }
}

@Test func initialCheckScanOutcomes() {
    var (g, _, _, f) = gate(scan: [.failed])
    #expect(g.initialCheck() == .failure(.detectionFailed))
    #expect(f.calls.count == 0)
    (g, _, _, f) = gate(scan: [.windows([])])
    #expect(g.initialCheck() == .failure(.noDialog))
    #expect(f.calls.count == 0)
    (g, _, _, f) = gate(scan: [.windows([win(7), win(8)])])
    #expect(g.initialCheck() == .failure(.multipleDialogs))
    #expect(f.calls.count == 0)
}

@Test func initialCheckFocusOutcomes() {
    let cases: [(AuthDialogFocus, AuthDialogTypingResult)] = [
        (.otherApplication, .notFocused),
        (.otherWindow, .notFocused),
        (.otherElement, .notPasswordField),
        (.accessibilityError(-25204), .accessibilityError(-25204)),
        (.passwordField(.nonEmpty), .fieldNotEmpty),
        (.passwordField(.unknown), .fieldContentUnknown),
    ]
    for (focus, expected) in cases {
        let (g, _, _, _) = gate(focus: [focus])
        #expect(g.initialCheck() == .failure(expected))
    }
    let (g, _, _, _) = gate()
    #expect(g.initialCheck() == .success(win(7)))
}

// MARK: - (d) recheck

@Test func recheckCases() {
    let target = win(7)
    var (g, _, _, _) = gate(lock: [.locked])
    #expect(!g.recheck(target: target))
    (g, _, _, _) = gate(scan: [.failed])
    #expect(!g.recheck(target: target))
    (g, _, _, _) = gate(scan: [.windows([win(9)])])
    #expect(!g.recheck(target: target))
    (g, _, _, _) = gate(scan: [.windows([win(7), win(8)])])
    #expect(!g.recheck(target: target))
    for focus in [AuthDialogFocus.otherApplication, .otherWindow, .otherElement, .accessibilityError(1)] {
        (g, _, _, _) = gate(focus: [focus])
        #expect(!g.recheck(target: target))
    }
    for content in [AuthDialogFieldContent.empty, .nonEmpty, .unknown] {
        (g, _, _, _) = gate(focus: [.passwordField(content)])
        #expect(g.recheck(target: target))
    }
}

// MARK: - (e) GuardedPasswordPoster

private final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private var chars: [Character] = []
    private var returns = 0
    private var rechecks = 0
    func char(_ c: Character) { lock.lock(); chars.append(c); lock.unlock() }
    func ret() { lock.lock(); returns += 1; lock.unlock() }
    func recheck() -> Int { lock.lock(); defer { lock.unlock() }; rechecks += 1; return rechecks }
    var posted: String { lock.lock(); defer { lock.unlock() }; return String(chars) }
    var returnCount: Int { lock.lock(); defer { lock.unlock() }; return returns }
    var recheckCount: Int { lock.lock(); defer { lock.unlock() }; return rechecks }
}

private func poster(_ r: Recorder, failRecheckAt k: Int? = nil, failCharAt: Int? = nil) -> GuardedPasswordPoster {
    GuardedPasswordPoster(
        postCharacter: { c in
            if let failCharAt, r.posted.count == failCharAt { return false }
            r.char(c)
            return true
        },
        postReturn: { r.ret(); return true },
        sleep: { _ in },
        recheck: { r.recheck() != k }
    )
}

@Test func posterAbortsAtFirstRecheck() {
    let r = Recorder()
    #expect(poster(r, failRecheckAt: 1).post("secret") == .aborted(charactersPosted: 0))
    #expect(r.posted.isEmpty)
    #expect(r.returnCount == 0)
}

@Test func posterAbortsMidTyping() {
    let r = Recorder()
    #expect(poster(r, failRecheckAt: 3).post("secret") == .aborted(charactersPosted: 2))
    #expect(r.posted == "se")
    #expect(r.returnCount == 0)
}

@Test func posterAbortsOnFinalPreReturnRecheck() {
    let r = Recorder()
    #expect(poster(r, failRecheckAt: 7).post("secret") == .aborted(charactersPosted: 6))
    #expect(r.posted == "secret")
    #expect(r.returnCount == 0)
}

@Test func posterPostFailure() {
    let r = Recorder()
    #expect(poster(r, failCharAt: 3).post("secret") == .postFailed(charactersPosted: 3))
    #expect(r.returnCount == 0)
}

@Test func posterHappyPath() {
    let r = Recorder()
    #expect(poster(r).post("secret") == .posted)
    #expect(r.posted == "secret")
    #expect(r.returnCount == 1)
    #expect(r.recheckCount == 7)
}

// MARK: - (f) Sequencer

private func sequencer(
    lock: [SessionLockState] = [.unlocked],
    scan: [AuthDialogScan] = [.windows([win(7)])],
    focus: [AuthDialogFocus] = [.passwordField(.empty)],
    failCharAt: Int? = nil,
    _ rec: Recorder
) -> AuthDialogKeystrokeSequencer {
    let (g, _, _, _) = gate(lock: lock, scan: scan, focus: focus)
    return AuthDialogKeystrokeSequencer(gate: g, makePoster: { recheck in
        GuardedPasswordPoster(
            postCharacter: { c in
                if let failCharAt, rec.posted.count == failCharAt { return false }
                rec.char(c)
                return true
            },
            postReturn: { rec.ret(); return true },
            sleep: { _ in },
            recheck: recheck
        )
    })
}

// Gate call order for "secret": initialCheck consumes lock#1, scan#1, focus#1; each recheck
// then consumes one lock/scan/focus entry (7 rechecks: 6 chars + pre-Return).

@Test func sequencerLockFlipsAfterTwoChars() {
    let r = Recorder()
    // lock#1 initial, rechecks #1,#2 pass (types 2), recheck #3 locked.
    let s = sequencer(lock: [.unlocked, .unlocked, .unlocked, .locked], r)
    #expect(s.run(password: "secret") == .interrupted(charactersPosted: 2))
    #expect(r.returnCount == 0)
}

@Test func sequencerFocusMovesMidTyping() {
    let r = Recorder()
    let s = sequencer(focus: [.passwordField(.empty), .passwordField(.empty), .otherApplication], r)
    #expect(s.run(password: "secret") == .interrupted(charactersPosted: 1))
    #expect(r.returnCount == 0)
}

@Test func sequencerWindowIDChangesMidTyping() {
    let r = Recorder()
    let s = sequencer(scan: [.windows([win(7)]), .windows([win(7)]), .windows([win(8)])], r)
    #expect(s.run(password: "secret") == .interrupted(charactersPosted: 1))
    #expect(r.returnCount == 0)
}

@Test func sequencerSecondDialogBeforeReturn() {
    let r = Recorder()
    // scan#1 initial, #2..#7 chars, #8 pre-Return.
    let ok = AuthDialogScan.windows([win(7)])
    let s = sequencer(scan: [ok, ok, ok, ok, ok, ok, ok, .windows([win(7), win(8)])], r)
    #expect(s.run(password: "secret") == .interrupted(charactersPosted: 6))
    #expect(r.posted == "secret")
    #expect(r.returnCount == 0)
}

@Test func sequencerHappyPath() {
    let r = Recorder()
    #expect(sequencer(r).run(password: "secret") == .typed(windowID: 7))
    #expect(r.posted == "secret")
    #expect(r.returnCount == 1)
}

@Test func sequencerEmptyPassword() {
    let r = Recorder()
    #expect(sequencer(r).run(password: "") == .postFailed)
    #expect(r.posted.isEmpty)
}

@Test func sequencerPostFailedMapping() {
    let r0 = Recorder()
    #expect(sequencer(failCharAt: 0, r0).run(password: "secret") == .postFailed)
    let r3 = Recorder()
    #expect(sequencer(failCharAt: 3, r3).run(password: "secret") == .interrupted(charactersPosted: 3))
    #expect(r3.returnCount == 0)
}

@Test func sequencerInitialRefusalPostsNothing() {
    let r = Recorder()
    #expect(sequencer(focus: [.otherElement], r).run(password: "secret") == .notPasswordField)
    #expect(r.posted.isEmpty)
}

// MARK: - (g) AuthDialogCloseTracker

private let present = AuthDialogScan.windows([win(7)])
private let absent = AuthDialogScan.windows([])

@Test func trackerTargetPresentPending() {
    var t = AuthDialogCloseTracker(target: 7)
    #expect(t.observe(lockState: .unlocked, scan: present) == .pending)
    #expect(t.observe(lockState: .unlocked, scan: present) == .pending)
}

@Test func trackerClosedAfterTwoAbsent() {
    var t = AuthDialogCloseTracker(target: 7)
    #expect(t.observe(lockState: .unlocked, scan: absent) == .pending)
    #expect(t.observe(lockState: .unlocked, scan: absent) == .closed)
}

@Test func trackerFailedResetsStreak() {
    var t = AuthDialogCloseTracker(target: 7)
    #expect(t.observe(lockState: .unlocked, scan: absent) == .pending)
    #expect(t.observe(lockState: .unlocked, scan: .failed) == .pending)
    #expect(t.observe(lockState: .unlocked, scan: absent) == .pending)
    #expect(t.observe(lockState: .unlocked, scan: absent) == .closed)
}

@Test func trackerReplaced() {
    var t = AuthDialogCloseTracker(target: 7)
    #expect(t.observe(lockState: .unlocked, scan: absent) == .pending)
    #expect(t.observe(lockState: .unlocked, scan: .windows([win(9)])) == .replaced)
}

@Test func trackerLockChangeImmediate() {
    for state in [SessionLockState.locked, .unknown] {
        var t = AuthDialogCloseTracker(target: 7)
        #expect(t.observe(lockState: state, scan: absent) == .lockChanged)
    }
}

@Test func trackerFailedAloneNeverCloses() {
    var t = AuthDialogCloseTracker(target: 7)
    for _ in 0..<20 {
        #expect(t.observe(lockState: .unlocked, scan: .failed) == .pending)
    }
}
