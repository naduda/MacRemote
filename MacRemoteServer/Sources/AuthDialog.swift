import Foundation

struct AuthDialogWindow: Equatable, Sendable {
    let windowID: UInt32
    let ownerPID: Int32
    let bounds: CGRect
}

enum AuthDialogScan: Equatable, Sendable {
    case windows([AuthDialogWindow])
    case failed
}

protocol AuthDialogDetecting: Sendable {
    func scan() -> AuthDialogScan
}

enum AuthDialogWindowFilter {
    // NEED DEVICE VERIFICATION on macOS 27: owner name and window layer of the auth dialog.
    static let ownerNames: Set<String> = ["SecurityAgent"]
    static let minimumSide: CGFloat = 50

    static func qualifying(in windows: [[String: Any]], displays: [CGRect]) -> [AuthDialogWindow] {
        var result: [AuthDialogWindow] = []
        for w in windows {
            guard let owner = w["kCGWindowOwnerName"] as? String, ownerNames.contains(owner) else { continue }
            guard let onscreen = w["kCGWindowIsOnscreen"] as? Bool, onscreen else { continue }
            guard let alpha = (w["kCGWindowAlpha"] as? NSNumber)?.doubleValue, alpha > 0 else { continue }
            guard let layer = (w["kCGWindowLayer"] as? NSNumber)?.intValue, layer >= 0 else { continue }
            guard let b = w["kCGWindowBounds"] as? [String: Any],
                  let x = (b["X"] as? NSNumber)?.doubleValue,
                  let y = (b["Y"] as? NSNumber)?.doubleValue,
                  let width = (b["Width"] as? NSNumber)?.doubleValue,
                  let height = (b["Height"] as? NSNumber)?.doubleValue else { continue }
            let rect = CGRect(x: x, y: y, width: width, height: height)
            guard rect.width >= minimumSide, rect.height >= minimumSide else { continue }
            guard displays.contains(where: { !$0.intersection(rect).isNull && !$0.intersection(rect).isEmpty }) else { continue }
            guard let pid = (w["kCGWindowOwnerPID"] as? NSNumber)?.int64Value, pid > 0, pid <= Int64(Int32.max) else { continue }
            guard let num = (w["kCGWindowNumber"] as? NSNumber)?.int64Value, num > 0, num <= Int64(UInt32.max) else { continue }
            result.append(AuthDialogWindow(windowID: UInt32(num), ownerPID: Int32(pid), bounds: rect))
        }
        return result
    }

    /// AX and CG both use global top-left coordinates.
    static func framesMatch(_ ax: CGRect, _ cg: CGRect, tolerance: CGFloat = 1) -> Bool {
        abs(ax.origin.x - cg.origin.x) <= tolerance
            && abs(ax.origin.y - cg.origin.y) <= tolerance
            && abs(ax.size.width - cg.size.width) <= tolerance
            && abs(ax.size.height - cg.size.height) <= tolerance
    }
}

enum AuthDialogFieldContent: Equatable, Sendable { case empty, nonEmpty, unknown }

enum AuthDialogFocus: Equatable, Sendable {
    case passwordField(AuthDialogFieldContent)
    case otherElement
    case otherWindow
    case otherApplication
    case accessibilityError(Int32)
}

typealias AuthDialogFocusProbe = @Sendable (AuthDialogWindow) -> AuthDialogFocus

enum AuthDialogTypingResult: Error, Equatable, Sendable {
    case typed(windowID: UInt32)
    case noDialog, multipleDialogs, detectionFailed
    case sessionNotUnlocked, notFocused, notPasswordField
    case fieldNotEmpty, fieldContentUnknown
    case accessibilityError(Int32)
    case interrupted(charactersPosted: Int)
    case postFailed
}

struct AuthDialogGate: Sendable {
    /// Fail closed on unknown field content; revisit after device verification.
    static let requireKnownEmptyField = true

    let lockState: @Sendable () -> SessionLockState
    let scan: @Sendable () -> AuthDialogScan
    let focus: @Sendable (AuthDialogWindow) -> AuthDialogFocus

    func initialCheck() -> Result<AuthDialogWindow, AuthDialogTypingResult> {
        guard lockState() == .unlocked else { return .failure(.sessionNotUnlocked) }
        let windows: [AuthDialogWindow]
        switch scan() {
        case .failed: return .failure(.detectionFailed)
        case .windows(let w): windows = w
        }
        if windows.isEmpty { return .failure(.noDialog) }
        if windows.count > 1 { return .failure(.multipleDialogs) }
        let window = windows[0]
        switch focus(window) {
        case .otherApplication, .otherWindow: return .failure(.notFocused)
        case .otherElement: return .failure(.notPasswordField)
        case .accessibilityError(let e): return .failure(.accessibilityError(e))
        case .passwordField(.nonEmpty): return .failure(.fieldNotEmpty)
        case .passwordField(.unknown): return .failure(.fieldContentUnknown)
        case .passwordField(.empty): return .success(window)
        }
    }

    func recheck(target: AuthDialogWindow) -> Bool {
        guard lockState() == .unlocked else { return false }
        guard case .windows(let w) = scan(), w.count == 1, w[0].windowID == target.windowID else { return false }
        if case .passwordField = focus(w[0]) { return true }
        return false
    }
}

struct GuardedPasswordPoster: Sendable {
    let postCharacter: @Sendable (Character) -> Bool
    let postReturn: @Sendable () -> Bool
    let sleep: @Sendable (TimeInterval) -> Void
    let recheck: @Sendable () -> Bool

    let characterDownUp: TimeInterval = 0.015
    let characterGap: TimeInterval = 0.025
    let returnDelay: TimeInterval = 0.1

    enum PosterOutcome: Equatable, Sendable {
        case posted
        case aborted(charactersPosted: Int)
        case postFailed(charactersPosted: Int)
    }

    func post(_ password: String) -> PosterOutcome {
        var count = 0
        for ch in password {
            guard recheck() else { return .aborted(charactersPosted: count) }
            guard postCharacter(ch) else { return .postFailed(charactersPosted: count) }
            count += 1
            sleep(characterGap)
        }
        sleep(returnDelay)
        guard recheck() else { return .aborted(charactersPosted: count) }
        guard postReturn() else { return .postFailed(charactersPosted: count) }
        return .posted
    }
}

typealias PosterOutcome = GuardedPasswordPoster.PosterOutcome

struct AuthDialogKeystrokeSequencer: Sendable {
    let gate: AuthDialogGate
    let makePoster: @Sendable (_ recheck: @escaping @Sendable () -> Bool) -> GuardedPasswordPoster

    func run(password: String) -> AuthDialogTypingResult {
        guard !password.isEmpty else { return .postFailed }
        let w: AuthDialogWindow
        switch gate.initialCheck() {
        case .failure(let r): return r
        case .success(let win): w = win
        }
        let gate = self.gate
        let poster = makePoster { gate.recheck(target: w) }
        switch poster.post(password) {
        case .posted: return .typed(windowID: w.windowID)
        case .aborted(let n): return .interrupted(charactersPosted: n)
        case .postFailed(let n): return n == 0 ? .postFailed : .interrupted(charactersPosted: n)
        }
    }
}

struct AuthDialogCloseTracker: Sendable {
    let target: UInt32
    private(set) var absentStreak = 0
    static let requiredAbsentScans = 2

    enum Status: Equatable { case pending, closed, replaced, lockChanged }

    init(target: UInt32) { self.target = target }

    /// `.closed` cannot distinguish a user Cancel from a successful auth.
    mutating func observe(lockState: SessionLockState, scan: AuthDialogScan) -> Status {
        guard lockState == .unlocked else { return .lockChanged }
        guard case .windows(let w) = scan else {
            absentStreak = 0
            return .pending
        }
        if w.contains(where: { $0.windowID == target }) {
            absentStreak = 0
            return .pending
        }
        if !w.isEmpty { return .replaced }
        absentStreak += 1
        return absentStreak >= Self.requiredAbsentScans ? .closed : .pending
    }
}
