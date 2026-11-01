import Foundation

/// Events that can trigger the user's on-unlock hook.
///
/// Note: `authDialog` means "the password and Return were posted into the verified field and that
/// window then closed". The server cannot distinguish a user Cancel from a successful auth.
enum UnlockHookEvent: String, Sendable {
    case unlock
    case authDialog = "auth-dialog"

    init?(code: UnlockResultCode) {
        switch code {
        case .verified: self = .unlock
        case .authDialogSubmitted: self = .authDialog
        default: return nil
        }
    }
}

struct HookFileAttributes: Equatable, Sendable {
    var isRegularFile: Bool
    var isDirectory: Bool
    var isSymlink: Bool
    var ownerUID: UInt32
    var mode: UInt16
}

struct HookFileIdentity: Equatable, Sendable {
    var dev: Int32
    var ino: UInt64
    var size: Int64
    var mtimeSec: Int
    var mtimeNsec: Int
}

enum HookDecision: Equatable, Sendable {
    case run
    case missing
    case refused(String)
}

/// Pure policy for the on-unlock hook.
///
/// Threat model: the whole directory chain from "/" to the hooks directory, and the hook file
/// itself, must be writable only by root or the current uid, and the fd identity is rechecked
/// around launch. Any remaining replacement requires root or same-user privileges, which already
/// allow arbitrary code execution as that user.
enum UnlockHookPolicy {
    static let timeout: TimeInterval = 30
    static let killGrace: TimeInterval = 2
    static let sendFallback: TimeInterval = 5
    static let fileName = "on-unlock"
    static let relativeDirectoryComponents = ["Library", "Application Support", "MacRemote", "hooks"]

    static func hooksDirectory(home: String) -> String {
        relativeDirectoryComponents.reduce(home) { ($0 as NSString).appendingPathComponent($1) }
    }

    static func hookPath(home: String) -> String {
        (hooksDirectory(home: home) as NSString).appendingPathComponent(fileName)
    }

    /// Every directory from "/" through the hooks directory.
    static func directoryChain(home: String) -> [String] {
        var result = ["/"]
        var current = ""
        for part in hooksDirectory(home: home).split(separator: "/") {
            current += "/" + part
            result.append(current)
        }
        return result
    }

    static func evaluate(
        file: HookFileAttributes?,
        chain: [(path: String, attributes: HookFileAttributes?)],
        userOwnedFrom: String,
        currentUID: UInt32
    ) -> HookDecision {
        var userOwned = false
        for entry in chain {
            if entry.path == userOwnedFrom { userOwned = true }
            guard let a = entry.attributes else { return .refused(entry.path) }
            if a.isSymlink || !a.isDirectory { return .refused(entry.path) }
            if a.ownerUID != 0 && a.ownerUID != currentUID { return .refused(entry.path) }
            if userOwned && a.ownerUID != currentUID { return .refused(entry.path) }
            if a.mode & 0o022 != 0 { return .refused(entry.path) }
        }
        guard let f = file else { return .missing }
        if f.isSymlink { return .refused("hook is a symlink") }
        if !f.isRegularFile { return .refused("hook is not a regular file") }
        if f.ownerUID != currentUID { return .refused("hook not owned by current user") }
        if f.mode & 0o022 != 0 { return .refused("hook is group/world writable") }
        if f.mode & 0o100 == 0 { return .refused("hook is not executable") }
        if f.mode & 0o6000 != 0 { return .refused("hook is setuid/setgid") }
        return .run
    }

    static func environment(home: String, user: String, tmpDir: String?, event: UnlockHookEvent) -> [String: String] {
        var env = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": home,
            "USER": user,
            "LOGNAME": user,
            "MACREMOTE_EVENT": event.rawValue,
        ]
        if let tmpDir { env["TMPDIR"] = tmpDir }
        return env
    }
}

/// Allows one hook run at a time.
struct HookRunGate: Sendable {
    private var current: UInt64?
    private var counter: UInt64 = 0

    /// Returns a new run id, or nil while a run is current.
    mutating func begin() -> UInt64? {
        guard current == nil else { return nil }
        counter += 1
        current = counter
        return counter
    }

    func isCurrent(_ id: UInt64) -> Bool { current == id }

    /// Clears the current run only if `id` matches.
    mutating func finish(_ id: UInt64) {
        if current == id { current = nil }
    }
}

/// Used to trigger the hook exactly once on the first of send completion, notConnected or fallback.
final class HookDispatchOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false

    /// Returns true only on the first call.
    func fire(_ reason: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if fired { return false }
        fired = true
        return true
    }
}
