import Foundation
import Testing
@testable import ServerUnlockLogic

private func dir(owner: UInt32 = 0, mode: UInt16 = 0o755, symlink: Bool = false, isDir: Bool = true) -> HookFileAttributes {
    HookFileAttributes(isRegularFile: false, isDirectory: isDir && !symlink, isSymlink: symlink, ownerUID: owner, mode: mode)
}

private func file(owner: UInt32 = 501, mode: UInt16 = 0o700, symlink: Bool = false, regular: Bool = true) -> HookFileAttributes {
    HookFileAttributes(isRegularFile: regular && !symlink, isDirectory: false, isSymlink: symlink, ownerUID: owner, mode: mode)
}

private let home = "/Users/a"
private let userOwnedFrom = "/Users/a/Library/Application Support/MacRemote"

/// A fully valid chain; `tweak` may modify one entry by path.
private func chain(_ tweak: (String, HookFileAttributes?) -> HookFileAttributes?? = { _, _ in nil })
    -> [(path: String, attributes: HookFileAttributes?)]
{
    UnlockHookPolicy.directoryChain(home: home).map { path in
        let base: HookFileAttributes
        switch path {
        case "/", "/Users": base = dir(owner: 0)
        default: base = dir(owner: 501)
        }
        if let replaced = tweak(path, base) { return (path, replaced) }
        return (path, base)
    }
}

private func evaluate(file f: HookFileAttributes?, chain c: [(path: String, attributes: HookFileAttributes?)]) -> HookDecision {
    UnlockHookPolicy.evaluate(file: f, chain: c, userOwnedFrom: userOwnedFrom, currentUID: 501)
}

@Suite struct UnlockHookTests {
    @Test func eventMapping() {
        #expect(UnlockHookEvent(code: .verified) == .unlock)
        #expect(UnlockHookEvent(code: .authDialogSubmitted) == .authDialog)
        let nilCodes: [UnlockResultCode] = [
            .alreadyUnlocked, .inProgress, .lockStateUnknown, .invalidSignature, .notConfigured,
            .inputNotPermitted, .postFailed, .notVerified, .authDialogRefused,
            .authDialogInterrupted, .authDialogRetryBlocked, .unrecognized,
        ]
        for code in nilCodes { #expect(UnlockHookEvent(code: code) == nil, "\(code)") }
        #expect(UnlockHookEvent.unlock.rawValue == "unlock")
        #expect(UnlockHookEvent.authDialog.rawValue == "auth-dialog")
    }

    @Test func directoryChainIsExact() {
        #expect(UnlockHookPolicy.directoryChain(home: "/Users/a") == [
            "/", "/Users", "/Users/a", "/Users/a/Library", "/Users/a/Library/Application Support",
            "/Users/a/Library/Application Support/MacRemote",
            "/Users/a/Library/Application Support/MacRemote/hooks",
        ])
    }

    @Test func runWhenEverythingIsSafe() {
        #expect(evaluate(file: file(), chain: chain()) == .run)
    }

    @Test func missingFile() {
        #expect(evaluate(file: nil, chain: chain()) == .missing)
    }

    @Test(arguments: [
        ("symlink", HookFileAttributes(isRegularFile: false, isDirectory: false, isSymlink: true, ownerUID: 501, mode: 0o700)),
        ("not regular", HookFileAttributes(isRegularFile: false, isDirectory: true, isSymlink: false, ownerUID: 501, mode: 0o700)),
        ("other owner", HookFileAttributes(isRegularFile: true, isDirectory: false, isSymlink: false, ownerUID: 0, mode: 0o700)),
        ("0o720", HookFileAttributes(isRegularFile: true, isDirectory: false, isSymlink: false, ownerUID: 501, mode: 0o720)),
        ("0o702", HookFileAttributes(isRegularFile: true, isDirectory: false, isSymlink: false, ownerUID: 501, mode: 0o702)),
        ("0o600", HookFileAttributes(isRegularFile: true, isDirectory: false, isSymlink: false, ownerUID: 501, mode: 0o600)),
        ("0o4700", HookFileAttributes(isRegularFile: true, isDirectory: false, isSymlink: false, ownerUID: 501, mode: 0o4700)),
    ])
    func refusedFiles(name: String, attrs: HookFileAttributes) {
        guard case .refused = evaluate(file: attrs, chain: chain()) else {
            Issue.record("expected refused for \(name)")
            return
        }
    }

    private func expectRefused(path: String, _ replacement: HookFileAttributes?) {
        let c = chain { p, _ in p == path ? .some(replacement) : nil }
        guard case .refused(let reason) = evaluate(file: file(), chain: c) else {
            Issue.record("expected refused for \(path)")
            return
        }
        #expect(reason.contains(path), "reason \(reason) should contain \(path)")
    }

    @Test func refusedChains() {
        expectRefused(path: "/Users", dir(owner: 0, mode: 0o775))
        expectRefused(path: "/Users/a", dir(owner: 502))
        expectRefused(path: userOwnedFrom, dir(owner: 0))
        expectRefused(path: userOwnedFrom + "/hooks", dir(owner: 501, symlink: true))
        expectRefused(path: "/Users/a/Library", nil)
        expectRefused(path: "/Users/a/Library", dir(owner: 501, isDir: false))
    }

    @Test func rootOwnedTopLevelPasses() {
        let c = chain { p, _ in (p == "/" || p == "/Users") ? .some(dir(owner: 0, mode: 0o755)) : nil }
        #expect(evaluate(file: file(), chain: c) == .run)
    }

    @Test func unsafeChainWinsOverMissingFile() {
        let c = chain { p, _ in p == "/Users" ? .some(dir(owner: 0, mode: 0o775)) : nil }
        guard case .refused = evaluate(file: nil, chain: c) else {
            Issue.record("expected refused, not missing")
            return
        }
    }

    @Test func environmentKeys() {
        let base: Set = ["PATH", "HOME", "USER", "LOGNAME", "MACREMOTE_EVENT"]
        let without = UnlockHookPolicy.environment(home: home, user: "a", tmpDir: nil, event: .unlock)
        #expect(Set(without.keys) == base)
        #expect(without["MACREMOTE_EVENT"] == "unlock")
        let with = UnlockHookPolicy.environment(home: home, user: "a", tmpDir: "/tmp/x", event: .authDialog)
        #expect(Set(with.keys) == base.union(["TMPDIR"]))
        #expect(with["MACREMOTE_EVENT"] == "auth-dialog")
        #expect(with["TMPDIR"] == "/tmp/x")
        for key in with.keys {
            #expect(!key.uppercased().contains("PASSWORD"))
            #expect(!key.uppercased().contains("SECRET"))
        }
    }

    @Test func runGateStaleIds() {
        var gate = HookRunGate()
        let first = gate.begin()
        #expect(first != nil)
        #expect(gate.begin() == nil)
        #expect(gate.isCurrent(first!))
        gate.finish(first! &+ 99)
        #expect(gate.isCurrent(first!))
        #expect(gate.begin() == nil)
        gate.finish(first!)
        #expect(!gate.isCurrent(first!))
        let second = gate.begin()
        #expect(second != nil && second != first)
        // A stale id must not clear the newer run.
        gate.finish(first!)
        #expect(gate.isCurrent(second!))
        #expect(!gate.isCurrent(first!))
    }

    @Test func dispatchOnceFiresExactlyOnce() {
        let once = HookDispatchOnce()
        let lock = NSLock()
        nonisolated(unsafe) var trues = 0
        DispatchQueue.concurrentPerform(iterations: 100) { i in
            if once.fire("call \(i)") {
                lock.lock(); trues += 1; lock.unlock()
            }
        }
        #expect(trues == 1)
        #expect(once.fire("later") == false)
    }
}
