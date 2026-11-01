import Foundation
import Testing
@testable import ServerUnlockLogic

private final class Collector: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [HookRunnerEvent] = []

    func add(_ e: HookRunnerEvent) { lock.lock(); items.append(e); lock.unlock() }
    var events: [HookRunnerEvent] { lock.lock(); defer { lock.unlock() }; return items }

    @discardableResult
    func waitFor(deadline: TimeInterval = 10, _ predicate: ([HookRunnerEvent]) -> Bool) async -> Bool {
        let end = Date().addingTimeInterval(deadline)
        while Date() < end {
            if predicate(events) { return true }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        return predicate(events)
    }

    func hasExit() -> Bool { events.contains { if case .exited = $0 { return true } else { return false } } }
    func count(_ match: (HookRunnerEvent) -> Bool) -> Int { events.filter(match).count }
}

private func isExited(_ e: HookRunnerEvent) -> Bool { if case .exited = e { return true } else { return false } }
private func isStarted(_ e: HookRunnerEvent) -> Bool { if case .started = e { return true } else { return false } }
private func isRefused(_ e: HookRunnerEvent) -> Bool { if case .refused = e { return true } else { return false } }

private final class Env {
    let home: String
    let hooksDir: String
    let hookPath: String
    let collector = Collector()
    let runner: UnlockHookRunner

    init(timeout: TimeInterval = 1.0, killGrace: TimeInterval = 0.5) throws {
        var base = NSTemporaryDirectory()
        if let rp = realpath(base, nil) { base = String(cString: rp); free(rp) }
        home = (base as NSString).appendingPathComponent(UUID().uuidString)
        hooksDir = UnlockHookPolicy.hooksDirectory(home: home)
        hookPath = UnlockHookPolicy.hookPath(home: home)
        try FileManager.default.createDirectory(
            atPath: hooksDir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755])
        // Intermediate dirs get the umask default; force the chain to 0o755.
        for path in UnlockHookPolicy.directoryChain(home: home).dropFirst() where path.hasPrefix(home) {
            chmod(path, 0o755)
        }
        chmod(home, 0o755)
        let pw = getpwuid(getuid())
        let user = pw.map { String(cString: $0.pointee.pw_name) } ?? "user"
        let c = collector
        runner = UnlockHookRunner(configuration: .init(
            home: home, user: user, uid: UInt32(getuid()), timeout: timeout, killGrace: killGrace,
            onEvent: { c.add($0) }))
    }

    deinit { try? FileManager.default.removeItem(atPath: home) }

    func writeScript(_ body: String, mode: mode_t = 0o700) throws {
        try? FileManager.default.removeItem(atPath: hookPath)
        try ("#!/bin/sh\n" + body + "\n").write(toFile: hookPath, atomically: false, encoding: .utf8)
        chmod(hookPath, mode)
    }

    func path(_ name: String) -> String { (home as NSString).appendingPathComponent(name) }
    func exists(_ name: String) -> Bool { FileManager.default.fileExists(atPath: path(name)) }
    func read(_ name: String) -> String { (try? String(contentsOfFile: path(name), encoding: .utf8)) ?? "" }
}

@Suite(.serialized) struct UnlockHookRunnerTests {
    @Test func noFileIsMissing() async throws {
        let env = try Env()
        env.runner.run(.unlock)
        #expect(await env.collector.waitFor { $0.contains(.missing) })
    }

    @Test func environmentIsExactlyThePolicySet() async throws {
        let env = try Env()
        try env.writeScript("env > \"$HOME/env.txt\"")
        env.runner.run(.authDialog)
        #expect(await env.collector.waitFor { $0.contains(.exited(status: 0, signaled: false)) })
        let events = env.collector.events
        let startIdx = events.firstIndex(where: isStarted)
        let exitIdx = events.firstIndex(where: isExited)
        #expect(startIdx != nil && exitIdx != nil && startIdx! < exitIdx!)
        var vars: [String: String] = [:]
        for line in env.read("env.txt").split(separator: "\n") {
            guard let eq = line.firstIndex(of: "=") else { continue }
            vars[String(line[..<eq])] = String(line[line.index(after: eq)...])
        }
        let tmp = ProcessInfo.processInfo.environment["TMPDIR"]
        let pw = getpwuid(getuid())
        let user = pw.map { String(cString: $0.pointee.pw_name) } ?? "user"
        let expected = UnlockHookPolicy.environment(home: env.home, user: user, tmpDir: tmp, event: .authDialog)
        // The shell itself may add PWD/SHLVL/_/OLDPWD; those are not ours.
        let shellAdded: Set = ["PWD", "SHLVL", "_", "OLDPWD", "__CF_USER_TEXT_ENCODING"]
        let actual = vars.filter { !shellAdded.contains($0.key) }
        #expect(Set(actual.keys) == Set(expected.keys))
        #expect(actual["MACREMOTE_EVENT"] == "auth-dialog")
    }

    @Test func unsafeHooksAreRefusedAndNeverRun() async throws {
        // 0o777
        do {
            let env = try Env()
            try env.writeScript("touch \"$HOME/marker\"", mode: 0o777)
            env.runner.run(.unlock)
            #expect(await env.collector.waitFor { $0.contains(where: isRefused) })
            try await Task.sleep(nanoseconds: 200_000_000)
            #expect(!env.exists("marker"))
        }
        // symlinked hook
        do {
            let env = try Env()
            let target = env.path("real-hook")
            try "#!/bin/sh\ntouch \"$HOME/marker\"\n".write(toFile: target, atomically: false, encoding: .utf8)
            chmod(target, 0o700)
            try FileManager.default.createSymbolicLink(atPath: env.hookPath, withDestinationPath: target)
            env.runner.run(.unlock)
            #expect(await env.collector.waitFor { $0.contains(where: isRefused) })
            try await Task.sleep(nanoseconds: 200_000_000)
            #expect(!env.exists("marker"))
        }
        // group-writable hooks dir
        do {
            let env = try Env()
            try env.writeScript("touch \"$HOME/marker\"")
            chmod(env.hooksDir, 0o775)
            env.runner.run(.unlock)
            #expect(await env.collector.waitFor { $0.contains(where: isRefused) })
            try await Task.sleep(nanoseconds: 200_000_000)
            #expect(!env.exists("marker"))
        }
        // non-executable 0o600
        do {
            let env = try Env()
            try env.writeScript("touch \"$HOME/marker\"", mode: 0o600)
            env.runner.run(.unlock)
            #expect(await env.collector.waitFor { $0.contains(where: isRefused) })
            try await Task.sleep(nanoseconds: 200_000_000)
            #expect(!env.exists("marker"))
        }
    }

    @Test func doesNotLeakInheritedFileDescriptors() async throws {
        let env = try Env()
        var raw: [Int32] = [0, 0]
        #expect(pipe(&raw) == 0)
        // Move the pipe to high fd numbers so they cannot collide with ls's own directory fd.
        // F_DUPFD returns a descriptor without CLOEXEC, so it would be inherited unless Process closes it.
        let fds: [Int32] = [fcntl(raw[0], F_DUPFD, 100), fcntl(raw[1], F_DUPFD, 101)]
        close(raw[0]); close(raw[1])
        #expect(fds.allSatisfy { $0 >= 100 })
        defer { close(fds[0]); close(fds[1]) }
        try env.writeScript("ls /dev/fd > \"$HOME/fds.txt\"")
        env.runner.run(.unlock)
        #expect(await env.collector.waitFor { $0.contains(where: isExited) })
        let listed = Set(env.read("fds.txt").split(whereSeparator: \.isWhitespace).compactMap { Int32($0) })
        #expect(!listed.isEmpty)
        for fd in fds { #expect(!listed.contains(fd), "fd \(fd) leaked into hook; listed=\(listed.sorted())") }
    }

    @Test func timeoutTerminates() async throws {
        let env = try Env()
        try env.writeScript("exec sleep 30")
        let t0 = Date()
        env.runner.run(.unlock)
        #expect(await env.collector.waitFor { $0.contains(where: isExited) })
        let elapsed = Date().timeIntervalSince(t0)
        #expect(elapsed < 2.5, "took \(elapsed)")
        let events = env.collector.events
        let t = events.firstIndex(of: .timedOut)
        let x = events.firstIndex(of: .exited(status: SIGTERM, signaled: true))
        #expect(t != nil && x != nil && t! < x!)
        #expect(!events.contains(.killed))
    }

    @Test func escalatesToKill() async throws {
        let env = try Env()
        try env.writeScript("trap '' TERM\nwhile :; do sleep 0.1; done")
        env.runner.run(.unlock)
        #expect(await env.collector.waitFor { $0.contains(where: isExited) })
        let events = env.collector.events
        let t = events.firstIndex(of: .timedOut)
        let k = events.firstIndex(of: .killed)
        let x = events.firstIndex(where: isExited)
        #expect(t != nil && k != nil && x != nil)
        if let t, let k, let x { #expect(t < k && k < x) }
        #expect(events.contains(.exited(status: SIGKILL, signaled: true)))
    }

    @Test func secondRunWhileBusyIsSkipped() async throws {
        let env = try Env(timeout: 5)
        try env.writeScript("sleep 0.8")
        env.runner.run(.unlock)
        env.runner.run(.unlock)
        #expect(await env.collector.waitFor { $0.contains(.skippedBusy) })
        #expect(await env.collector.waitFor { $0.contains(where: isExited) })
        #expect(env.collector.count(isStarted) == 1)
    }

    @Test func staleTimerDoesNotAffectNextRun() async throws {
        let env = try Env(timeout: 1.5)
        try env.writeScript("exit 0")
        env.runner.run(.unlock)
        #expect(await env.collector.waitFor { $0.contains(where: isExited) })
        try await Task.sleep(nanoseconds: 800_000_000)
        try env.writeScript("sleep 1.0\ntouch \"$HOME/done\"")
        env.runner.run(.unlock)
        #expect(await env.collector.waitFor { $0.filter(isExited).count == 2 })
        let events = env.collector.events
        #expect(!events.contains(.timedOut), "events: \(events)")
        #expect(events.last == .exited(status: 0, signaled: false))
        #expect(env.exists("done"))
    }

    @Test func exitedProcessIsReaped() async throws {
        let env = try Env()
        try env.writeScript("exit 0")
        env.runner.run(.unlock)
        #expect(await env.collector.waitFor { $0.contains(where: isExited) })
        var pid: Int32 = 0
        for e in env.collector.events { if case .started(let p, _) = e { pid = p } }
        #expect(pid > 0)
        #expect(kill(pid, 0) == -1)
        #expect(errno == ESRCH)
    }

    @Test func replacingFileBetweenRunsStillWorks() async throws {
        let env = try Env()
        try env.writeScript("touch \"$HOME/one\"")
        env.runner.run(.unlock)
        #expect(await env.collector.waitFor { $0.filter(isExited).count == 1 })
        try env.writeScript("touch \"$HOME/two\"")
        env.runner.run(.unlock)
        #expect(await env.collector.waitFor { $0.filter(isExited).count == 2 })
        #expect(env.exists("one") && env.exists("two"))
        #expect(env.collector.count(isRefused) == 0)
    }
}
