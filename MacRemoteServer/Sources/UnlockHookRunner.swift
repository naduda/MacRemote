import Foundation

enum HookRunnerEvent: Equatable, Sendable {
    case missing
    case refused(String)
    case skippedBusy
    case started(pid: Int32, event: UnlockHookEvent)
    case launchFailed(String)
    case identityChanged
    case timedOut
    case killed
    case exited(status: Int32, signaled: Bool)
}

/// Runs the user's on-unlock hook.
///
/// Why `Process`: the task requires Foundation `Process` (not posix_spawn) for launching the hook.
///
/// Limitations and notes:
/// - Descendants are not killed on timeout: `Process` has no process-group option, so only the
///   hook's own pid receives SIGTERM/SIGKILL. Hook authors should `exec` long-running work.
/// - A tiny pid-reuse window exists between the child being reaped and `gate.finish`; it is
///   mitigated by checking `process.isRunning` before signalling.
/// - Events that arrive while a hook is running are dropped and logged, not queued.
///
/// Threading: the gate and all process state are touched only on `queue`. `onEvent` is called on `queue`.
final class UnlockHookRunner: @unchecked Sendable {
    struct Configuration: Sendable {
        var home: String
        var user: String
        var uid: UInt32
        var timeout: TimeInterval
        var killGrace: TimeInterval
        var onEvent: @Sendable (HookRunnerEvent) -> Void
    }

    private let configuration: Configuration?
    private let onEvent: @Sendable (HookRunnerEvent) -> Void
    private let queue = DispatchQueue(label: "com.macremote.unlock-hook", qos: .utility)
    // Touched only on `queue`.
    private var gate = HookRunGate()
    private var process: Process?

    init(configuration: Configuration) {
        self.configuration = configuration
        self.onEvent = configuration.onEvent
    }

    private init(unavailable onEvent: @escaping @Sendable (HookRunnerEvent) -> Void) {
        self.configuration = nil
        self.onEvent = onEvent
    }

    static func live() -> UnlockHookRunner {
        guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir, let name = pw.pointee.pw_name else {
            return UnlockHookRunner(unavailable: { _ in })
        }
        return UnlockHookRunner(configuration: Configuration(
            home: String(cString: dir),
            user: String(cString: name),
            uid: UInt32(getuid()),
            timeout: UnlockHookPolicy.timeout,
            killGrace: UnlockHookPolicy.killGrace,
            onEvent: { _ in }
        ))
    }

    func run(_ event: UnlockHookEvent) {
        queue.async { self.start(event) }
    }

    // MARK: - Private

    private func emit(_ event: HookRunnerEvent) {
        switch event {
        case .missing: print("[Hook] No on-unlock hook installed")
        case .refused(let why): print("[Hook] Refusing to run on-unlock hook: \(why)")
        case .skippedBusy: print("[Hook] Previous on-unlock hook still running; skipping this event")
        case .started(let pid, let e): print("[Hook] Started on-unlock hook pid=\(pid) event=\(e.rawValue)")
        case .launchFailed(let why): print("[Hook] Failed to launch on-unlock hook: \(why)")
        case .identityChanged: print("[Hook] Hook file changed during launch; killing it")
        case .timedOut: print("[Hook] On-unlock hook timed out; sending SIGTERM")
        case .killed: print("[Hook] On-unlock hook ignored SIGTERM; sent SIGKILL")
        case .exited(let status, let signaled):
            print("[Hook] On-unlock hook exited status=\(status) signaled=\(signaled)")
        }
        onEvent(event)
    }

    private static func attributes(_ st: stat) -> HookFileAttributes {
        let fmt = st.st_mode & S_IFMT
        return HookFileAttributes(
            isRegularFile: fmt == S_IFREG,
            isDirectory: fmt == S_IFDIR,
            isSymlink: fmt == S_IFLNK,
            ownerUID: UInt32(st.st_uid),
            mode: UInt16(st.st_mode & 0o7777)
        )
    }

    private static func identity(_ st: stat) -> HookFileIdentity {
        HookFileIdentity(
            dev: Int32(st.st_dev),
            ino: UInt64(st.st_ino),
            size: Int64(st.st_size),
            mtimeSec: Int(st.st_mtimespec.tv_sec),
            mtimeNsec: Int(st.st_mtimespec.tv_nsec)
        )
    }

    private static func lstatPath(_ path: String) -> stat? {
        var st = stat()
        return lstat(path, &st) == 0 ? st : nil
    }

    private static func realPath(_ path: String) -> String? {
        guard let p = realpath(path, nil) else { return nil }
        defer { free(p) }
        return String(cString: p)
    }

    private func start(_ event: UnlockHookEvent) {
        guard let cfg = configuration else {
            emit(.refused("no passwd entry for current user"))
            return
        }
        let hooksDir = UnlockHookPolicy.hooksDirectory(home: cfg.home)
        let hookPath = UnlockHookPolicy.hookPath(home: cfg.home)

        // 1. Directory chain.
        let chain: [(path: String, attributes: HookFileAttributes?)] =
            UnlockHookPolicy.directoryChain(home: cfg.home).map { path in
                (path, Self.lstatPath(path).map(Self.attributes))
            }

        // 2. Open the file without following symlinks, then fstat the fd.
        var fileAttrs: HookFileAttributes?
        var fileIdentity: HookFileIdentity?
        var fd: Int32 = open(hookPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd >= 0 {
            var st = stat()
            if fstat(fd, &st) == 0 {
                fileAttrs = Self.attributes(st)
                fileIdentity = Self.identity(st)
            } else {
                close(fd)
                fd = -1
                emit(.refused("fstat failed"))
                return
            }
        } else if errno == ELOOP {
            fileAttrs = HookFileAttributes(
                isRegularFile: false, isDirectory: false, isSymlink: true, ownerUID: 0, mode: 0)
        } else if errno != ENOENT {
            emit(.refused("open failed: errno \(errno)"))
            return
        }
        func closeFD() {
            if fd >= 0 { close(fd); fd = -1 }
        }

        // 3. Policy decision.
        switch UnlockHookPolicy.evaluate(
            file: fileAttrs, chain: chain,
            userOwnedFrom: (hooksDir as NSString).deletingLastPathComponent, currentUID: cfg.uid
        ) {
        case .missing:
            closeFD()
            emit(.missing)
            return
        case .refused(let why):
            closeFD()
            emit(.refused(why))
            return
        case .run:
            break
        }
        guard let identity = fileIdentity else {
            closeFD()
            emit(.refused("no file identity"))
            return
        }

        // 4. Canonical paths must match the constructed ones.
        guard Self.realPath(hooksDir) == hooksDir, Self.realPath(hookPath) == hookPath else {
            closeFD()
            emit(.refused("path is not canonical"))
            return
        }

        // 5. One run at a time; events arriving meanwhile are dropped, not queued.
        guard let id = gate.begin() else {
            closeFD()
            emit(.skippedBusy)
            return
        }

        // 6. Configure the process.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: hookPath)
        p.arguments = []
        p.environment = UnlockHookPolicy.environment(
            home: cfg.home, user: cfg.user,
            tmpDir: ProcessInfo.processInfo.environment["TMPDIR"], event: event)
        p.currentDirectoryURL = URL(fileURLWithPath: hooksDir)
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        p.qualityOfService = .utility
        p.terminationHandler = { [queue] proc in
            let status = proc.terminationStatus
            let signaled = proc.terminationReason == .uncaughtSignal
            queue.async {
                self.emit(.exited(status: status, signaled: signaled))
                self.gate.finish(id)
                if self.process === proc { self.process = nil }
            }
        }

        // 7. Identity must still match right before launch.
        func matchesIdentity() -> Bool {
            guard let st = Self.lstatPath(hookPath) else { return false }
            return Self.identity(st) == identity
        }
        guard matchesIdentity() else {
            closeFD()
            gate.finish(id)
            emit(.refused("hook changed before launch"))
            return
        }
        do {
            try p.run()
        } catch {
            closeFD()
            gate.finish(id)
            emit(.launchFailed("\(error)"))
            return
        }
        process = p
        let pid = p.processIdentifier
        if !matchesIdentity() {
            emit(.identityChanged)
            p.terminate()
            if p.isRunning { kill(pid, SIGKILL) }
        }
        closeFD()
        emit(.started(pid: pid, event: event))

        // 8. Timeout, then SIGKILL after the grace period.
        queue.asyncAfter(deadline: .now() + cfg.timeout) { [self] in
            guard gate.isCurrent(id), p.isRunning else { return }
            emit(.timedOut)
            p.terminate()
            queue.asyncAfter(deadline: .now() + cfg.killGrace) { [self] in
                guard gate.isCurrent(id), p.isRunning else { return }
                kill(pid, SIGKILL)
                emit(.killed)
            }
        }
    }
}
