import Foundation

/// Persists the menu-bar "on unlock" command as the validated on-unlock hook script,
/// so `UnlockHookRunner` stays the single place that decides whether and how it runs.
struct HookCommandStore {
    private static let marker = "# MacRemote hook command (managed by the menu bar; edits are overwritten)"
    private static let shebang = "#!/bin/zsh -l"

    private let directory: String
    private let path: String

    init(home: String = NSHomeDirectory()) {
        directory = UnlockHookPolicy.hooksDirectory(home: home)
        path = UnlockHookPolicy.hookPath(home: home)
    }

    /// The saved command, or nil when none is set or the script was written by hand.
    func load() -> String? {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        let lines = text.components(separatedBy: "\n")
        guard lines.count >= 3, lines[0] == Self.shebang, lines[1] == Self.marker else { return nil }
        let command = lines.dropFirst(2).joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        return command.isEmpty ? nil : command
    }

    /// True when a script exists that this store did not write; saving would overwrite it.
    func hasForeignScript() -> Bool {
        FileManager.default.fileExists(atPath: path) && load() == nil
            && ((try? String(contentsOfFile: path, encoding: .utf8))?.contains(Self.marker) != true)
    }

    func save(_ command: String) throws {
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        let fm = FileManager.default
        if trimmed.isEmpty {
            if fm.fileExists(atPath: path) { try fm.removeItem(atPath: path) }
            return
        }
        try fm.createDirectory(atPath: directory, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        let script = [Self.shebang, Self.marker, trimmed, ""].joined(separator: "\n")
        let tmp = path + ".tmp"
        try? fm.removeItem(atPath: tmp)
        guard fm.createFile(atPath: tmp, contents: Data(script.utf8), attributes: [.posixPermissions: 0o700]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        _ = try fm.replaceItemAt(URL(fileURLWithPath: path), withItemAt: URL(fileURLWithPath: tmp))
    }
}
