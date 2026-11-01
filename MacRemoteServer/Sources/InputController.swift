import Foundation
import CoreGraphics
import AppKit

/// Posts keyboard events on macOS using the CGEvent API
final class InputController: Sendable {

    /// Posts HID-level events so they can reach the macOS login window.
    /// The caller keeps the password in the Keychain and never sends it over the network.
    func unlockScreen(password: String, lockState: SessionLockStateProviding) -> UnlockTypingResult {
        let sequencer = UnlockKeystrokeSequencer(
            lockState: { lockState.currentState() },
            postWake: { self.postWakeKey() },
            postPassword: { Self.makePoster(recheck: { true }).post($0) == .posted },
            sleep: { usleep(useconds_t($0 * 1_000_000)) }
        )
        let result = sequencer.run(password: password)
        if result == .typed {
            print("[InputController] Remote unlock events posted")
        }
        return result
    }

    private func postWakeKey() -> Bool {
        let source = CGEventSource(stateID: .hidSystemState)

        // Wake the display with Shift: it types nothing, whereas a space would land in the
        // password field when the display is already awake.
        guard let wakeDown = CGEvent(keyboardEventSource: source, virtualKey: 56, keyDown: true),
              let wakeUp = CGEvent(keyboardEventSource: source, virtualKey: 56, keyDown: false) else {
            return false
        }
        wakeDown.post(tap: .cghidEventTap)
        wakeUp.post(tap: .cghidEventTap)
        return true
    }

    static func makePoster(recheck: @escaping @Sendable () -> Bool) -> GuardedPasswordPoster {
        GuardedPasswordPoster(
            postCharacter: { character in
                let source = CGEventSource(stateID: .hidSystemState)
                // One key event pair per character: the lock screen drops long unicode strings posted as one event.
                guard let down = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: true),
                      let up = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: false) else {
                    return false
                }
                var utf16 = Array(String(character).utf16)
                down.keyboardSetUnicodeString(stringLength: utf16.count, unicodeString: &utf16)
                up.keyboardSetUnicodeString(stringLength: utf16.count, unicodeString: &utf16)
                down.post(tap: .cghidEventTap)
                usleep(15_000)
                up.post(tap: .cghidEventTap)
                return true
            },
            postReturn: {
                let source = CGEventSource(stateID: .hidSystemState)
                guard let returnDown = CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: true),
                      let returnUp = CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: false) else {
                    return false
                }
                returnDown.post(tap: .cghidEventTap)
                returnUp.post(tap: .cghidEventTap)
                return true
            },
            sleep: { usleep(useconds_t($0 * 1_000_000)) },
            recheck: recheck
        )
    }

    /// Types the password into the focused auth dialog. Runs on `unlockTypingQueue`, never on MainActor.
    func submitAuthDialog(password: String,
                          lockState: SessionLockStateProviding & Sendable,
                          detector: AuthDialogDetecting) -> AuthDialogTypingResult {
        let gate = AuthDialogGate(
            lockState: { lockState.currentState() },
            scan: { detector.scan() },
            focus: { AXAuthDialogFocusProbe.focus(for: $0) }
        )
        let sequencer = AuthDialogKeystrokeSequencer(gate: gate, makePoster: { recheck in Self.makePoster(recheck: recheck) })
        let result = sequencer.run(password: password)
        switch result {
        case .typed:
            print("[InputController] Auth dialog password posted")
        case .interrupted(let n):
            print("[InputController] Auth dialog typing interrupted after \(n) characters; Return not pressed")
        default:
            print("[InputController] Auth dialog refused: \(result)")
        }
        return result
    }

    // MARK: - Permissions

    static func checkAccessibilityPermission(prompt: Bool = false) -> Bool {
        // Literal value of kAXTrustedCheckOptionPrompt, which is shared mutable state under Swift 6 concurrency checking.
        let options = ["AXTrustedCheckOptionPrompt": prompt] as CFDictionary
        let result = AXIsProcessTrustedWithOptions(options)
        print("[InputController] Accessibility check (prompt=\(prompt)): \(result)")
        return result
    }

    static func openAccessibilityPreferences() {
        let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!
        NSWorkspace.shared.open(url)
    }
}
