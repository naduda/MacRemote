import Foundation
import CoreGraphics
import AppKit

/// Posts keyboard events on macOS using the CGEvent API
final class InputController {

    /// Posts HID-level events so they can reach the macOS login window.
    /// The caller keeps the password in the Keychain and never sends it over the network.
    func unlockScreen(password: String, lockState: SessionLockStateProviding) -> UnlockTypingResult {
        let sequencer = UnlockKeystrokeSequencer(
            lockState: { lockState.currentState() },
            postWake: { self.postWakeKey() },
            postPassword: { self.postPasswordAndReturn($0) },
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

    private func postPasswordAndReturn(_ password: String) -> Bool {
        let source = CGEventSource(stateID: .hidSystemState)
        guard let returnDown = CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: true),
              let returnUp = CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: false) else {
            return false
        }

        // One key event pair per character: the lock screen drops long unicode strings posted as one event.
        for character in password {
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
            usleep(25_000)
        }
        usleep(100_000)
        returnDown.post(tap: .cghidEventTap)
        returnUp.post(tap: .cghidEventTap)
        return true
    }

    // MARK: - Permissions

    static func checkAccessibilityPermission(prompt: Bool = false) -> Bool {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: prompt] as CFDictionary
        let result = AXIsProcessTrustedWithOptions(options)
        print("[InputController] Accessibility check (prompt=\(prompt)): \(result)")
        return result
    }

    static func openAccessibilityPreferences() {
        let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!
        NSWorkspace.shared.open(url)
    }
}
