import Foundation
import CoreGraphics
import ApplicationServices

/// Live window detector backed by CGWindowList. Stateless and thread-safe.
struct CGWindowListAuthDialogDetector: AuthDialogDetecting {
    func scan() -> AuthDialogScan {
        guard let raw = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID),
              let windows = raw as? [[String: Any]] else { return .failed }

        var count: UInt32 = 0
        guard CGGetActiveDisplayList(0, nil, &count) == .success, count > 0 else { return .failed }
        var ids = [CGDirectDisplayID](repeating: 0, count: Int(count))
        var fetched: UInt32 = 0
        guard CGGetActiveDisplayList(count, &ids, &fetched) == .success, fetched > 0 else { return .failed }
        let displays = ids.prefix(Int(fetched)).map { CGDisplayBounds($0) }

        return .windows(AuthDialogWindowFilter.qualifying(in: windows, displays: displays))
    }
}

/// Accessibility probe: is the system focus in the password field of the given dialog window?
///
/// NEEDS DEVICE VERIFICATION on macOS 27: SecurityAgent is reported as the focused application,
/// the focused element's window attribute and frame match the CG window, the subrole is
/// AXSecureTextField, and which of kAXNumberOfCharactersAttribute / kAXValueAttribute is exposed.
/// The field value itself is never logged or returned.
enum AXAuthDialogFocusProbe {
    static func focus(for window: AuthDialogWindow) -> AuthDialogFocus {
        let system = AXUIElementCreateSystemWide()

        var appRef: CFTypeRef?
        let appErr = AXUIElementCopyAttributeValue(system, kAXFocusedApplicationAttribute as CFString, &appRef)
        guard appErr == .success, let appValue = appRef, CFGetTypeID(appValue) == AXUIElementGetTypeID() else {
            return .accessibilityError(appErr == .success ? AXError.failure.rawValue : appErr.rawValue)
        }
        let app = appValue as! AXUIElement

        var pid: pid_t = 0
        let pidErr = AXUIElementGetPid(app, &pid)
        guard pidErr == .success else { return .accessibilityError(pidErr.rawValue) }
        guard pid == window.ownerPID else { return .otherApplication }

        guard let focusedWindow = copyElement(app, kAXFocusedWindowAttribute).get else {
            return .accessibilityError(copyElement(app, kAXFocusedWindowAttribute).error)
        }
        let elementResult = copyElement(app, kAXFocusedUIElementAttribute)
        guard let element = elementResult.get else { return .accessibilityError(elementResult.error) }
        let elementWindowResult = copyElement(element, kAXWindowAttribute)
        guard let elementWindow = elementWindowResult.get else {
            return .accessibilityError(elementWindowResult.error)
        }
        guard CFEqual(elementWindow, focusedWindow) else { return .otherWindow }

        guard let axFrame = frame(of: elementWindow) else { return .otherWindow }
        guard AuthDialogWindowFilter.framesMatch(axFrame, window.bounds) else { return .otherWindow }

        var subroleRef: CFTypeRef?
        let subErr = AXUIElementCopyAttributeValue(element, kAXSubroleAttribute as CFString, &subroleRef)
        guard subErr == .success else { return .accessibilityError(subErr.rawValue) }
        guard let subrole = subroleRef as? String, subrole == (kAXSecureTextFieldSubrole as String) else {
            return .otherElement
        }

        return .passwordField(content(of: element))
    }

    private static func content(of element: AXUIElement) -> AuthDialogFieldContent {
        var countRef: CFTypeRef?
        if AXUIElementCopyAttributeValue(element, kAXNumberOfCharactersAttribute as CFString, &countRef) == .success,
           let n = countRef as? NSNumber, CFGetTypeID(n) == CFNumberGetTypeID() {
            return n.intValue == 0 ? .empty : .nonEmpty
        }
        var valueRef: CFTypeRef?
        if AXUIElementCopyAttributeValue(element, kAXValueAttribute as CFString, &valueRef) == .success,
           let s = valueRef as? String {
            return s.isEmpty ? .empty : .nonEmpty
        }
        return .unknown
    }

    private static func frame(of element: AXUIElement) -> CGRect? {
        var posRef: CFTypeRef?
        var sizeRef: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXPositionAttribute as CFString, &posRef) == .success,
              AXUIElementCopyAttributeValue(element, kAXSizeAttribute as CFString, &sizeRef) == .success,
              let posValue = posRef, let sizeValue = sizeRef,
              CFGetTypeID(posValue) == AXValueGetTypeID(), CFGetTypeID(sizeValue) == AXValueGetTypeID()
        else { return nil }
        var point = CGPoint.zero
        var size = CGSize.zero
        guard AXValueGetValue(posValue as! AXValue, .cgPoint, &point),
              AXValueGetValue(sizeValue as! AXValue, .cgSize, &size) else { return nil }
        return CGRect(origin: point, size: size)
    }

    private struct ElementResult {
        let get: AXUIElement?
        let error: Int32
    }

    private static func copyElement(_ element: AXUIElement, _ attribute: String) -> ElementResult {
        var ref: CFTypeRef?
        let err = AXUIElementCopyAttributeValue(element, attribute as CFString, &ref)
        guard err == .success else { return ElementResult(get: nil, error: err.rawValue) }
        guard let value = ref, CFGetTypeID(value) == AXUIElementGetTypeID() else {
            return ElementResult(get: nil, error: AXError.failure.rawValue)
        }
        return ElementResult(get: (value as! AXUIElement), error: 0)
    }
}
