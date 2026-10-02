# MacRemote

Unlock your Mac from your iPhone with the Action Button and Face ID. Nothing else: no trackpad, no screen sharing.

## Features

- **Protected Unlock**: The Mac password stays in the Mac Keychain; iOS requires device-owner authentication and a pairing key
- **Action Button / Shortcuts**: An **Unlock Mac** App Intent bound to one paired Mac

## Requirements

- **macOS**: 14.0+
- **iOS**: 17.0+
- **Network**: Both devices on the same WiFi network

## Installation

### Prerequisites

- [Tuist](https://tuist.io) installed (`brew install tuist`)
- Xcode 15+

### Build

```bash
git clone https://github.com/pedrocid/MacRemote.git
cd MacRemote
tuist generate
open MacRemote.xcworkspace
```

### macOS Server

1. Build and run `MacRemoteServer` scheme
2. Grant **Accessibility** permission when prompted (System Settings → Privacy & Security → Accessibility)
3. Click "Start Server" in the menubar app

### Remote Unlock Setup

1. Open the MacRemote Server menu bar window.
2. Enter the Mac login password under **Remote Unlock** and enable it.
3. Copy the generated pairing key.
4. Connect from iOS and save that pairing key.
5. Tap **Unlock Mac** and authenticate with Face ID, Touch ID, or the iPhone passcode.

The Mac password remains in the Mac Keychain. The iOS app stores only the pairing token and sends a one-time HMAC response for each unlock request.

### Unlock from the Action Button (Shortcuts)

The Action Button shortcut works with one bound Mac at a time. Before setting it up, update MacRemote Server, enable **Remote Unlock**, and grant the server **Accessibility** permission. In the iOS app, save the pairing key while connected to the Mac you want to bind; this binds Shortcuts to that Mac.

The bound Mac is the one shown under the **Unlock Mac** button in the app. Shortcuts never chooses an arbitrary Mac. To switch Macs, connect to the other Mac and save its pairing key again while connected.

In the Shortcuts app, create a shortcut, add the MacRemote **Unlock Mac** action, and save it. Then assign it in **Settings → Action Button → Shortcut** and choose that shortcut.

The shortcut can report that the Mac was unlocked, that it was already unlocked (in which case nothing was typed), or that the request was sent but the result could not be confirmed by an older server. If the Mac does not answer after a request is sent, the shortcut reports that no answer was received and does not retry the unlock.

The Mac must be logged in with MacRemote Server running; after a FileVault-protected reboot, the server is not running until someone logs in. The iPhone and Mac must be on the same local network, and MacRemote needs Local Network permission on the iPhone. If the iPhone is locked when the Action Button is pressed, iOS requires it to be unlocked before the shortcut runs. Each attempt then uses Face ID or Touch ID with iPhone passcode fallback, so this flow is not biometrics-only. Older MacRemote Server versions cannot be used from Shortcuts.

### iOS Client

1. Build and run `MacRemoteClient` scheme on your iPhone
2. The app will discover your Mac automatically via Bonjour
3. Tap to connect

## Architecture

```
┌─────────────────┐       WiFi/TCP (Bonjour)       ┌─────────────────┐
│   iOS Client    │◄─────────────────────────────►│   macOS Server  │
│ • Pairing       │      JSON, length-prefixed     │   (Menubar)     │
│ • Face ID       │                                │ • Challenge/HMAC│
│ • Unlock intent │                                │ • CGEvent typing│
└─────────────────┘                                └─────────────────┘
```

### Protocol

JSON messages over TCP with a 4-byte big-endian length prefix:

```swift
// Client → Server
enum RemoteMessage {
    case ping
    case unlock(signature: Data)         // one-time HMAC response
}

// Server → Client
enum ServerMessage {
    case connected(screenWidth: Double, screenHeight: Double, unlockChallenge: Data?, unlockAvailable: Bool, serverId: String?)
    case unlockResult(success: Bool, message: String, code: UnlockResultCode?)
    case unlockChallenge(Data)
    case pong
    case error(message: String)
}
```

### Project Structure

```
MacRemote/
├── Shared/                      # Protocol shared by both apps
├── MacRemoteServer/Sources/     # Menubar app: server, Bonjour, unlock verifier, keystroke injection
├── MacRemoteClient/Sources/     # iOS app: pairing UI, unlock service, App Intent
└── LogicTests/                  # SwiftPM harness for unlock logic
```

## Permissions

### macOS (Server)

| Permission | Purpose |
|------------|---------|
| Accessibility | Type the password on the lock screen |
| Local Network | Bonjour discovery and TCP server |

### iOS (Client)

| Permission | Purpose |
|------------|---------|
| Local Network | Discover and connect to Mac |

## Troubleshooting

### "Accessibility permission required"

1. Open System Settings → Privacy & Security → Accessibility
2. Add or enable "MacRemote Server"
3. Click "Refresh" in the app

### Can't find Mac

- Ensure both devices are on the same WiFi network
- Check that the server is running (antenna icon in menubar)
- Try restarting the server

### Connection drops

- Check WiFi stability
- Ensure Mac doesn't go to sleep

## License

MIT

## Acknowledgments

Built with:
- [Network.framework](https://developer.apple.com/documentation/network)
- [Bonjour](https://developer.apple.com/bonjour/)
