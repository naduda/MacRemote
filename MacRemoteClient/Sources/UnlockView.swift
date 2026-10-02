import SwiftUI

/// Pairing and unlock screen shown after connecting to a Mac
struct UnlockView: View {
    @ObservedObject var client: NetworkClient
    @State private var pairingKey = ""
    @State private var pairingKeyError = false
    @AppStorage(UnlockSettings.requireFaceIDForShortcutKey) private var requireFaceIDForShortcut = true

    private var shortcutTargetCaption: Text {
        switch client.pairingState {
        case .paired(let target):
            return Text(String(format: String(localized: "unlock_shortcut_target"), target.displayName))
        case .tokenOnlyLegacy:
            return Text(String(localized: "unlock_shortcut_legacy"))
        case .unpaired:
            return Text(String(localized: "unlock_shortcut_no_target"))
        }
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                VStack(spacing: 12) {
                    Image(systemName: "lock.open.fill")
                        .font(.system(size: 48))
                        .foregroundStyle(client.isUnlockAvailable ? .green : .secondary)
                    Text(String(localized: "unlock_mac"))
                        .font(.headline)

                    if client.hasUnlockPairingKey {
                        Button {
                            client.requestUnlock()
                        } label: {
                            Label(
                                client.isAuthenticatingForUnlock
                                    ? String(localized: "unlock_authenticating")
                                    : String(localized: "unlock_mac"),
                                systemImage: "faceid"
                            )
                            .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!client.isUnlockAvailable || client.isAuthenticatingForUnlock)

                        shortcutTargetCaption
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        Toggle(String(localized: "unlock_shortcut_require_faceid"), isOn: $requireFaceIDForShortcut)
                            .font(.caption)

                        Button(String(localized: "unlock_forget_pairing"), role: .destructive) {
                            client.removeUnlockPairingKey()
                        }
                        .font(.caption)
                    } else {
                        TextField(String(localized: "unlock_pairing_key"), text: $pairingKey)
                            .textInputAutocapitalization(.characters)
                            .autocorrectionDisabled()
                            .textFieldStyle(.roundedBorder)

                        Button(String(localized: "unlock_save_pairing")) {
                            pairingKeyError = !client.saveUnlockPairingKey(pairingKey)
                            if !pairingKeyError {
                                pairingKey = ""
                            }
                        }
                        .buttonStyle(.bordered)

                    }

                    if !client.hasUnlockPairingKey {
                        shortcutTargetCaption
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    if let status = client.unlockStatus {
                        Text(status)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color(.systemGray6))
                .cornerRadius(20)
            }
            .padding()
        }
    }
}
