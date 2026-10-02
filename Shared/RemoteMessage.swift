import Foundation

/// Messages sent from iOS client to macOS server
enum RemoteMessage: Codable {
    case ping
    case unlock(signature: Data)
}

/// Messages sent from macOS server to iOS client
enum ServerMessage: Codable {
    case connected(screenWidth: Double, screenHeight: Double, unlockChallenge: Data?, unlockAvailable: Bool, serverId: String?)
    case pong
    case error(message: String)
    case unlockResult(success: Bool, message: String, code: UnlockResultCode?)
    case unlockChallenge(Data)
}

/// Protocol message wrapper with length prefix for TCP framing
struct MessageFrame {
    static func encode<T: Encodable>(_ message: T) throws -> Data {
        let jsonData = try JSONEncoder().encode(message)
        var length = UInt32(jsonData.count).bigEndian
        var frameData = Data(bytes: &length, count: 4)
        frameData.append(jsonData)
        return frameData
    }

    static func decode<T: Decodable>(_ data: Data, as type: T.Type) throws -> T {
        return try JSONDecoder().decode(type, from: data)
    }
}
