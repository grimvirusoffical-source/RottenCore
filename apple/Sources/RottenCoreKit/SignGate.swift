import Foundation

/// Button rules for lifetime signing. The engine enforces the same rules again.
public enum SignControl: Equatable {
    case enabled
    case disabled(String)
}

/// Charcoal, crimson and bone for the Sign panel.
public enum SignPalette {
    public struct RGB: Equatable {
        public let r, g, b: Int
        public init(_ r: Int, _ g: Int, _ b: Int) {
            self.r = r
            self.g = g
            self.b = b
        }
    }

    public static let charcoal = RGB(0x0C, 0x0D, 0x10)
    public static let crimson = RGB(0xE2, 0x3B, 0x3B)
    public static let bone = RGB(0xEC, 0xE8, 0xE4)
}

public enum SignGate {
    public static let officialNote = "Official OS signing is still recommended. This overlay works either way."

    /// Developers cannot produce a signature that leaves the launcher out.
    /// Launcher detection turns on "Sign with launcher"; it does not turn on "without launcher".
    public static func withoutLauncher(role: String, agentRunning: Bool) -> SignControl {
        guard role == "owner" else {
            return .disabled("Developers sign with the Rotten Apple launcher.")
        }
        guard agentRunning else {
            return .disabled("Unlock the lifetime cert first.")
        }
        return .enabled
    }

    public static func withLauncher(role: String, launcherInstalled: Bool, launcherRunning: Bool, agentRunning: Bool) -> SignControl {
        guard agentRunning else {
            if role == "owner" {
                return .disabled("Unlock the lifetime cert first.")
            }
            return .disabled("An owner has to unlock signing on this Mac.")
        }
        guard launcherInstalled && launcherRunning else {
            return .disabled("The Rotten Apple launcher has to be installed and running.")
        }
        return .enabled
    }
}
