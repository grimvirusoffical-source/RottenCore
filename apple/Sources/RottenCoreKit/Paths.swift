import Foundation

/// Rotten Core's support directory, resolved exactly like Go's `core.SupportDir` (macOS layout):
/// `ROTTENCORE_HOME`, then its alias `ROTTENCORE_SUPPORT_DIR` (QuickLaunch honours both, in this order),
/// otherwise `~/Library/Application Support/RottenCore`.
public enum RottenCorePaths {
    public static func supportDir(environment env: [String: String] = ProcessInfo.processInfo.environment,
                                  home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        for key in ["ROTTENCORE_HOME", "ROTTENCORE_SUPPORT_DIR"] {
            if let v = env[key], !v.isEmpty { return URL(fileURLWithPath: v, isDirectory: true) }
        }
        return home.appendingPathComponent("Library/Application Support/RottenCore", isDirectory: true)
    }
}
