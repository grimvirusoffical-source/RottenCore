import Foundation

/// Where the app-launched hand-off finds the signing bundle and Keychain label without shell vars (QA v2 N2).
/// Precedence: process environment, then `<support>/config.json` `signing` object, then
/// `<support>/signing.json`, then the Keychain label recorded at device registration (`devhub/device.json`).
public struct SigningConfig: Equatable {
    public var bundle: String?
    public var label: String?
    public var service: String?
    public var errorMessage: String?

    public static func resolve(environment env: [String: String] = ProcessInfo.processInfo.environment,
                               support: URL = RottenCorePaths.supportDir(),
                               fileManager fm: FileManager = .default) -> SigningConfig {
        var c = SigningConfig()
        c.bundle = nonEmpty(env["ROTTENCORE_SIGN_BUNDLE"])
        c.label = nonEmpty(env["ROTTENCORE_SIGN_LABEL"])
        c.service = nonEmpty(env["ROTTENCORE_SIGN_SERVICE"])

        if c.bundle == nil || c.label == nil {
            if let cfg = readJSON(support.appendingPathComponent("config.json"), fm: fm) {
                if let signing = cfg["signing"] as? [String: Any] {
                    if c.bundle == nil { c.bundle = nonEmpty(signing["bundle"] as? String) }
                    if c.label == nil { c.label = nonEmpty(signing["label"] as? String) }
                    if c.service == nil { c.service = nonEmpty(signing["service"] as? String) }
                }
                // Flat keys also accepted.
                if c.bundle == nil { c.bundle = nonEmpty(cfg["signBundle"] as? String) }
                if c.label == nil { c.label = nonEmpty(cfg["signLabel"] as? String) }
            }
        }
        if c.bundle == nil || c.label == nil {
            if let cfg = readJSON(support.appendingPathComponent("signing.json"), fm: fm) {
                if c.bundle == nil { c.bundle = nonEmpty(cfg["bundle"] as? String) }
                if c.label == nil { c.label = nonEmpty(cfg["label"] as? String) }
                if c.service == nil { c.service = nonEmpty(cfg["service"] as? String) }
            }
        }
        if c.label == nil {
            // Device registration records the Keychain label under devhub/device.json.
            if let device = readJSON(support.appendingPathComponent("devhub/device.json"), fm: fm) {
                c.label = nonEmpty(device["keychainLabel"] as? String) ?? nonEmpty(device["label"] as? String)
            }
        }
        if c.bundle == nil || (c.bundle?.isEmpty ?? true) {
            c.errorMessage = "Signing is not set up: save a certificate bundle path in Rotten Core's config (signing.bundle) or \(support.path)/signing.json, or set ROTTENCORE_SIGN_BUNDLE. A Keychain label from device registration is used when present."
        }
        return c
    }

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }

    private static func readJSON(_ url: URL, fm: FileManager) -> [String: Any]? {
        guard fm.fileExists(atPath: url.path),
              let data = try? Data(contentsOf: url),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let dict = obj as? [String: Any] else { return nil }
        return dict
    }
}
