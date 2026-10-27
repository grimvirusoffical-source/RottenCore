import Foundation

/// Mirrors the JSON the `rottencore` command line prints with `--json` (see docs/ROTTENCORE.md).
public struct Verdict: Codable, Equatable {
    public var sha256: String
    public var bytes: Int64
    public var expected: [Expected]
    public var checksum: String // match | mismatch | none
    public var trusted: Bool
    public var trustedBy: String?
    public var warning: String?
    public var reasons: [String]
    public var refuse: Bool

    public struct Expected: Codable, Equatable {
        public var from: String
        public var sha256: String
        public var bytes: Int64?
    }
}

public struct GitHubRef: Codable, Equatable {
    public var owner: String
    public var repo: String
    public var tag: String?
    public var asset: String?
    public var assetPattern: String?
}

public struct StoreRef: Codable, Equatable {
    public var url: String?
    public var listingId: Int64?
}

public struct Listing: Codable, Equatable, Identifiable {
    public var id: Int64
    public var appId: String
    public var name: String
    public var tagline: String
    public var ageRating: String
    public var priceCents: Int64
    public var version: String
}

public struct Inspection: Codable, Equatable {
    public var path: String
    public var kind: String
    public var appId: String
    public var name: String
    public var version: String
    public var source: String // store | github | unknown
    public var detectedBy: [String]
    public var github: GitHubRef?
    public var releaseUrl: String?
    public var store: StoreRef?
    public var listing: Listing?
    public var ageRating: String?
    public var minMacOS: String?
    public var verdict: Verdict
    public var problems: [String]
}

public struct Codesign: Codable, Equatable {
    public var signed: Bool
    public var valid: Bool
    public var gatekeeper: String
    public var detail: String?
}

public struct InstalledApp: Codable, Equatable, Identifiable {
    public var id: String { appId }
    public var appId: String
    public var name: String
    public var version: String
    public var source: String
    public var trusted: Bool
    public var trustedBy: String?
    public var acceptedRisk: Bool
    public var kind: String
    public var artifactName: String?
    public var sha256: String?
    public var paths: [String]
    public var pkgIds: [String]?
    public var github: GitHubRef?
    public var store: StoreRef?
    public var ageRating: String?
    public var codesign: Codesign?
    public var managed: String?
    public var installedAt: String
    public var updatedAt: String
}

public struct UpdateInfo: Codable, Equatable, Identifiable {
    public var id: String { appId }
    public var appId: String
    public var name: String
    public var source: String
    public var installed: String
    public var available: String?
    public var newer: Bool
    public var asset: String?
    public var error: String?
}

public struct SignIdentity: Codable, Equatable {
    public var role: String
    public var email: String
    public var verified: Bool
    public var idVerified: Bool
    public var idVerifiedMs: Int64
    public var mfa: Bool
    public var platforms: [String]
    public var launcherInstalled: Bool
    public var launcherRunning: Bool
    public var agentRunning: Bool
    public var officialOSSigning: String
}

public struct SignResult: Codable, Equatable {
    public var type: String
    public var sigId: String
    public var appId: String
    public var version: String
    public var hash: String
    public var platforms: [String]
    public var launcherRequired: Bool
    public var certId: String
    public var output: String
    public var officialOSSigning: String
    public var prevSigId: String?
}

public struct AgentAck: Codable, Equatable {
    public var stopped: Bool
}

/// The trust rule the app enforces before it lets anyone press Install (the engine enforces it again).
public enum InstallGate: Equatable {
    case refused(String)          // checksum mismatch: never installable
    case needsAcceptance(String)  // untrusted: the person must accept the warning
    case ready

    public static let untrustedWarning = "RottenCore doesn't trust this app: it isn't from the Rotten Apple store."

    public static func evaluate(_ v: Verdict, accepted: Bool) -> InstallGate {
        if v.refuse { return .refused("The file's checksum does not match. It was changed or damaged and will not be installed.") }
        if !v.trusted && !accepted { return .needsAcceptance(v.warning ?? untrustedWarning) }
        return .ready
    }
}
