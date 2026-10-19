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

/// The trust rule the app enforces before it lets anyone press Install (the engine enforces it again).
public enum InstallGate: Equatable {
    case refused(String)          // checksum mismatch: never installable
    case needsAcceptance(String)  // untrusted: the person must accept the warning
    case ready

    public static let untrustedWarning = "Rotten Core doesn't trust this app: it isn't from the Rotten Apple store."

    public static func evaluate(_ v: Verdict, accepted: Bool) -> InstallGate {
        if v.refuse { return .refused("The file's checksum does not match. It was changed or damaged and will not be installed.") }
        if !v.trusted && !accepted { return .needsAcceptance(v.warning ?? untrustedWarning) }
        return .ready
    }
}

// MARK: - Hosted updates (M4) — mirrors core.HostRollout / RolloutHealth in the Go client.

/// Health rates are nullable: when the host has not reported yet they are nil and the UI shows
/// "awaiting health data" instead of promoting anything (core.RolloutHealth.Known()).
public struct RolloutHealth: Codable, Equatable {
    public var successRate: Double?
    public var errorRate: Double?
    public var crashRate: Double?
    public var samples: Int?

    enum CodingKeys: String, CodingKey {
        case successRate = "success_rate"
        case errorRate = "error_rate"
        case crashRate = "crash_rate"
        case samples
    }

    /// The number of canary samples before health is considered known (Go core.CanaryMinSamples).
    public static let minSamples = 20

    public init(successRate: Double? = nil, errorRate: Double? = nil, crashRate: Double? = nil, samples: Int? = nil) {
        self.successRate = successRate; self.errorRate = errorRate; self.crashRate = crashRate; self.samples = samples
    }

    /// True only once the host has real rates AND at least minSamples canary samples. Mirrors Go
    /// RolloutHealth.Known() after fbc2098.
    public var known: Bool {
        (samples ?? 0) >= RolloutHealth.minSamples && (successRate != nil || errorRate != nil || crashRate != nil)
    }
}

/// One app's hosted rollout. `awaitingHealthData` means nothing auto-promotes yet.
public struct HostRollout: Codable, Equatable, Identifiable {
    public var id: String { rolloutID.isEmpty ? appId : rolloutID }
    public var rolloutID: String    // the host rollout id, for a live rollback
    public var appId: String
    public var version: String
    public var phase: String        // staged | rolling | promoted | rolledback | failed
    public var fromVersion: String?
    public var health: RolloutHealth
    public var updatedAt: String?

    enum CodingKeys: String, CodingKey {
        case rolloutID = "rollout_id"
        case appId = "app"
        case version
        case phase = "state"
        case fromVersion
        case health
        case updatedAt
    }

    public init(rolloutID: String = "", appId: String, version: String, phase: String, fromVersion: String? = nil, health: RolloutHealth = RolloutHealth(), updatedAt: String? = nil) {
        self.rolloutID = rolloutID; self.appId = appId; self.version = version; self.phase = phase; self.fromVersion = fromVersion; self.health = health; self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        rolloutID = (try? c.decode(String.self, forKey: .rolloutID)) ?? ""
        appId = (try? c.decode(String.self, forKey: .appId)) ?? ""
        version = (try? c.decode(String.self, forKey: .version)) ?? ""
        phase = (try? c.decode(String.self, forKey: .phase)) ?? ""
        fromVersion = try? c.decode(String.self, forKey: .fromVersion)
        // health may be null (the host has not reported yet)
        health = (try? c.decode(RolloutHealth.self, forKey: .health)) ?? RolloutHealth()
        updatedAt = try? c.decode(String.self, forKey: .updatedAt)
    }

    /// Mirrors Go HostRollout.AwaitingHealthData: no known health yet (nothing auto-promotes).
    public var awaitingHealthData: Bool { !health.known }

    public var healthSummary: String {
        if !health.known { return "awaiting health data" }
        func pct(_ v: Double?) -> String { v.map { String(format: "%.1f%%", $0 * 100) } ?? "—" }
        return "success \(pct(health.successRate)) · error \(pct(health.errorRate)) · crash \(pct(health.crashRate))"
    }
}

/// Where an update may come from. On a hosted app the picker offers all three; GitHub is untrusted.
public enum UpdateSource: String, CaseIterable, Identifiable, Codable {
    case host = "Rotten Apple store"
    case github = "GitHub release"
    case both = "Store, then GitHub"
    public var id: String { rawValue }
}

/// The result card shown after an install, update, upload or rollout step.
public struct Outcome: Identifiable, Equatable {
    public enum Kind: Equatable { case success, failure, info, awaiting }
    public var id = UUID()
    public var kind: Kind
    public var title: String
    public var detail: String

    public init(kind: Kind, title: String, detail: String) {
        self.kind = kind; self.title = title; self.detail = detail
    }
}


/// What `rottencore host rollback` returns.
public struct HostRollbackResult: Codable, Equatable {
    public var rolledBack: String
    public init(rolledBack: String) { self.rolledBack = rolledBack }
}
