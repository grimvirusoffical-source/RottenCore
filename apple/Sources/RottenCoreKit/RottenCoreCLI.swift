import Foundation

public enum RottenCoreError: Error, LocalizedError, Equatable {
    case binaryMissing
    case untrusted(String)
    case refused(String)
    case failed(String)

    public var errorDescription: String? {
        switch self {
        case .binaryMissing: return "The rottencore engine is missing from this app."
        case .untrusted(let m), .refused(let m), .failed(let m): return m
        }
    }
}

struct Envelope<T: Decodable>: Decodable {
    var ok: Bool
    var result: T?
    var error: String?
    var code: String?
}

/// Runs the bundled `rottencore` binary with `--json`. One engine for the app, the command line and every
/// Red-XAI app that embeds RottenCore.
public final class RottenCoreCLI {
    public let binary: URL
    public var environment: [String: String]

    public init(binary: URL? = nil, environment: [String: String] = ProcessInfo.processInfo.environment) throws {
        if let b = binary {
            self.binary = b
        } else if let env = environment["ROTTENCORE_BIN"] {
            self.binary = URL(fileURLWithPath: env)
        } else if let b = Bundle.main.url(forResource: "rottencore", withExtension: nil) {
            self.binary = b
        } else {
            throw RottenCoreError.binaryMissing
        }
        self.environment = environment
    }

    /// Arguments for a command; always JSON, and the macOS password dialog for anything that needs root.
    public static func arguments(_ command: [String]) -> [String] {
        command + ["--json", "--admin", "osascript"]
    }

    public static func decode<T: Decodable>(_ data: Data, as: T.Type) throws -> T {
        let env: Envelope<T>
        do {
            env = try JSONDecoder().decode(Envelope<T>.self, from: data)
        } catch {
            throw RottenCoreError.failed("RottenCore answered something unreadable: \(error.localizedDescription)")
        }
        if env.ok, let r = env.result { return r }
        let msg = env.error ?? "RottenCore failed"
        switch env.code {
        case "untrusted": throw RottenCoreError.untrusted(msg)
        case "refused": throw RottenCoreError.refused(msg)
        default: throw RottenCoreError.failed(msg)
        }
    }

    public func run<T: Decodable>(_ command: [String], as: T.Type) async throws -> T {
        let bin = binary, env = environment
        let data: Data = try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = bin
                p.arguments = RottenCoreCLI.arguments(command)
                p.environment = env
                let pipe = Pipe()
                p.standardOutput = pipe
                p.standardError = FileHandle.nullDevice
                do {
                    try p.run()
                } catch {
                    cont.resume(throwing: RottenCoreError.failed(error.localizedDescription))
                    return
                }
                let d = pipe.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                cont.resume(returning: d)
            }
        }
        return try RottenCoreCLI.decode(data, as: T.self)
    }

    public func inspect(_ file: URL) async throws -> Inspection {
        try await run(["inspect", file.path], as: Inspection.self)
    }

    public func install(_ file: URL, acceptUntrusted: Bool, userApplications: Bool = false) async throws -> InstalledApp {
        var c = ["install", file.path, "--yes"]
        if acceptUntrusted { c.append("--accept-untrusted") }
        if userApplications { c.append("--user") }
        return try await run(c, as: InstalledApp.self)
    }

    public func installGitHub(owner: String, repo: String, acceptUntrusted: Bool) async throws -> InstalledApp {
        var c = ["install", "github:\(owner)/\(repo)", "--yes"]
        if acceptUntrusted { c.append("--accept-untrusted") }
        return try await run(c, as: InstalledApp.self)
    }

    public func list() async throws -> [InstalledApp] { try await run(["list"], as: [InstalledApp].self) }
    public func checkUpdates() async throws -> [UpdateInfo] { try await run(["check-updates"], as: [UpdateInfo].self) }

    public func update(_ appId: String, acceptUntrusted: Bool) async throws -> InstalledApp {
        var c = ["update", appId, "--yes"]
        if acceptUntrusted { c.append("--accept-untrusted") }
        return try await run(c, as: InstalledApp.self)
    }

    public func uninstall(_ appId: String) async throws -> InstalledApp { try await run(["uninstall", appId], as: InstalledApp.self) }
    public func search(_ q: String) async throws -> [Listing] { try await run(["search", q], as: [Listing].self) }

    /// Loads and runs a QuickLaunch build request from the inbox (`rottencore build-inbox <id>`).
    /// `confirmed` must be true (adds `--yes`); the app shows a confirmation sheet first (QA v2 N3).
    /// Signing flags come from Rotten Core's config / support dir when the shell env is empty (QA v2 N2).
    public func buildInbox(id: String, confirmed: Bool = false) async throws -> Outcome {
        guard BuildInbox.validateID(id) else {
            throw RottenCoreError.refused("build id must be 8-64 characters of [A-Za-z0-9_-]")
        }
        guard confirmed else {
            throw RottenCoreError.refused("confirm the build before it runs")
        }
        var args = ["build-inbox", id, "--yes"]
        let signing = SigningConfig.resolve(environment: environment)
        if let label = signing.label, !label.isEmpty {
            args += ["--keychain", "--label", label]
        }
        if let bundle = signing.bundle, !bundle.isEmpty {
            args += ["--bundle", bundle]
        }
        if signing.bundle == nil || signing.bundle?.isEmpty == true {
            throw RottenCoreError.failed(signing.errorMessage ?? "Signing is not set up: save a certificate bundle path in Rotten Core's config (signing.bundle) or support dir, or register a device with a Keychain label.")
        }
        struct BuildEnvelope: Decodable {
            var result: BuildResult?
        }
        struct BuildResult: Decodable {
            var sumsPath: String?
            var artifacts: [BuildArtifact]?
        }
        struct BuildArtifact: Decodable {
            var filename: String?
        }
        // N6: empty or unreadable output is an error, not "Build started".
        let env: BuildEnvelope = try await run(args, as: BuildEnvelope.self)
        let sums = env.result?.sumsPath ?? "(no SHA256SUMS path)"
        return Outcome(kind: .success, title: "Build finished", detail: "Request \(id) built and signed. \(sums)")
    }

    /// Live rollback of a hosted rollout through `rottencore host rollback <id>` (the updater's rollout card).
    /// The host URL and key come from the environment (RA_HOST_URL / RA_HOST_KEY); the key is never shown.
    public func hostRollback(_ rolloutID: String, reason: String? = nil) async throws -> HostRollbackResult {
        var c = ["host", "rollback", rolloutID]
        if let r = reason, !r.isEmpty { c.append(r) }
        return try await run(c, as: HostRollbackResult.self)
    }

    /// One hosted app's live rollout status (`rottencore host rollout <id>`).
    public func hostRollout(_ rolloutID: String) async throws -> HostRollout {
        try await run(["host", "rollout", rolloutID], as: HostRollout.self)
    }
}
