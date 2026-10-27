import XCTest
@testable import RottenCoreKit

final class RottenCoreKitTests: XCTestCase {
    let untrusted = """
    {"ok":true,"result":{"path":"/tmp/RedX.dmg","kind":"dmg","appId":"com.redxai.redx","name":"RedX","version":"0.4.3","source":"github",
     "detectedBy":["manifest:embedded:dmg"],"manifest":{"schema":1},"github":{"owner":"grimvirusoffical-source","repo":"RedX","tag":"v0.4.3"},
     "verdict":{"sha256":"ab","bytes":10,"expected":[{"from":"github-sha256sums","sha256":"ab"}],"checksum":"match","trusted":false,
     "warning":"RottenCore doesn't trust this app: it isn't from the Rotten Apple store.","reasons":["matches the SHA256SUMS of the GitHub release"],"refuse":false},
     "problems":[]}}
    """

    func testDecodeInspectionAndGate() throws {
        let i = try RottenCoreCLI.decode(Data(untrusted.utf8), as: Inspection.self)
        XCTAssertEqual(i.appId, "com.redxai.redx")
        XCTAssertEqual(i.github?.repo, "RedX")
        XCTAssertFalse(i.verdict.trusted)
        XCTAssertEqual(InstallGate.evaluate(i.verdict, accepted: false), .needsAcceptance(InstallGate.untrustedWarning))
        XCTAssertEqual(InstallGate.evaluate(i.verdict, accepted: true), .ready)
        var refused = i.verdict
        refused.refuse = true
        if case .refused = InstallGate.evaluate(refused, accepted: true) {} else { XCTFail("a mismatch must never be installable") }
        var trusted = i.verdict
        trusted.trusted = true
        trusted.warning = nil
        XCTAssertEqual(InstallGate.evaluate(trusted, accepted: false), .ready)
    }

    func testErrorsMapToCases() {
        let u = #"{"ok":false,"error":"untrusted","code":"untrusted"}"#
        XCTAssertThrowsError(try RottenCoreCLI.decode(Data(u.utf8), as: Inspection.self)) { e in
            XCTAssertEqual(e as? RottenCoreError, .untrusted("untrusted"))
        }
        let r = #"{"ok":false,"error":"mismatch","code":"refused"}"#
        XCTAssertThrowsError(try RottenCoreCLI.decode(Data(r.utf8), as: Inspection.self)) { e in
            XCTAssertEqual(e as? RottenCoreError, .refused("mismatch"))
        }
    }

    func testDecodeInstalledList() throws {
        let j = """
        {"ok":true,"result":[{"appId":"com.acme.tool","name":"Tool","version":"1.0.0","source":"github","trusted":false,"acceptedRisk":true,
        "kind":"zip","paths":["/Applications/Tool.app"],"codesign":{"signed":false,"valid":false,"gatekeeper":"skipped","detail":"not code-signed"},
        "installedAt":"2026-10-19T12:00:00.123456789Z","updatedAt":"2026-10-19T12:00:00Z"}]}
        """
        let l = try RottenCoreCLI.decode(Data(j.utf8), as: [InstalledApp].self)
        XCTAssertEqual(l.first?.paths, ["/Applications/Tool.app"])
        XCTAssertEqual(l.first?.codesign?.gatekeeper, "skipped")
    }

    func testArgumentsAlwaysJSONAndPasswordDialog() {
        XCTAssertEqual(RottenCoreCLI.arguments(["list"]), ["list", "--json", "--admin", "osascript"])
    }

    func testThemeDefaultIsDark() {
        XCTAssertEqual(Theme.allCases.first, .dark)
    }

    func testSignPaletteIsCharcoalCrimsonBone() {
        XCTAssertEqual(SignPalette.charcoal, SignPalette.RGB(0x0C, 0x0D, 0x10))
        XCTAssertEqual(SignPalette.crimson, SignPalette.RGB(0xE2, 0x3B, 0x3B))
        XCTAssertEqual(SignPalette.bone, SignPalette.RGB(0xEC, 0xE8, 0xE4))
        XCTAssertEqual(SignGate.officialNote, "Official OS signing is still recommended. This overlay works either way.")
    }

    func testSignGateKeepsDevelopersOnTheLauncher() {
        XCTAssertEqual(
            SignGate.withoutLauncher(role: "dev", agentRunning: true),
            .disabled("Developers sign with the Rotten Apple launcher.")
        )
        XCTAssertEqual(
            SignGate.withoutLauncher(role: "owner", agentRunning: false),
            .disabled("Unlock the lifetime cert first.")
        )
        XCTAssertEqual(SignGate.withoutLauncher(role: "owner", agentRunning: true), .enabled)
        XCTAssertEqual(
            SignGate.withLauncher(role: "dev", launcherInstalled: true, launcherRunning: true, agentRunning: false),
            .disabled("An owner has to unlock signing on this Mac.")
        )
        XCTAssertEqual(
            SignGate.withLauncher(role: "owner", launcherInstalled: true, launcherRunning: false, agentRunning: false),
            .disabled("Unlock the lifetime cert first.")
        )
        XCTAssertEqual(
            SignGate.withLauncher(role: "owner", launcherInstalled: false, launcherRunning: false, agentRunning: true),
            .disabled("The Rotten Apple launcher has to be installed and running.")
        )
        XCTAssertEqual(
            SignGate.withLauncher(role: "dev", launcherInstalled: true, launcherRunning: true, agentRunning: true),
            .enabled
        )
        XCTAssertEqual(
            SignGate.withLauncher(role: "owner", launcherInstalled: true, launcherRunning: true, agentRunning: true),
            .enabled
        )
    }

    func testAgentHandshakeFramesTokenThenPassword() {
        let data = AgentHandshake.frames(token: "ab", password: "c")
        XCTAssertEqual([UInt8](data), [0, 0, 0, 2, 0x61, 0x62, 0, 0, 0, 1, 0x63])
    }

    func testDecodeSignResult() throws {
        let j = """
        {"ok":true,"result":{"type":"rotten_core_signed","sigId":"rxa_ab","appId":"com.redx.app","version":"1.2.3","hash":"aa","platforms":["macos"],"launcherRequired":false,"certId":"cert-1","output":"/tmp/a.rotten_core_signed","officialOSSigning":"Official OS signing is still recommended. This overlay works either way.","prevSigId":"rxa_prev"}}
        """
        let r = try RottenCoreCLI.decode(Data(j.utf8), as: SignResult.self)
        XCTAssertEqual(r.type, "rotten_core_signed")
        XCTAssertEqual(r.sigId, "rxa_ab")
        XCTAssertEqual(r.appId, "com.redx.app")
        XCTAssertFalse(r.launcherRequired)
        XCTAssertEqual(r.prevSigId, "rxa_prev")
        XCTAssertEqual(r.officialOSSigning, SignGate.officialNote)
        let who = """
        {"ok":true,"result":{"role":"owner","email":"support@infected-nation.com","verified":true,"idVerified":true,"idVerifiedMs":1700000000000,"mfa":true,"platforms":["macos","ios"],"launcherInstalled":false,"launcherRunning":false,"agentRunning":true,"officialOSSigning":"Official OS signing is still recommended. This overlay works either way."}}
        """
        let id = try RottenCoreCLI.decode(Data(who.utf8), as: SignIdentity.self)
        XCTAssertEqual(id.role, "owner")
        XCTAssertEqual(id.platforms, ["macos", "ios"])
        XCTAssertTrue(id.agentRunning)
        XCTAssertFalse(id.launcherInstalled)
    }

    /// Runs the real engine when CI provides it (ROTTENCORE_BIN), against a private support folder.
    func testRealBinary() async throws {
        guard let bin = ProcessInfo.processInfo.environment["ROTTENCORE_BIN"] else { throw XCTSkip("ROTTENCORE_BIN not set") }
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("rc-\(UUID().uuidString)")
        var env = ProcessInfo.processInfo.environment
        env["ROTTENCORE_HOME"] = home.path
        let cli = try RottenCoreCLI(binary: URL(fileURLWithPath: bin), environment: env)
        let l = try await cli.list()
        XCTAssertEqual(l, [])
        // a zipped app with no manifest: unknown source, no checksum, not trusted
        let work = home.appendingPathComponent("w")
        let app = work.appendingPathComponent("Probe.app/Contents/MacOS")
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        try Data("#!/bin/sh\n".utf8).write(to: app.appendingPathComponent("Probe"))
        let zip = home.appendingPathComponent("Probe.zip")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        p.arguments = ["-c", "-k", "--keepParent", work.appendingPathComponent("Probe.app").path, zip.path]
        try p.run(); p.waitUntilExit()
        let i = try await cli.inspect(zip)
        XCTAssertEqual(i.source, "unknown")
        XCTAssertFalse(i.verdict.trusted)
        XCTAssertEqual(i.verdict.warning, InstallGate.untrustedWarning)
        do {
            _ = try await cli.install(zip, acceptUntrusted: false)
            XCTFail("installed without accepting")
        } catch RottenCoreError.untrusted {}
    }
}
