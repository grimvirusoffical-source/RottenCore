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
