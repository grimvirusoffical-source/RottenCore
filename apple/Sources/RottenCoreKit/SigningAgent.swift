import Foundation

/// Frames the Mac app writes to `rottencore agent`. The password and token are not arguments.
public enum AgentHandshake {
    public static func frames(token: String, password: String) -> Data {
        var data = Data()
        append(&data, Array(token.utf8))
        append(&data, Array(password.utf8))
        return data
    }

    private static func append(_ data: inout Data, _ bytes: [UInt8]) {
        var n = UInt32(bytes.count).bigEndian
        withUnsafeBytes(of: &n) { data.append(contentsOf: $0) }
        data.append(contentsOf: bytes)
    }
}

/// The in-memory signing agent. The app keeps this process for the login; leaving the
/// Sign section does not stop it. Sign-out does.
public final class SigningAgent {
    private var process: Process?
    public init() {}

    public var isRunning: Bool { process?.isRunning ?? false }

    public func start(binary: URL, environment: [String: String], token: String, password: String) throws {
        if isRunning { return }
        let p = Process()
        p.executableURL = binary
        p.arguments = ["agent"]
        var env = environment
        env.removeValue(forKey: "ROTTENCORE_ACCESS_TOKEN")
        p.environment = env
        let input = Pipe()
        let errors = Pipe()
        p.standardInput = input
        p.standardOutput = FileHandle.nullDevice
        p.standardError = errors
        try p.run()
        try input.fileHandleForWriting.write(contentsOf: AgentHandshake.frames(token: token, password: password))
        try input.fileHandleForWriting.close()
        let started = Date()
        while p.isRunning && Date().timeIntervalSince(started) < 0.3 {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if !p.isRunning {
            let data = errors.fileHandleForReading.readDataToEndOfFile()
            var text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if text.isEmpty || text.contains(password) || text.contains(token) {
                text = "The signing agent stopped."
            }
            throw RottenCoreError.failed(text)
        }
        process = p
    }

    public func stop(using cli: RottenCoreCLI) async {
        _ = try? await cli.stopAgent()
        process?.terminate()
        process = nil
    }
}
