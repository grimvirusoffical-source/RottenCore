import Foundation

/// Strict build-id format shared with Go `builder.BuildIDRe` (QA v2 N3). Anything with path separators,
/// dots or spaces is refused before it touches the disk.
public enum BuildInbox {
    public static let idPattern = "\\A[A-Za-z0-9_-]{8,64}\\z"
    private static let idRegex = try! NSRegularExpression(pattern: idPattern)

    public static func validateID(_ id: String) -> Bool {
        let range = NSRange(id.startIndex..<id.endIndex, in: id)
        return idRegex.firstMatch(in: id, options: [], range: range) != nil
    }

    /// Resolves `<support>/build-requests/<id>.json`, refusing traversal, symlinks that escape the inbox,
    /// and files that are not owner-only mode 0600. The JSON `id` must equal the file name.
    public static func resolveRequest(id: String,
                                      support: URL = RottenCorePaths.supportDir(),
                                      fileManager fm: FileManager = .default) throws -> (url: URL, preview: BuildPreview) {
        guard validateID(id) else {
            throw RottenCoreError.refused("build id must be 8-64 characters of [A-Za-z0-9_-]")
        }
        let inbox = support.appendingPathComponent("build-requests", isDirectory: true)
        let url = inbox.appendingPathComponent(id + ".json", isDirectory: false)
        let inboxPath = inbox.resolvingSymlinksInPath().standardizedFileURL.path
        // Refuse if the leaf itself is a symlink (EvalSymlinks on the file would chase it outside).
        if fm.fileExists(atPath: url.path) {
            if let attrs = try? fm.attributesOfItem(atPath: url.path),
               let t = attrs[.type] as? FileAttributeType, t == .typeSymbolicLink {
                throw RottenCoreError.refused("build request must not be a symlink")
            }
        }
        let resolved = url.resolvingSymlinksInPath().standardizedFileURL
        let resolvedPath = resolved.path
        guard resolvedPath.hasPrefix(inboxPath.hasSuffix("/") ? inboxPath : inboxPath + "/") || resolvedPath == inboxPath + "/" + id + ".json"
                || resolved.deletingLastPathComponent().path == inboxPath else {
            throw RottenCoreError.refused("build request path escapes the inbox")
        }
        guard fm.fileExists(atPath: resolved.path) else {
            throw RottenCoreError.failed("No build request \"\(id)\" in the Rotten Core inbox.")
        }
        let attrs = try fm.attributesOfItem(atPath: resolved.path)
        if let t = attrs[.type] as? FileAttributeType, t != .typeRegular {
            throw RottenCoreError.refused("build request must be a regular file owned by you with mode 0600")
        }
        if let perms = attrs[.posixPermissions] as? NSNumber {
            let mode = perms.uint16Value & 0o777
            if mode & 0o077 != 0 {
                throw RottenCoreError.refused("build request must be a regular file owned by you with mode 0600")
            }
        }
        let data = try Data(contentsOf: resolved)
        let preview = try JSONDecoder().decode(BuildPreview.self, from: data)
        guard preview.id == id else {
            throw RottenCoreError.refused("build request id does not match the inbox file name")
        }
        return (resolved, preview)
    }
}

/// Subset of the inbox JSON the confirmation sheet shows (app, targets, commands, project dir).
public struct BuildPreview: Codable, Equatable {
    public var schema: String?
    public var id: String
    public var project: BuildPreviewProject
    public var targets: [BuildPreviewTarget]
    public var sdks: [String]?

    public init(id: String, project: BuildPreviewProject, targets: [BuildPreviewTarget], sdks: [String]? = nil) {
        self.id = id
        self.project = project
        self.targets = targets
        self.sdks = sdks
    }
}

public struct BuildPreviewProject: Codable, Equatable {
    public var name: String
    public var id: String
    public var version: String
    public var channel: String?
    public var dir: String

    public init(name: String, id: String, version: String, channel: String? = nil, dir: String) {
        self.name = name; self.id = id; self.version = version; self.channel = channel; self.dir = dir
    }
}

public struct BuildPreviewTarget: Codable, Equatable {
    public var platform: String
    public var command: [String]?
    public var prebuilt: String?
    public var artifact: String?

    public init(platform: String, command: [String]? = nil, prebuilt: String? = nil, artifact: String? = nil) {
        self.platform = platform; self.command = command; self.prebuilt = prebuilt; self.artifact = artifact
    }
}
