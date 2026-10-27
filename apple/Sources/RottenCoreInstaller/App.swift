import SwiftUI
import AppKit
import UniformTypeIdentifiers
import RottenCoreKit

@main
struct RottenCoreInstallerApp: App {
    @StateObject private var model = AppModel()
    @AppStorage("theme") private var theme: String = Theme.dark.rawValue

    var body: some Scene {
        WindowGroup("RottenCore Installer") {
            ContentView()
                .environmentObject(model)
                .preferredColorScheme(scheme)
                .frame(minWidth: 820, minHeight: 540)
                .onOpenURL { url in model.open(url) }
        }
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open Installer File…") { model.pickFile() }.keyboardShortcut("o")
            }
        }
    }

    private var scheme: ColorScheme? {
        switch Theme(rawValue: theme) ?? .dark {
        case .dark: return .dark
        case .light: return .light
        case .system: return nil
        }
    }
}

enum SidebarItem: String, CaseIterable, Identifiable {
    case install = "Install", installed = "Installed", updates = "Updates", store = "Store", sign = "Sign", settings = "Settings"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .install: return "square.and.arrow.down"
        case .installed: return "square.grid.2x2"
        case .updates: return "arrow.triangle.2.circlepath"
        case .store: return "bag"
        case .sign: return "signature"
        case .settings: return "gearshape"
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    @Published var section: SidebarItem? = .install
    @Published var inspection: Inspection?
    @Published var accepted = false
    @Published var busy: String?
    @Published var message: String?
    @Published var error: String?
    @Published var installed: [InstalledApp] = []
    @Published var updates: [UpdateInfo] = []
    @Published var results: [Listing] = []
    @Published var signSession: SignIdentity?
    @Published var signFile: URL?
    @Published var signPlatform = ""
    let accounts: AccountProvider = RedXAIAccountsStub()
    /// Kept for the login. Changing sidebar sections does not stop it. Sign-out does.
    let signingAgent = SigningAgent()
    private var cli: RottenCoreCLI?

    init() {
        cli = try? RottenCoreCLI()
        if cli == nil { error = RottenCoreError.binaryMissing.errorDescription }
        // An app that embeds RottenCore starts it with the file to install as the first argument.
        let args = CommandLine.arguments.dropFirst().filter { !$0.hasPrefix("-") }
        if let f = args.first, FileManager.default.fileExists(atPath: f) { Task { await self.inspect(URL(fileURLWithPath: f)) } }
        Task {
            await refresh()
            await refreshSignSession(quiet: true)
        }
    }

    func open(_ url: URL) { if url.isFileURL { Task { await inspect(url) } } }

    func pickFile() {
        let p = NSOpenPanel()
        p.allowedContentTypes = ["dmg", "pkg", "zip", "app", "rarxai"].compactMap { UTType(filenameExtension: $0) }
        p.treatsFilePackagesAsDirectories = false
        if p.runModal() == .OK, let u = p.url { Task { await inspect(u) } }
    }

    func work<T>(_ label: String, _ f: () async throws -> T) async -> T? {
        busy = label; error = nil; message = nil
        defer { busy = nil }
        do { return try await f() } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            return nil
        }
    }

    func inspect(_ url: URL) async {
        guard let cli = cli else { return }
        section = .install
        accepted = false
        inspection = await work("Checking \(url.lastPathComponent)…") { try await cli.inspect(url) }
    }

    func installInspected() async {
        guard let cli = cli, let i = inspection else { return }
        guard case .ready = InstallGate.evaluate(i.verdict, accepted: accepted) else { return }
        if let e = await work("Installing \(i.name)…", { try await cli.install(URL(fileURLWithPath: i.path), acceptUntrusted: accepted) }) {
            message = "Installed \(e.name) \(e.version)."
            inspection = nil
            await refresh()
        }
    }

    func refresh() async {
        guard let cli = cli else { return }
        if let l = try? await cli.list() { installed = l }
    }

    func checkUpdates() async {
        guard let cli = cli else { return }
        if let u = await work("Checking for updates…", { try await cli.checkUpdates() }) { updates = u }
    }

    func update(_ u: UpdateInfo, acceptUntrusted: Bool) async {
        guard let cli = cli else { return }
        if let e = await work("Updating \(u.name)…", { try await cli.update(u.appId, acceptUntrusted: acceptUntrusted) }) {
            message = "\(e.name) is now \(e.version)."
            await refresh(); await checkUpdates()
        }
    }

    func uninstall(_ a: InstalledApp) async {
        guard let cli = cli else { return }
        if await work("Removing \(a.name)…", { try await cli.uninstall(a.appId) }) != nil {
            message = "\(a.name) was moved to the Trash."
            await refresh()
        }
    }

    func search(_ q: String) async {
        guard let cli = cli else { return }
        if let r = await work("Searching the Rotten Apple store…", { try await cli.search(q) }) { results = r }
    }

    /// Quiet failures stay off the status bar. A poll that fails does not drop a session
    /// that was already shown; sign-out clears it.
    func refreshSignSession(quiet: Bool) async {
        guard let cli = cli else { return }
        do {
            let who = try await cli.whoami()
            signSession = who
            if signPlatform.isEmpty || !who.platforms.contains(signPlatform) {
                signPlatform = who.platforms.first ?? ""
            }
        } catch {
            if !quiet {
                self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            }
        }
    }

    func pickSignFile() {
        let p = NSOpenPanel()
        p.canChooseFiles = true
        p.canChooseDirectories = true
        p.treatsFilePackagesAsDirectories = false
        p.allowsOtherFileTypes = true
        if p.runModal() == .OK, let u = p.url { signFile = u }
    }

    /// password is the view's copy. It is not stored on the model, in preferences, or in the child environment.
    func unlockSigning(password: String) async {
        guard let cli = cli else { return }
        guard signSession?.role == "owner" else {
            error = "Only an owner session can unlock the lifetime cert."
            return
        }
        guard let token = cli.environment["ROTTENCORE_ACCESS_TOKEN"], !token.isEmpty else {
            error = "Sign in with a Red-XAI owner account first."
            return
        }
        busy = "Unlocking the lifetime certificate…"
        error = nil
        defer { busy = nil }
        let agent = signingAgent
        let binary = cli.binary
        let env = cli.environment
        do {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    do {
                        try agent.start(binary: binary, environment: env, token: token, password: password)
                        cont.resume()
                    } catch {
                        cont.resume(throwing: error)
                    }
                }
            }
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            return
        }
        for _ in 0..<40 {
            if let who = try? await cli.whoami(), who.agentRunning {
                signSession = who
                if signPlatform.isEmpty || !who.platforms.contains(signPlatform) {
                    signPlatform = who.platforms.first ?? ""
                }
                message = "Lifetime certificate unlocked for this login."
                return
            }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        error = "The signing agent did not unlock."
    }

    func performSign(withLauncher: Bool) async {
        guard let cli = cli, let file = signFile, let who = signSession else { return }
        let control = withLauncher
            ? SignGate.withLauncher(role: who.role, launcherInstalled: who.launcherInstalled, launcherRunning: who.launcherRunning, agentRunning: who.agentRunning)
            : SignGate.withoutLauncher(role: who.role, agentRunning: who.agentRunning)
        guard control == .enabled else { return }
        if let result = await work("Signing \(file.lastPathComponent)…", {
            try await cli.sign(file: file, platform: signPlatform, withLauncher: withLauncher, viaAgent: true)
        }) {
            message = "Signed \(result.appId) \(result.version)."
        }
    }

    func signOut() async {
        if let cli = cli {
            await signingAgent.stop(using: cli)
            cli.environment.removeValue(forKey: "ROTTENCORE_ACCESS_TOKEN")
        }
        signSession = nil
        signFile = nil
        signPlatform = ""
        message = "Signed out. The signing agent was stopped."
    }
}

struct ContentView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        NavigationView {
            List(SidebarItem.allCases, selection: $model.section) { s in
                NavigationLink(tag: s, selection: $model.section) { detail(s) } label: { Label(s.rawValue, systemImage: s.icon) }
            }
            .listStyle(.sidebar)
            .frame(minWidth: 180)
            detail(.install)
        }
        .overlay(alignment: .bottom) { StatusBar() }
    }

    @ViewBuilder func detail(_ s: SidebarItem) -> some View {
        switch s {
        case .install: InstallView()
        case .installed: InstalledView()
        case .updates: UpdatesView()
        case .store: StoreView()
        case .sign: SignView()
        case .settings: SettingsView()
        }
    }
}

struct StatusBar: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 4) {
            if let b = model.busy { HStack { ProgressView().controlSize(.small); Text(b) } }
            if let m = model.message { Text(m).foregroundColor(.green) }
            if let e = model.error { Text(e).foregroundColor(.red) }
        }
        .padding(8)
    }
}

struct Brand: View {
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "shippingbox.fill").font(.system(size: 30)).foregroundColor(.red)
            VStack(alignment: .leading) {
                Text("RottenCore Installer").font(.title2).bold()
                Text("One installer for every Red-XAI app").font(.callout).foregroundColor(.secondary)
            }
        }
    }
}

struct InstallView: View {
    @EnvironmentObject var model: AppModel
    @State private var dropping = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Brand()
                if let i = model.inspection { InspectionCard(i: i) } else { dropZone }
            }
            .padding(24)
        }
    }

    var dropZone: some View {
        VStack(spacing: 12) {
            Image(systemName: "square.and.arrow.down.on.square").font(.system(size: 40)).foregroundColor(.red)
            Text("Drop a .dmg, .pkg, .zip, .app or .rarxai here").font(.headline)
            Button("Choose a File…") { model.pickFile() }
        }
        .frame(maxWidth: .infinity, minHeight: 220)
        .background(RoundedRectangle(cornerRadius: 14).strokeBorder(dropping ? Color.red : Color.secondary.opacity(0.4), style: StrokeStyle(lineWidth: 2, dash: [8])))
        .onDrop(of: [UTType.fileURL], isTargeted: $dropping) { items in
            guard let p = items.first else { return false }
            _ = p.loadObject(ofClass: URL.self) { url, _ in
                if let u = url { Task { @MainActor in await model.inspect(u) } }
            }
            return true
        }
    }
}

struct InspectionCard: View {
    @EnvironmentObject var model: AppModel
    let i: Inspection

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("\(i.name) \(i.version)").font(.title3).bold()
                Spacer()
                TrustBadge(trusted: i.verdict.trusted, refused: i.verdict.refuse)
            }
            Grid2(rows: [
                ("App", i.appId.isEmpty ? "unknown" : i.appId),
                ("Kind", i.kind),
                ("Source", sourceText),
                ("Age rating", i.ageRating ?? "not given"),
                ("Checksum", i.verdict.checksum == "match" ? "verified" : i.verdict.checksum == "none" ? "none published" : "DOES NOT MATCH"),
                ("SHA-256", i.verdict.sha256.isEmpty ? "-" : i.verdict.sha256),
            ])
            ForEach(i.verdict.reasons, id: \.self) { Text("• " + $0).font(.callout).foregroundColor(.secondary) }
            ForEach(i.problems, id: \.self) { Text("! " + $0).font(.callout).foregroundColor(.orange) }
            gate
            HStack {
                Button("Cancel") { model.inspection = nil }
                Spacer()
                Button("Install") { Task { await model.installInspected() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(InstallGate.evaluate(i.verdict, accepted: model.accepted) != .ready || model.busy != nil)
            }
        }
        .padding(18)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color.primary.opacity(0.05)))
    }

    var sourceText: String {
        switch i.source {
        case "store": return "Rotten Apple store"
        case "github": return "GitHub release" + (i.github.map { " (\($0.owner)/\($0.repo) \($0.tag ?? ""))" } ?? "")
        default: return "unknown"
        }
    }

    @ViewBuilder var gate: some View {
        switch InstallGate.evaluate(i.verdict, accepted: true) {
        case .refused(let m):
            Label(m, systemImage: "xmark.octagon.fill").foregroundColor(.red).font(.headline)
        default:
            if !i.verdict.trusted {
                VStack(alignment: .leading, spacing: 8) {
                    Label(InstallGate.untrustedWarning, systemImage: "exclamationmark.triangle.fill").foregroundColor(.red).font(.headline)
                    Toggle("I understand the risk and want to install it anyway", isOn: $model.accepted)
                }
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.red.opacity(0.12)))
            }
        }
    }
}

struct TrustBadge: View {
    let trusted: Bool
    let refused: Bool
    var body: some View {
        let (t, c, s): (String, Color, String) = refused ? ("Refused", .red, "xmark.octagon.fill")
            : trusted ? ("Rotten Apple store", .green, "checkmark.seal.fill") : ("Not trusted", .orange, "exclamationmark.triangle.fill")
        return Label(t, systemImage: s).foregroundColor(c).padding(.horizontal, 10).padding(.vertical, 4)
            .background(Capsule().fill(c.opacity(0.15)))
    }
}

struct Grid2: View {
    let rows: [(String, String)]
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(0..<rows.count, id: \.self) { n in
                let r = rows[n]
                HStack(alignment: .top) {
                    Text(r.0).foregroundColor(.secondary).frame(width: 100, alignment: .leading)
                    Text(r.1).textSelection(.enabled).font(r.0 == "SHA-256" ? .system(.caption, design: .monospaced) : .body)
                }
            }
        }
    }
}

struct InstalledView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        List {
            if model.installed.isEmpty { Text("Nothing installed by RottenCore yet.").foregroundColor(.secondary) }
            ForEach(model.installed) { a in
                HStack {
                    VStack(alignment: .leading) {
                        Text("\(a.name) \(a.version)").bold()
                        Text("\(a.appId) · \(a.source) · \(a.kind)").font(.caption).foregroundColor(.secondary)
                    }
                    Spacer()
                    TrustBadge(trusted: a.trusted, refused: false)
                    if let p = a.paths.first {
                        Button("Show") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: p)]) }
                    }
                    Button("Uninstall") { Task { await model.uninstall(a) } }
                }
            }
        }
        .task { await model.refresh() }
    }
}

struct UpdatesView: View {
    @EnvironmentObject var model: AppModel
    @State private var accept = false
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Button("Check for Updates") { Task { await model.checkUpdates() } }
                Toggle("Accept the untrusted-source warning for GitHub updates", isOn: $accept)
            }
            .padding()
            List(model.updates) { u in
                HStack {
                    Text(u.name).bold()
                    Text(u.newer ? "\(u.installed) → \(u.available ?? "")" : "\(u.installed) (up to date)").foregroundColor(.secondary)
                    if let e = u.error { Text(e).foregroundColor(.orange).font(.caption) }
                    Spacer()
                    if u.newer { Button("Update") { Task { await model.update(u, acceptUntrusted: accept) } } }
                }
            }
        }
    }
}

struct StoreView: View {
    @EnvironmentObject var model: AppModel
    @State private var q = ""
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField("Search the Rotten Apple store", text: $q).onSubmit { Task { await model.search(q) } }
                Button("Search") { Task { await model.search(q) } }
            }
            .padding()
            List(model.results) { l in
                HStack {
                    VStack(alignment: .leading) {
                        Text(l.name).bold()
                        Text(l.tagline).font(.caption).foregroundColor(.secondary)
                    }
                    Spacer()
                    Text(l.ageRating).padding(.horizontal, 6).background(Capsule().fill(Color.secondary.opacity(0.2)))
                    Text(l.version).foregroundColor(.secondary)
                    Button("Get") {
                        let store = UserDefaults.standard.string(forKey: "storeURL") ?? "https://api.rottenapplestore.org"
                        var c = URLComponents(); c.scheme = "rottenapple"; c.host = "install"
                        c.queryItems = [URLQueryItem(name: "app", value: l.appId), URLQueryItem(name: "store", value: store)]
                        if let u = c.url { NSWorkspace.shared.open(u) } // the Rotten Apple launcher installs store apps
                    }
                }
            }
            Text("Store apps install through the Rotten Apple launcher, which checks the store's signatures, age rating and purchase.")
                .font(.caption).foregroundColor(.secondary).padding()
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage("theme") private var theme: String = Theme.dark.rawValue
    var body: some View {
        Form {
            Picker("Appearance", selection: $theme) {
                ForEach(Theme.allCases) { Text($0.label).tag($0.rawValue) }
            }
            .pickerStyle(.segmented)
            if let who = model.signSession {
                HStack {
                    Text("Red-XAI Account")
                    Spacer()
                    Text("\(who.email) · \(who.role)").foregroundColor(.secondary)
                    Button("Sign Out") { Task { await model.signOut() } }
                }
            } else {
                HStack {
                    Text("Red-XAI Account")
                    Spacer()
                    Button("Sign In") { Task { _ = await model.work("Signing in…") { try await model.accounts.signIn() } } }
                        .disabled(!model.accounts.isAvailable)
                    Text("Coming soon").foregroundColor(.secondary)
                }
            }
            Text("RottenCore sends no telemetry. The store address and account settings live in ~/Library/Application Support/RottenCore/config.json.")
                .font(.caption).foregroundColor(.secondary)
            Text("RottenCore is developed and maintained by Red-XAI LLC. Red-XAI LLC is wholly owned by GRIM-VIRUS, an independent recording artist who leads development under the alias MainDirectory. © Red-XAI LLC. All rights reserved.")
                .font(.caption).foregroundColor(.secondary)
        }
        .padding(24)
    }
}
