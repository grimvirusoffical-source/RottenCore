import SwiftUI
import RottenCoreKit

/// Uploader screen. Owners and admins see unlimited, free uploads; everyone sees that publishing stays
/// blocked until QA signs off (uploader/publish.go). The bytes stream through the Go uploader; this screen
/// collects the artifact and shows the outcome.
struct UploadView: View {
    @EnvironmentObject var model: AppModel
    @State private var appId = ""
    @State private var version = ""
    @State private var artifact = ""
    @State private var ownerOrAdmin = false
    @State private var qaSignedOff = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Upload a build").font(.title3).bold()

                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        LabeledRow("App ID") { TextField("com.example.app", text: $appId) }
                        LabeledRow("Version") { TextField("1.0.0", text: $version) }
                        LabeledRow("Artifact") {
                            HStack {
                                TextField("path to the signed artifact", text: $artifact)
                                Button("Choose…") { chooseArtifact() }
                            }
                        }
                    }
                    .padding(6)
                }

                if ownerOrAdmin {
                    OutcomeCard(outcome: Outcome(kind: .success, title: "Unlimited and free",
                                                detail: "Owners and admins upload any size at no charge."))
                } else {
                    OutcomeCard(outcome: Outcome(kind: .info, title: "Upload limits apply",
                                                detail: "Developer accounts upload within their plan's size and count limits."))
                }

                OutcomeCard(outcome: Outcome(kind: qaSignedOff ? .success : .awaiting,
                                            title: qaSignedOff ? "QA signed off" : "Publishing blocked until QA signs off",
                                            detail: qaSignedOff ? "This build may be published." : "The build uploads now; it can be published only after QA signs it off."))

                HStack {
                    Toggle("I'm an owner or admin", isOn: $ownerOrAdmin)
                    Spacer()
                    Button {
                        model.uploads.insert(Outcome(kind: .info, title: "Upload queued",
                                                     detail: "\(appId) \(version) — the Go uploader streams the artifact in resumable chunks."), at: 0)
                    } label: { Label("Upload", systemImage: "square.and.arrow.up") }
                    .disabled(appId.isEmpty || version.isEmpty || artifact.isEmpty)
                    Button {
                        model.uploads.insert(Outcome(kind: .failure, title: "Publish blocked",
                                                     detail: "QA has not signed off on \(appId) \(version)."), at: 0)
                    } label: { Label("Publish", systemImage: "paperplane") }
                    .disabled(!qaSignedOff)
                }

                if !model.uploads.isEmpty {
                    Text("Recent").font(.headline)
                    ForEach(model.uploads) { OutcomeCard(outcome: $0) }
                }
            }
            .padding()
        }
    }

    private func chooseArtifact() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { artifact = url.path }
    }
}

/// Builder screen. Rotten Core is the builder: it requires a build API key from the dev account, and on a
/// Mac it builds and signs only Mac and iOS; Windows and Android need a Windows device (builder/host.go).
struct BuildView: View {
    @EnvironmentObject var model: AppModel
    @State private var projectName = ""
    @State private var appId = ""
    @State private var version = ""
    @State private var hasBuildKey = false
    @State private var selected: Set<String> = ["macos-arm64", "ios"]

    private let hostTargets = ["macos-arm64", "macos-intel", "ios"]
    private let otherTargets = ["windows", "android"]
    private let neutralTargets = ["linux", "extensions"]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Build with Rotten Core").font(.title3).bold()

                if !hasBuildKey {
                    OutcomeCard(outcome: Outcome(kind: .failure, title: "No build API key",
                                                detail: "Create a build API key in your Rotten Apple dev account."))
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        LabeledRow("Project") { TextField("App name", text: $projectName) }
                        LabeledRow("App ID") { TextField("com.example.app", text: $appId) }
                        LabeledRow("Version") { TextField("1.0.0", text: $version) }
                    }
                    .padding(6)
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("Targets").font(.headline)
                    Text("On this Mac, Rotten Core builds and signs Mac and iOS. Android and Windows need a Windows device.")
                        .font(.caption).foregroundColor(.secondary)
                    targetGroup("Mac & iOS (this device)", hostTargets, enabled: true)
                    targetGroup("Windows & Android (needs a Windows device)", otherTargets, enabled: false)
                    targetGroup("Host-neutral", neutralTargets, enabled: true)
                }

                HStack {
                    Toggle("I have a build API key", isOn: $hasBuildKey)
                    Spacer()
                    Button {
                        model.builds.insert(Outcome(kind: .success, title: "Build started",
                                                    detail: "\(projectName) \(version) → \(selected.sorted().joined(separator: ", "))"), at: 0)
                    } label: { Label("Build", systemImage: "hammer") }
                    .disabled(!hasBuildKey || projectName.isEmpty || appId.isEmpty || version.isEmpty || selected.isEmpty)
                }

                if !model.builds.isEmpty {
                    Text("Recent").font(.headline)
                    ForEach(model.builds) { OutcomeCard(outcome: $0) }
                }
            }
            .padding()
        }
        .sheet(item: $model.pendingBuild) { preview in
            BuildConfirmSheet(preview: preview,
                              onConfirm: { Task { await model.confirmPendingBuild() } },
                              onCancel: { model.cancelPendingBuild() })
        }
    }

    @ViewBuilder func targetGroup(_ title: String, _ targets: [String], enabled: Bool) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.callout).foregroundColor(enabled ? .primary : .secondary)
            ForEach(targets, id: \.self) { t in
                Toggle(t, isOn: Binding(
                    get: { selected.contains(t) },
                    set: { on in if on { selected.insert(t) } else { selected.remove(t) } }
                ))
                .disabled(!enabled)
                .font(.callout)
            }
        }
    }
}


/// macOS 12-compatible stand-in for LabeledContent (which is 13+).
struct LabeledRow<Content: View>: View {
    let label: String
    @ViewBuilder let content: () -> Content
    init(_ label: String, @ViewBuilder content: @escaping () -> Content) {
        self.label = label; self.content = content
    }
    var body: some View {
        HStack {
            Text(label).frame(width: 90, alignment: .leading).foregroundColor(.secondary)
            content()
        }
    }
}


/// Confirmation sheet before a URL-handed build runs (QA v2 N3): app, targets, commands, project dir.
struct BuildConfirmSheet: View {
    let preview: BuildConfirmPreview
    var onConfirm: () -> Void
    var onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Confirm build").font(.title2).bold()
            Text("\(preview.app) \(preview.version)")
                .font(.headline)
            LabeledRow("App ID") { Text(preview.appId) }
            LabeledRow("Project dir") { Text(preview.dir).lineLimit(2) }
            if let channel = preview.channel, !channel.isEmpty {
                LabeledRow("Channel") { Text(channel) }
            }
            Text("Targets").font(.headline)
            ForEach(preview.targets, id: \.platform) { t in
                VStack(alignment: .leading, spacing: 2) {
                    Text(t.platform).font(.callout).bold()
                    if let cmd = t.command, !cmd.isEmpty {
                        let envPrefix = (t.env?.isEmpty == false) ? (t.env!.joined(separator: " ") + " ") : ""
                        Text(envPrefix + cmd.joined(separator: " ")).font(.caption).foregroundColor(.secondary)
                    } else if let pre = t.prebuilt {
                        Text("prebuilt: \(pre)").font(.caption).foregroundColor(.secondary)
                    }
                }
            }
            if let sdks = preview.sdks, !sdks.isEmpty {
                LabeledRow("SDKs") { Text(sdks.joined(separator: ", ")) }
            }
            Spacer(minLength: 8)
            HStack {
                Button("Cancel", role: .cancel, action: onCancel)
                Spacer()
                Button("Build", action: onConfirm).keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 420, minHeight: 320)
    }
}

