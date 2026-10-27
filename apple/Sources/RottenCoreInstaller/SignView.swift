import SwiftUI
import RottenCoreKit

/// The Sign panel colors, taken from SignPalette so the view cannot drift from the tested hex.
enum SignColors {
    static var charcoal: Color { color(SignPalette.charcoal) }
    static var crimson: Color { color(SignPalette.crimson) }
    static var bone: Color { color(SignPalette.bone) }

    private static func color(_ rgb: SignPalette.RGB) -> Color {
        Color(red: Double(rgb.r) / 255, green: Double(rgb.g) / 255, blue: Double(rgb.b) / 255)
    }
}

struct SignView: View {
    @EnvironmentObject var model: AppModel
    @State private var password = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Lifetime certificate").font(.title2).bold()
                Text(SignGate.officialNote).font(.callout)
                if let who = model.signSession {
                    session(who)
                } else {
                    Text("Sign in with a Red-XAI account. RottenCore reads ROTTENCORE_ACCESS_TOKEN for this login and does not save it.")
                        .font(.callout)
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(SignColors.charcoal)
        .foregroundColor(SignColors.bone)
        .task {
            while !Task.isCancelled {
                await model.refreshSignSession(quiet: true)
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    @ViewBuilder private func session(_ who: SignIdentity) -> some View {
        Text(who.email).font(.headline)
        Text(who.role == "owner" ? "Owner" : "Developer").font(.callout)
        if who.role == "owner" && !who.agentRunning {
            SecureField("Red-SecretsXAI password", text: $password)
                .textFieldStyle(.roundedBorder)
            Button("Unlock") { unlock() }
                .buttonStyle(.borderedProminent)
                .tint(SignColors.crimson)
                .disabled(password.isEmpty || model.busy != nil)
            Text("The password decrypts the lifetime cert in memory for this login. It is not saved.")
                .font(.caption)
        } else if who.agentRunning {
            Text("The lifetime cert is unlocked for this login.").font(.callout)
        } else {
            Text("An owner has to unlock signing on this Mac.").font(.callout)
        }

        Picker("Platform", selection: $model.signPlatform) {
            ForEach(who.platforms, id: \.self) { Text($0).tag($0) }
        }
        .pickerStyle(.segmented)

        HStack {
            if let file = model.signFile {
                Text(file.lastPathComponent).font(.callout)
            } else {
                Text("No file chosen").font(.callout)
            }
            Spacer()
            Button("Choose a File…") { model.pickSignFile() }
        }

        HStack(spacing: 12) {
            signButton("Sign with launcher", withLauncher: true, who: who)
            signButton("Sign without launcher", withLauncher: false, who: who)
        }
        reason(SignGate.withLauncher(role: who.role, launcherInstalled: who.launcherInstalled, launcherRunning: who.launcherRunning, agentRunning: who.agentRunning))
        reason(SignGate.withoutLauncher(role: who.role, agentRunning: who.agentRunning))
    }

    @ViewBuilder private func reason(_ control: SignControl) -> some View {
        if case .disabled(let message) = control {
            Text(message).font(.caption)
        }
    }

    private func signButton(_ title: String, withLauncher: Bool, who: SignIdentity) -> some View {
        let control = withLauncher
            ? SignGate.withLauncher(role: who.role, launcherInstalled: who.launcherInstalled, launcherRunning: who.launcherRunning, agentRunning: who.agentRunning)
            : SignGate.withoutLauncher(role: who.role, agentRunning: who.agentRunning)
        return Button(title) {
            Task { await model.performSign(withLauncher: withLauncher) }
        }
        .buttonStyle(.borderedProminent)
        .tint(SignColors.crimson)
        .disabled(control != .enabled || model.signFile == nil || model.signPlatform.isEmpty || model.busy != nil)
    }

    /// The password lives only in this view. It is cleared before the unlock task starts.
    private func unlock() {
        let pw = password
        password = ""
        Task { await model.unlockSigning(password: pw) }
    }
}
