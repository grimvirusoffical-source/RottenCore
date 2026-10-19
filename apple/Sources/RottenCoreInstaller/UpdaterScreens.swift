import SwiftUI
import RottenCoreKit

/// A result card for an install/update/upload/rollout step. The "awaiting health data" state is its own
/// kind so a hosted rollout that has not reported rates reads clearly instead of looking like a failure.
struct OutcomeCard: View {
    let outcome: Outcome

    private var icon: String {
        switch outcome.kind {
        case .success: return "checkmark.circle.fill"
        case .failure: return "xmark.octagon.fill"
        case .info: return "info.circle.fill"
        case .awaiting: return "hourglass"
        }
    }
    private var tint: Color {
        switch outcome.kind {
        case .success: return .green
        case .failure: return .red
        case .info: return .blue
        case .awaiting: return .orange
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundColor(tint).font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(outcome.title).bold()
                Text(outcome.detail).font(.callout).foregroundColor(.secondary)
            }
            Spacer()
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(tint.opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(tint.opacity(0.35), lineWidth: 1))
    }
}

/// Picks where an update is pulled from. GitHub carries the untrusted-source warning.
struct SourcePicker: View {
    @Binding var source: UpdateSource
    @Binding var acceptUntrusted: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("Update source", selection: $source) {
                ForEach(UpdateSource.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            if source != .host {
                Toggle("Accept the untrusted-source warning for GitHub releases", isOn: $acceptUntrusted)
                    .font(.callout)
            }
        }
    }
}

/// One hosted rollout: phase, health summary, and the "awaiting health data" banner when nothing can
/// auto-promote yet. Rollback is always available; it restores only this app's own state.
struct RolloutCard: View {
    let rollout: HostRollout
    var onRollback: () -> Void = {}

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(rollout.appId).bold()
                Text(rollout.version).foregroundColor(.secondary)
                if let f = rollout.fromVersion { Text("(from \(f))").font(.caption).foregroundColor(.secondary) }
                Spacer()
                Text(rollout.phase.capitalized)
                    .font(.caption).padding(.horizontal, 8).padding(.vertical, 2)
                    .background(Capsule().fill(Color.secondary.opacity(0.2)))
            }
            if rollout.awaitingHealthData {
                OutcomeCard(outcome: Outcome(kind: .awaiting,
                                             title: "Awaiting health data",
                                             detail: "The host has not reported success, error and crash rates yet, so nothing is auto-promoted."))
            } else {
                Text(rollout.healthSummary).font(.callout).foregroundColor(.secondary)
            }
            HStack {
                Spacer()
                Button(role: .destructive) { onRollback() } label: { Label("Roll back", systemImage: "arrow.uturn.backward") }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.secondary.opacity(0.06)))
    }
}
