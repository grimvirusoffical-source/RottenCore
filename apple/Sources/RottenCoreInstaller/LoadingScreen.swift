import SwiftUI
import RottenCoreKit

/// RottenCore loading screen for installs, updates and uploads: a black apple rolling across the window in
/// real time (wrapping at the edges), a bar with the 0/100 counter inside driven only by real engine
/// progress, and a live line naming what is being changed, added or downloaded right now.
struct LoadingScreen: View {
    let state: LoadingState
    var appleSize: CGFloat = 64

    var body: some View {
        VStack(spacing: 18) {
            GeometryReader { geo in
                TimelineView(.animation) { tl in
                    let t = tl.date.timeIntervalSinceReferenceDate
                    let roll = RollingApple(width: Double(geo.size.width), size: Double(appleSize))
                    BlackApple()
                        .frame(width: appleSize, height: appleSize)
                        .rotationEffect(.radians(roll.angle(at: t)))
                        .offset(x: CGFloat(roll.x(at: t)), y: geo.size.height - appleSize)
                }
            }
            .frame(height: appleSize + 8)
            .clipped()
            .accessibilityHidden(true)

            ZStack {
                GeometryReader { g in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Color.white.opacity(0.12))
                        Capsule().fill(state.state == "failed" ? Color.red : Color.green)
                            .frame(width: g.size.width * CGFloat(state.fraction))
                    }
                }
                Text(state.counter)
                    .font(.system(.callout, design: .monospaced).weight(.semibold))
                    .foregroundColor(.white)
            }
            .frame(height: 24)
            .accessibilityElement()
            .accessibilityLabel("Progress")
            .accessibilityValue("\(state.percent) percent")

            Text(state.line.isEmpty ? " " : state.line)
                .font(.system(.footnote, design: .monospaced))
                .foregroundColor(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding(24)
        .background(Color.black.opacity(0.92))
    }
}

/// RottenCore's black apple (our own drawing, not Apple's logo).
struct BlackApple: View {
    var body: some View {
        ZStack {
            Circle().fill(Color.black).overlay(Circle().stroke(Color.white.opacity(0.35), lineWidth: 1.5))
            Ellipse().fill(Color(white: 0.22)).frame(width: 14, height: 7).offset(x: 8, y: -30).rotationEffect(.degrees(-25))
            Rectangle().fill(Color(white: 0.3)).frame(width: 3, height: 10).offset(y: -32)
            Circle().fill(Color.white.opacity(0.12)).frame(width: 12, height: 12).offset(x: -12, y: -10)
        }
    }
}
