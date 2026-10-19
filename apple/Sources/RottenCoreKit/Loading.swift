import Foundation

/// One line of `rottencore ... --progress json` (core/progress.go ProgressEvent).
public struct ProgressEvent: Codable, Equatable {
    public var op: String
    public var step: Int
    public var steps: Int
    public var action: String
    public var item: String
    public var line: String
    public var done: Int64
    public var total: Int64
    public var percent: Int
    public var state: String // running | done | failed
    public var error: String?
    public var atMs: Int64
}

/// What the loading screen shows. It only changes when the engine reports real work: the counter is the
/// engine's integer percent, clamped to 0...100 and never allowed to go backwards. There is no timer.
public struct LoadingState: Equatable {
    public private(set) var percent: Int = 0
    public private(set) var line: String = ""
    public private(set) var state: String = "running"
    public private(set) var error: String?

    public init() {}

    public mutating func apply(_ e: ProgressEvent) {
        percent = max(percent, min(100, max(0, e.percent)))
        line = e.line
        state = e.state
        error = e.error
    }

    /// The bar's text, e.g. "37/100".
    public var counter: String { "\(percent)/100" }
    public var fraction: Double { Double(percent) / 100 }
}

/// Reads NDJSON progress lines as they arrive (partial chunks are buffered until a newline).
public struct ProgressLineDecoder {
    private var buffer = Data()
    public init() {}
    public mutating func feed(_ chunk: Data) -> [ProgressEvent] {
        buffer.append(chunk)
        var out: [ProgressEvent] = []
        while let nl = buffer.firstIndex(of: 0x0A) {
            let line = buffer[buffer.startIndex..<nl]
            buffer.removeSubrange(buffer.startIndex...nl)
            if let e = try? JSONDecoder().decode(ProgressEvent.self, from: Data(line)) { out.append(e) }
        }
        return out
    }
}

/// The rolling black apple. Pure geometry so it can be tested: the apple rolls left to right at a constant
/// speed in real time (wall clock, not progress), turns as a wheel of its own radius would, and when it
/// has fully left the right edge it re-enters from the left edge.
public struct RollingApple {
    public var width: Double      // screen (or view) width in points
    public var size: Double       // apple diameter in points
    public var speed: Double      // points per second

    public init(width: Double, size: Double = 64, speed: Double = 140) {
        self.width = width; self.size = size; self.speed = speed
    }

    /// The track is the screen plus one apple on each side, so the apple is fully off-screen before it wraps.
    public var track: Double { width + size }

    /// x of the apple's left edge at time t (seconds): from -size (just off the left) to width (just off the right).
    public func x(at t: Double) -> Double {
        guard track > 0 else { return 0 }
        let d = (t * speed).truncatingRemainder(dividingBy: track)
        return (d < 0 ? d + track : d) - size
    }

    /// Rotation in radians: distance rolled / radius (rolling without slipping).
    public func angle(at t: Double) -> Double {
        let r = size / 2
        return r > 0 ? (t * speed) / r : 0
    }
}
