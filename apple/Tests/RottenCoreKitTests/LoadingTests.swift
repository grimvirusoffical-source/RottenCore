import XCTest
@testable import RottenCoreKit

final class LoadingTests: XCTestCase {
    func ev(_ p: Int, _ state: String = "running", line: String = "Downloading a.dmg") -> ProgressEvent {
        ProgressEvent(op: "install", step: 0, steps: 1, action: "downloading", item: "a.dmg", line: line, done: 0, total: -1, percent: p, state: state, error: nil, atMs: 0)
    }

    func testCounterIsMonotonicAndClamped() {
        var s = LoadingState()
        XCTAssertEqual(s.counter, "0/100")
        s.apply(ev(40)); XCTAssertEqual(s.counter, "40/100")
        s.apply(ev(10)); XCTAssertEqual(s.percent, 40)
        s.apply(ev(250, "done", line: "Done")); XCTAssertEqual(s.percent, 100); XCTAssertEqual(s.line, "Done")
    }

    func testDecoderHandlesPartialLines() {
        var d = ProgressLineDecoder()
        let l = #"{"op":"download","step":0,"steps":1,"action":"downloading","item":"x","line":"Downloading x — 1 KB","done":1024,"total":2048,"percent":50,"state":"running","atMs":1}"#
        XCTAssertTrue(d.feed(Data(l.prefix(20).utf8)).isEmpty)
        let evs = d.feed(Data((l.dropFirst(20) + "\n").utf8))
        XCTAssertEqual(evs.count, 1); XCTAssertEqual(evs[0].percent, 50)
    }

    func testAppleRollsAndWraps() {
        let a = RollingApple(width: 400, size: 64, speed: 100)
        XCTAssertEqual(a.x(at: 0), -64, accuracy: 1e-9)          // just off the left edge
        XCTAssertEqual(a.x(at: 1), 36, accuracy: 1e-9)
        XCTAssertEqual(a.x(at: 4.63), 399, accuracy: 1e-6)       // almost fully off the right edge
        XCTAssertEqual(a.x(at: 4.65), -63, accuracy: 1e-6)       // back in from the left
        XCTAssertEqual(a.angle(at: 1), 100.0 / 32.0, accuracy: 1e-9)
        for t in stride(from: 0.0, to: 30.0, by: 0.37) {
            XCTAssert(a.x(at: t) >= -64 && a.x(at: t) < 400)
        }
    }
}
