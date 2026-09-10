import Foundation

/// Subscribes to the core's one event stream for the app's whole life and keeps `CoreEngine`
/// current without anyone needing the menu or the main window open.
///
/// This is the fix for what Task 2's review found: the menu bar icon used to refresh only when
/// the dropdown opened, plus once at construction, so a listener that died while the menu was
/// closed left the icon claiming everything was fine. `Engine.events()` mints a fresh
/// subscription over a broadcast channel the core keeps for the engine's whole life — this pump
/// holds the one subscription `CoreEngine` needs and turns every event into the matching
/// re-query, on the main actor, the moment it happens.
///
/// `EventStream.next()` returning `nil` is the stream ending because the engine was torn down
/// (`CoreEngine.retryConstruction()`, or app teardown) — a normal ending, not an error, so the
/// pump task just returns rather than looping or treating it as a failure to report.
@MainActor
final class EventPump {
    private let engine: Engine
    private unowned let coreEngine: CoreEngine
    private var task: Task<Void, Never>?

    init(engine: Engine, coreEngine: CoreEngine) {
        self.engine = engine
        self.coreEngine = coreEngine
    }

    /// Starts the pump task. Safe to call more than once — a second call while one is already
    /// running is a no-op, matching `Engine.start`'s own already-running behaviour.
    func start() {
        guard task == nil else { return }
        let stream = engine.events()
        task = Task { [weak self] in
            while let event = await stream.next() {
                guard let self else { return }
                await self.handle(event)
            }
        }
    }

    /// Ends the subscription from this side, e.g. when `CoreEngine` is about to build a fresh
    /// `Engine` and this pump's own `engine` reference is going away. Cancelling the task alone
    /// is enough: `EventStream.next()`'s `await` is what actually gets interrupted.
    func stop() {
        task?.cancel()
        task = nil
    }

    private func handle(_ event: Event) async {
        switch event {
        case .serverStateChanged, .tlsTrustChanged:
            // Both events carry no detail by design (`crates/openimzo-ffi/src/events.rs`) — each is
            // a nudge to re-query `status()` for the fresh value.
            await coreEngine.refreshStatus()
        case .keysChanged:
            await coreEngine.refreshKeys()
        case let .activity(entry):
            coreEngine.appendActivity(entry)
        case let .log(line):
            coreEngine.appendLogLine(line)
        }
    }
}

/// The shell's own record of `Event.activity` entries: `activity.jsonl` under
/// `~/Library/Application Support/OpenImzo/`, one JSON object per line, per the design
/// spec's storage layout (§4.2). The core has no "fetch the last N" call — this is the only
/// history there is, and only while `Settings.keepActivityLog` is on; `CoreEngine` is the one
/// that decides whether to read or write through this at all.
final class ActivityStore {
    private let fileURL: URL

    init(directory: URL) {
        fileURL = directory.appendingPathComponent("activity.jsonl")
    }

    /// Every entry currently on disk, in file order (oldest first), skipping any line that
    /// fails to parse — a partially written last line from a previous crash, say — rather than
    /// failing the whole read over one bad line.
    func loadAll() -> [ActivityEntry] {
        guard let data = FileManager.default.contents(atPath: fileURL.path),
              let text = String(data: data, encoding: .utf8)
        else { return [] }
        let decoder = JSONDecoder()
        var entries: [ActivityEntry] = []
        for line in text.split(separator: "\n") {
            guard let lineData = line.data(using: .utf8),
                  let entry = try? decoder.decode(ActivityEntry.self, from: lineData)
            else { continue }
            entries.append(entry)
        }
        return entries
    }

    /// Appends one entry as its own line. Opens and closes the file every time rather than
    /// holding a handle open across `Settings.keepActivityLog` being switched off and back on —
    /// activity is at most one entry per website call, so this is not hot enough to matter.
    func append(_ entry: ActivityEntry) {
        guard let line = encodedLine(entry) else { return }
        ensureFileExists()
        guard let handle = FileHandle(forWritingAtPath: fileURL.path) else { return }
        defer { handle.closeFile() }
        handle.seekToEndOfFile()
        if let lineData = line.data(using: .utf8) {
            handle.write(lineData)
        }
    }

    /// Overwrites the file with exactly `entries` — used once, when persistence is switched on
    /// mid-session, to seed the file with whatever this session already has in memory instead of
    /// starting the file mid-history.
    func replaceAll(_ entries: [ActivityEntry]) {
        let lines = entries.compactMap(encodedLine)
        let text = lines.joined()
        try? text.write(to: fileURL, atomically: true, encoding: .utf8)
    }

    /// Deletes the file. `CoreEngine.clearActivity()`'s counterpart to emptying the in-memory
    /// list — there is no `clearActivity` on the core, so this only ever touches what this app
    /// itself wrote.
    func clear() {
        try? FileManager.default.removeItem(at: fileURL)
    }

    private func encodedLine(_ entry: ActivityEntry) -> String? {
        guard let data = try? JSONEncoder().encode(entry),
              let json = String(data: data, encoding: .utf8)
        else { return nil }
        return json + "\n"
    }

    private func ensureFileExists() {
        guard !FileManager.default.fileExists(atPath: fileURL.path) else { return }
        FileManager.default.createFile(atPath: fileURL.path, contents: nil)
    }
}

/// Writes every `Event.log` line to a plain text file under
/// `~/Library/Logs/OpenImzo/`, always — independent of `Settings.keepActivityLog`, which
/// only governs whether these lines also show up in the Activity view (`CoreEngine
/// .appendLogLine`). `EngineConfig.logsDir` tells the core where this directory is, but nothing
/// in `crates/openimzo-ffi` actually writes a file there — `Event.log` is the only channel these
/// lines travel over, so if the shell doesn't write them down, "open the logs directory" (the
/// About screen's own action) would always open an empty folder. Lines are already formatted by
/// `tracing` with their own timestamp and level, so this only ever appends them verbatim plus a
/// trailing newline.
final class LogFileWriter {
    private let fileURL: URL

    init(directory: URL) {
        fileURL = directory.appendingPathComponent("openimzo.log")
    }

    func append(_ line: String) {
        guard let data = (line + "\n").data(using: .utf8) else { return }
        if !FileManager.default.fileExists(atPath: fileURL.path) {
            FileManager.default.createFile(atPath: fileURL.path, contents: nil)
        }
        guard let handle = FileHandle(forWritingAtPath: fileURL.path) else { return }
        defer { handle.closeFile() }
        handle.seekToEndOfFile()
        handle.write(data)
    }
}

/// `ActivityEntry`'s four fields are all `String`, so this is a plain, lossless mirror of what
/// `crates/openimzo-ffi/src/types.rs` sends across — needed only so `ActivityStore` can read and
/// write it as JSON; uniffi's own generated type has no reason to carry that conformance itself.
/// Written by hand rather than `: Codable {}`: automatic synthesis only applies within the file
/// that declares the type, and `ActivityEntry` is declared in the generated bindings, not here.
extension ActivityEntry: Codable {
    private enum CodingKeys: String, CodingKey {
        case at, origin, function, outcome
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            at: try container.decode(String.self, forKey: .at),
            origin: try container.decode(String.self, forKey: .origin),
            function: try container.decode(String.self, forKey: .function),
            outcome: try container.decode(String.self, forKey: .outcome)
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(at, forKey: .at)
        try container.encode(origin, forKey: .origin)
        try container.encode(function, forKey: .function)
        try container.encode(outcome, forKey: .outcome)
    }
}
