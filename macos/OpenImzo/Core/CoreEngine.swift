import Foundation
import Observation

/// Owns the single `Engine` for the app's whole lifetime, and is the only place any call into
/// the Rust core is made — every view and every later task goes through this type, never
/// `Engine` directly. Every core call is `async`; this type itself is pinned to the main actor
/// so nothing can touch the core off it.
///
/// `Engine`'s constructor needs both a `Platform` and a `UiDelegate`: Task 3's `MacPlatform` and
/// Task 4's `MacUiDelegate`, both used here now. Task 5 adds `EventPump`, which keeps everything
/// below current without anyone needing the menu or window open (`startEventPumpIfNeeded`).
@MainActor
@Observable
final class CoreEngine {
    /// A human-readable, secret-free description of why the engine failed to construct, or
    /// `nil` if it constructed fine. Covers both this app's own directory setup and a failure
    /// from `Engine.init` itself. Shown on the Settings screen with a retry
    /// (`retryConstruction()`) per the controller addendum: a construction failure has to say
    /// what went wrong, not just show the same problem triangle every time.
    private(set) var constructionError: String?

    /// The last status read from the core. `nil` before the first `refreshStatus()` call
    /// completes (including the one this type fires off at construction), which the menu bar
    /// icon correctly reads as "not known to be up" — i.e. a problem, same as a listener that
    /// is explicitly down.
    private(set) var status: EngineStatus?

    private(set) var keys: [KeyEntry] = []
    private(set) var sites: [Site] = []

    /// Certificate summaries for password-protected PFX rows the person has explicitly unlocked
    /// this session, keyed by `unlockKey(path:alias:)`. Never persisted — there is nothing to
    /// clear on quit, since this dictionary simply stops existing with the process — and never
    /// populated except by `unlockKey(_:password:)` below, which only ever runs when a person
    /// submits `KeysView`'s own unlock sheet for that one row. Left alone by `retryConstruction()`
    /// for the same reason `activity`/`logLines` are: it belongs to the person's session, not to
    /// any one engine instance, and the certificate a file holds does not change underneath it.
    private(set) var unlockedSummaries: [String: CertificateSummary] = [:]

    /// The settings read at construction, or the last ones `updateSettings` wrote. `nil` until
    /// the first read completes, same reasoning as `status`.
    private(set) var settings: Settings?

    /// The app's own chrome language — see `AppLanguage`'s own doc comment for why this is a
    /// separate concept from `Settings.lang`. Loaded from `UserSettings` at construction, same
    /// as `extraKeyFolders`, and left alone by `retryConstruction()`: it belongs to the person's
    /// session, not to any one engine instance, same reasoning as `activity`/`logLines`.
    private(set) var appLanguage: AppLanguage = UserSettings.appLanguage

    /// Every `ActivityEntry` this session has seen, oldest first, capped so a long-running menu
    /// bar app doesn't grow this without bound. Populated from `activity.jsonl` at construction
    /// when `Settings.keepActivityLog` is on (there is no "fetch the last N" call on the core —
    /// this is the shell's own history), then appended to live by `EventPump`.
    private(set) var activity: [ActivityEntry] = []

    /// Formatted `Event.log` lines, shown in the Activity view only when `Settings
    /// .keepActivityLog` is on — every line is always written to the log file under
    /// `AppDirectories.logsDirectory()` regardless (see `EventPump`'s doc comment for why that
    /// split is deliberate), but this in-memory copy, which the UI actually reads, only grows
    /// while persistence is switched on.
    private(set) var logLines: [String] = []

    /// Set for as long as a request panel is open, via `MacUiDelegate.onActivityChange`.
    private(set) var isRequestInFlight = false

    /// Set by the menu bar's Keys submenu just before it opens the main window, so `KeysView`
    /// can select the row the person actually clicked instead of just landing on the list.
    /// Read-and-cleared by `KeysView.onAppear`.
    var pendingKeySelection: String?

    private var engine: Engine?
    private var eventPump: EventPump?
    private var activityStore: ActivityStore?
    private var logFile: LogFileWriter?

    /// Held only so `prepareForQuit()` can take down an open panel directly, without waiting on
    /// the core to call `cancel` first — see that method's doc comment.
    private var uiDelegate: MacUiDelegate?

    private static let activityCap = 1000
    private static let logLineCap = 500

    init() {
        retryConstruction()
    }

    /// (Re)builds the engine from scratch: the directory checks, then `Engine.init`, then the
    /// event pump. Safe to call more than once — the Settings screen's "Retry" button after a
    /// construction failure is exactly that (controller addendum #2). Keys, sites and status are
    /// reset to "not yet known" since they came from whatever engine just went away; activity and
    /// log history are left alone, since those belong to the person's session, not to any one
    /// engine instance.
    func retryConstruction() {
        eventPump?.stop()
        eventPump = nil
        engine = nil
        status = nil
        keys = []
        sites = []
        settings = nil
        constructionError = nil

        let appSupportURL = AppDirectories.appSupportDirectory()
        let logsURL = AppDirectories.logsDirectory()
        guard AppDirectories.exists(appSupportURL), AppDirectories.exists(logsURL) else {
            constructionError = appLanguage.locale.localizedAppString(
                "Could not create the app's data folders. Check that %@ and %@ can be created, then retry.",
                appSupportURL.path,
                logsURL.path
            )
            return
        }

        logFile = LogFileWriter(directory: logsURL)
        activityStore = ActivityStore(directory: appSupportURL)

        let config = EngineConfig(
            devMode: false,
            appSupportDir: appSupportURL.path,
            logsDir: logsURL.path,
            extraFolders: []
        )

        let uiDelegate = MacUiDelegate()
        let builtEngine: Engine
        do {
            builtEngine = try Engine(config: config, platform: MacPlatform(), ui: uiDelegate)
        } catch let error as EngineError {
            constructionError = error.userMessage(locale: appLanguage.locale)
            return
        } catch {
            constructionError = error.localizedDescription
            return
        }

        // Wired after every stored property has a value: the closure below captures `self`,
        // which isn't valid to reference any earlier in this method's caller (`init`).
        uiDelegate.onActivityChange = { [weak self] isInFlight in self?.isRequestInFlight = isInFlight }
        self.uiDelegate = uiDelegate
        engine = builtEngine
        let pump = EventPump(engine: builtEngine, coreEngine: self)
        eventPump = pump

        Task {
            await start()
            await refreshKeys()
            await refreshSites()
            await refreshSettings()
            if settings?.keepActivityLog == true, let activityStore {
                activity = Array(activityStore.loadAll().suffix(Self.activityCap))
            }
            pump.start()
        }
    }

    /// Binds both listeners. A no-op if the engine failed to construct, matching `Engine`'s own
    /// no-op-if-already-running behaviour: either way, calling this when there is nothing
    /// useful to do is safe.
    func start() async {
        guard let engine else { return }
        await engine.start()
        await refreshStatus()
    }

    func stop() async {
        guard let engine else { return }
        await engine.stop()
        await refreshStatus()
    }

    func refreshStatus() async {
        guard let engine else { return }
        status = await engine.status()
    }

    func refreshKeys() async {
        guard let engine else { return }
        keys = await engine.listKeys()
    }

    func rescanKeys() async {
        guard let engine else { return }
        await engine.rescanKeys()
        // `rescanKeys` itself sends `Event.keysChanged`, which `EventPump` turns back into a
        // `refreshKeys()` call — but that is a genuinely separate round trip through the event
        // stream, and a person who just pressed "Rescan" should see the list update as part of
        // that same action, not a moment later.
        await refreshKeys()
    }

    func refreshSites() async {
        guard let engine else { return }
        sites = await engine.sites()
    }

    func forgetSite(_ domain: String) async {
        guard let engine else { return }
        await engine.forgetSite(domain: domain)
        await refreshSites()
    }

    /// Reads `Settings` from the core, then reconciles both of its language fields against the
    /// chrome language already chosen (`appLanguage`) if they disagree. That disagreement is
    /// possible exactly once: `setAppLanguage(_:)` itself skips telling the core when `settings`
    /// is still `nil` (nothing to update yet), which happens if the person changes the chrome
    /// language in the brief window between construction and this method's first call completing.
    /// Without this, that one race would leave the core silently stuck on the old language until
    /// the person changed it again — exactly the disagreement task 6's controller addendum says
    /// must never happen. It also carries an existing `settings.json` forward: one written before
    /// `uiLang` existed arrives with it defaulted from `lang`, and this is what corrects it from
    /// `UserDefaults`, which is where the chrome language has always actually lived.
    func refreshSettings() async {
        guard let engine else { return }
        settings = await engine.settings()
        if var current = settings,
           current.lang != appLanguage.coreLangCode || current.uiLang != appLanguage.rawValue {
            current.lang = appLanguage.coreLangCode
            current.uiLang = appLanguage.rawValue
            await updateSettings(current)
        }
    }

    /// Persists `newSettings` and applies the parts the core reads immediately. If activity
    /// persistence was just switched on, seeds the file with whatever this session has
    /// accumulated in memory so far, rather than starting the file mid-history.
    func updateSettings(_ newSettings: Settings) async {
        guard let engine else { return }
        let wasLogging = settings?.keepActivityLog ?? false
        await engine.updateSettings(settings: newSettings)
        settings = newSettings
        if newSettings.keepActivityLog, !wasLogging {
            activityStore?.replaceAll(activity)
        }
    }

    /// Changes the app's own chrome language and tells the core both of the things it now wants
    /// to know about it, which are two different questions:
    ///
    /// - `lang` is what a **website** is answered in. Uzbek maps to the core's own `uz`, and both
    ///   Russian and English map to `ru`, since the wire contract has no English and Russian is
    ///   its (and the original's) own default — see `AppLanguage.coreLangCode`. Per task 6's
    ///   controller addendum, the two halves must never disagree about what "Uzbek" or "Russian"
    ///   means.
    /// - `uiLang` is what the **person** reads, and it does have English. The core uses it for
    ///   the two pages it serves on `127.0.0.1`, so opening them lands in the language the menu
    ///   bar is already speaking rather than in Russian regardless.
    ///
    /// The chrome switches immediately regardless of the core, since it doesn't depend on the
    /// engine at all; telling the core is skipped, not dropped, if `settings` hasn't loaded yet
    /// — `refreshSettings()`'s own doc comment covers the catch-up.
    func setAppLanguage(_ language: AppLanguage) async {
        appLanguage = language
        UserSettings.appLanguage = language
        guard var updated = settings else { return }
        updated.lang = language.coreLangCode
        updated.uiLang = language.rawValue
        await updateSettings(updated)
    }

    /// Always installs into the login keychain — `systemWide` is never `true` here, by design:
    /// the System keychain needs an administrator prompt this app does not offer yet (a later
    /// phase), and this project treats that as a security boundary, not a default to relax.
    @discardableResult
    func installTlsTrust() async -> Bool {
        guard let engine else { return false }
        return await engine.installTlsTrust(systemWide: false)
    }

    func clearPasswordCache() async {
        guard let engine else { return }
        await engine.clearPasswordCache()
    }

    func changePassword(path: String, old: String, new: String) async throws {
        guard let engine else { throw EngineError.NotRunning }
        try await engine.changePassword(path: path, old: old, new: new)
    }

    func convertPfxToYks(path: String, password: String) async throws {
        guard let engine else { throw EngineError.NotRunning }
        try await engine.convertPfxToYks(path: path, password: password)
    }

    func convertYksToPfx(path: String, password: String) async throws {
        guard let engine else { throw EngineError.NotRunning }
        try await engine.convertYksToPfx(path: path, password: password)
    }

    func exportQrKey(path: String, password: String) async throws -> Data {
        guard let engine else { throw EngineError.NotRunning }
        return try await engine.exportQrKey(path: path, password: password)
    }

    /// Reads `key`'s own certificate from its password-protected PFX and remembers it under
    /// `unlockKey(path:alias:)`, so `KeysView` shows exactly what the YKS row already shows
    /// without asking again for the rest of this session. `password` reaches the core as a plain
    /// `String` argument and is never stored by this type — `Engine.unlockKey`'s own doc comment
    /// covers where it lives, and for how long, on the Rust side.
    @discardableResult
    func unlockKey(_ key: KeyEntry, password: String) async throws -> CertificateSummary {
        guard let engine else { throw EngineError.NotRunning }
        let summary = try await engine.unlockKey(path: key.fullPath, alias: key.alias, password: password)
        unlockedSummaries[Self.unlockKey(path: key.fullPath, alias: key.alias)] = summary
        return summary
    }

    /// The certificate summary `unlockKey(_:password:)` already fetched for `key` this session,
    /// if any — `nil` means the row is still locked, not that unlocking failed.
    func unlockedSummary(for key: KeyEntry) -> CertificateSummary? {
        unlockedSummaries[Self.unlockKey(path: key.fullPath, alias: key.alias)]
    }

    /// A PFX can hold more than one alias (`Discovery::scan`'s own per-alias rows), so the cache
    /// key is the pair, not the path alone.
    private static func unlockKey(path: String, alias: String) -> String {
        "\(path)#\(alias)"
    }

    /// Empties the in-memory activity and log history and whatever `activity.jsonl` the shell
    /// itself wrote. There is no `clearActivity` on the core — nothing there is being asked to
    /// forget anything, only what this app is holding and the file this app wrote.
    func clearActivity() {
        activity = []
        logLines = []
        activityStore?.clear()
    }

    /// Called once, by `EventPump`, for every `Event.activity`.
    func appendActivity(_ entry: ActivityEntry) {
        activity.append(entry)
        if activity.count > Self.activityCap {
            activity.removeFirst(activity.count - Self.activityCap)
        }
        if settings?.keepActivityLog == true {
            activityStore?.append(entry)
        }
    }

    /// Called once, by `EventPump`, for every `Event.log`. Always written to the on-disk log
    /// file; only kept in memory (and so only shown in the Activity view) while activity
    /// persistence is on — see `logLines`'s doc comment.
    func appendLogLine(_ line: String) {
        logFile?.append(line)
        guard settings?.keepActivityLog == true else { return }
        logLines.append(line)
        if logLines.count > Self.logLineCap {
            logLines.removeFirst(logLines.count - Self.logLineCap)
        }
    }

    /// Quit must not kill the process out from under an open panel (controller addendum #3):
    /// this takes down whatever panel is open — as if the person had cancelled it — and then
    /// stops the engine, bounded to `timeout` so a stop that hangs cannot make Quit hang.
    /// `AppDelegate.applicationShouldTerminate` awaits this before actually terminating.
    func prepareForQuit(timeout: Duration = .seconds(3)) async {
        uiDelegate?.forceCloseActivePanel()
        guard let engine else { return }
        await Self.race(timeout: timeout) { await engine.stop() }
    }

    /// Runs `operation` and returns once it finishes or `timeout` elapses, whichever comes
    /// first. If `operation` is still running when the timeout wins, it keeps running
    /// unstructured in the background rather than being force-cancelled — `Engine.stop` isn't
    /// written to observe cancellation, so cancelling it would not actually make it stop any
    /// sooner, and simply not waiting on it any longer is what actually bounds Quit's delay.
    private static func race(timeout: Duration, operation: @escaping () async -> Void) async {
        final class OnceFlag {
            private var fired = false
            func fireOnce() -> Bool {
                guard !fired else { return false }
                fired = true
                return true
            }
        }
        let flag = OnceFlag()
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            Task { @MainActor in
                await operation()
                if flag.fireOnce() { continuation.resume() }
            }
            Task { @MainActor in
                try? await Task.sleep(for: timeout)
                if flag.fireOnce() { continuation.resume() }
            }
        }
    }
}

extension EngineError {
    /// A person-facing description, in the app's own chrome language. Uniffi's own
    /// `LocalizedError.errorDescription` for this type just reflects the Swift case name
    /// (`OpenImzo.EngineError.KeyFile`) — the message each case is documented with in
    /// `crates/openimzo-ffi/src/types.rs` never crosses the FFI boundary, so it is restated here to
    /// match it, word for word, then localized.
    ///
    /// Takes `locale` explicitly rather than reading it from `@Environment` because this is a
    /// plain `Swift.Error` extension, not a `View` — every call site is a view that already has
    /// one to hand, from `@Environment(\.locale)`, or `CoreEngine`'s own `appLanguage.locale`.
    func userMessage(locale: Locale) -> String {
        switch self {
        case .NotRunning: locale.localizedAppString("The engine is not running.")
        case .KeyFile: locale.localizedAppString("That key file could not be opened.")
        case .Password: locale.localizedAppString("The password was not accepted.")
        case .Failed: locale.localizedAppString("The operation failed.")
        }
    }
}
