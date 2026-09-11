import Foundation

/// The one setting this app keeps entirely to itself, outside the core's own `Settings` record.
///
/// `extraKeyFolders` backs `MacPlatform.volumesRoots()`: folders beyond `/Volumes` the person has
/// added for key discovery (managed from `KeysView`'s folder list). It stays in `UserDefaults`
/// rather than moving into `Engine.settings()`/`updateSettings()` because there is no matching
/// field there to move it to — `Settings` (`crates/openimzo-ffi/src/types.rs`) only carries `lang`,
/// `launchAtLogin`, `developerMode`, `rememberPasswords`, `askBeforeRandseed` and
/// `keepActivityLog`, none of which is this. The core never reads this array itself either: per
/// `build_discovery` (`crates/openimzo-ffi/src/engine.rs`), it calls `Platform.volumesRoots()` fresh
/// on every `listKeys`/`rescanKeys`, and `MacPlatform.volumesRoots()` reads straight from here —
/// so this is purely a macOS-shell, `Platform`-layer detail, exactly the kind of thing
/// `UserDefaults` is for, not a setting the core has any concept of. Defaults to empty, which
/// `volumesRoots()` turns into exactly `["/Volumes"]`.
///
/// `UserDefaults.standard` is keyed by bundle identifier, which the OpenImzo rename changed —
/// unlike `AppDirectories`' on-disk files, there is no directory to move here, so
/// `migrateLegacyDefaults()` below reads the previous bundle identifier's domain directly and
/// copies across what it finds, once.
enum UserSettings {
    private static let extraKeyFoldersKey = "extraKeyFolders"
    private static let appLanguageKey = "appLanguage"
    private static let hasCompletedFirstRunKey = "hasCompletedFirstRun"
    private static let automaticUpdateChecksKey = "automaticUpdateChecks"
    private static let lastUpdateCheckKey = "lastUpdateCheck"
    private static let skippedUpdateVersionKey = "skippedUpdateVersion"

    /// Whether names and identifiers are replaced with dots until revealed.
    ///
    /// `internal`, and the only preference here exposed as a key rather than a property: the two
    /// views that use it bind through `@AppStorage`, which is what makes a change in Settings
    /// redraw the Keys list immediately — a `static var` read would not, since nothing observes
    /// it. The name lives here anyway, with every other preference name, because a literal typed
    /// into two different views is how two spellings of one preference begin.
    static let maskSensitiveDataKey = "maskSensitiveData"

    /// The bundle identifier this app shipped under before the OpenImzo rename
    /// (`macos/project.yml`, before this task). Read only by `migrateLegacyDefaults()`.
    private static let legacyBundleIdentifier = "uz.eimzo-renewed.app"

    /// Runs the one-time `UserDefaults` migration before the first real read of either migrated
    /// key, no matter which one is touched first: a `static let` initializes lazily, exactly
    /// once, on its own first access, which is why every accessor below evaluates this (via the
    /// discarded `_ =`) before touching its own key rather than relying on some later app-startup
    /// hook — `CoreEngine`'s own `appLanguage` property is itself initialized from
    /// `UserSettings.appLanguage` before `AppDelegate.applicationDidFinishLaunching` ever runs, so
    /// a hook there would already be too late.
    private static let migrateLegacyDefaultsOnce: Void = migrateLegacyDefaults()

    static var extraKeyFolders: [String] {
        get {
            _ = migrateLegacyDefaultsOnce
            return UserDefaults.standard.stringArray(forKey: extraKeyFoldersKey) ?? []
        }
        set {
            _ = migrateLegacyDefaultsOnce
            UserDefaults.standard.set(newValue, forKey: extraKeyFoldersKey)
        }
    }

    /// Whether `FirstRunFlow` has already been shown once. Set the moment the flow is presented,
    /// not when it is completed — someone who closes the window partway through has still "had"
    /// first run; it is a one-time welcome, not a gate that gets re-shown until every step is
    /// acted on. Defaults to `false`, so a fresh install (no value written yet) always shows it.
    ///
    /// Deliberately excluded from `migrateLegacyDefaults()`, unlike `extraKeyFolders` and
    /// `appLanguage` — this is not the same kind of gap left unfixed. `SettingsView`
    /// .`LaunchAtLoginRow` seeds itself from `SMAppService.mainApp.status`, which really is keyed
    /// to the bundle identifier: a person's login-item registration does not carry over, and
    /// re-registering under the new identity genuinely needs a person to go through that step
    /// again. Showing `FirstRunFlow` once more after the rename is what puts that step back in
    /// front of them, so reading `false` here under the new bundle identifier — because nothing
    /// ever copies the old value across — is the correct outcome, not an oversight to match
    /// `extraKeyFolders`. (The flow's own TLS Trust step reads `coreEngine.status.tlsTrusted`
    /// live rather than assuming untrusted, so it does not ask someone to redo the one step that
    /// the rename does not actually break.)
    static var hasCompletedFirstRun: Bool {
        get { UserDefaults.standard.bool(forKey: hasCompletedFirstRunKey) }
        set { UserDefaults.standard.set(newValue, forKey: hasCompletedFirstRunKey) }
    }

    /// The app's own chrome language (`AppLanguage`). This is the authority on it: the core's
    /// `Settings.uiLang` mirrors it so the pages served on `127.0.0.1` can follow it, but that
    /// mirror is written from here, not read back — it has to be, because the chrome has a
    /// language before the engine exists to be asked. `CoreEngine.refreshSettings()` reconciles
    /// the two on launch. Defaults to Russian, matching the original's own default.
    static var appLanguage: AppLanguage {
        get {
            _ = migrateLegacyDefaultsOnce
            return UserDefaults.standard.string(forKey: appLanguageKey).flatMap(AppLanguage.init(rawValue:)) ?? .ru
        }
        set {
            _ = migrateLegacyDefaultsOnce
            UserDefaults.standard.set(newValue.rawValue, forKey: appLanguageKey)
        }
    }

    /// Whether `UpdateChecker` may ask GitHub about new releases without being told to.
    ///
    /// Defaults to **on**, and `UserDefaults.bool(forKey:)` returns `false` for a key never
    /// written — so this reads the object first and only falls back to the default when there is
    /// genuinely nothing stored. Getting that wrong would silently switch update checking off for
    /// everyone who has never opened Settings.
    ///
    /// On by default because this is a signing client: a copy that quietly goes a year out of
    /// date is a security problem, not a preference. Off is one toggle away, and the Settings row
    /// says exactly what a check sends and where, so the choice is an informed one.
    static var automaticUpdateChecks: Bool {
        get { UserDefaults.standard.object(forKey: automaticUpdateChecksKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: automaticUpdateChecksKey) }
    }

    /// When the last check ran, successful or not — it is what rate-limits the automatic ones.
    static var lastUpdateCheck: Date? {
        get { UserDefaults.standard.object(forKey: lastUpdateCheckKey) as? Date }
        set { UserDefaults.standard.set(newValue, forKey: lastUpdateCheckKey) }
    }

    /// A release the person chose not to be reminded about. Stored as its version text rather
    /// than a flag, so the next release after it is announced normally.
    static var skippedUpdateVersion: String? {
        get { UserDefaults.standard.string(forKey: skippedUpdateVersionKey) }
        set { UserDefaults.standard.set(newValue, forKey: skippedUpdateVersionKey) }
    }

    /// Copies `extraKeyFolders` and `appLanguage` from the previous bundle identifier's
    /// `UserDefaults` domain into this one — guarded the same way `AppDirectories`' directory
    /// migration is: never overwrite a value already present under the new identity (a repeat
    /// launch, or someone who genuinely wants the default), and if the old domain has nothing to
    /// offer, or can't be opened at all, do nothing and let the getters above fall back to their
    /// own defaults rather than blocking startup on it. Not a directory move, so there is nothing
    /// to fail partway through — each key is copied independently and a miss on one says nothing
    /// about the other.
    ///
    /// `extraKeyFolders` is the one that matters: it is where someone's keys live when they are
    /// not on a mounted volume, and losing it silently would mean opening the app after an update
    /// and finding no keys at all with nothing on screen explaining why — the same failure shape
    /// as an unmigrated `sites.json`, just reached through `UserDefaults` instead of a directory.
    private static func migrateLegacyDefaults() {
        guard let legacy = UserDefaults(suiteName: legacyBundleIdentifier) else { return }
        let standard = UserDefaults.standard

        if standard.object(forKey: extraKeyFoldersKey) == nil,
           let legacyFolders = legacy.stringArray(forKey: extraKeyFoldersKey), !legacyFolders.isEmpty {
            standard.set(legacyFolders, forKey: extraKeyFoldersKey)
        }
        if standard.object(forKey: appLanguageKey) == nil,
           let legacyLanguage = legacy.string(forKey: appLanguageKey) {
            standard.set(legacyLanguage, forKey: appLanguageKey)
        }
    }
}
