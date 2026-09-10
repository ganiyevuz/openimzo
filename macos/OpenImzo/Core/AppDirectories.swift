import Foundation
import os

/// Where this app keeps its own files, per the design spec (the design spec): application-support data under `~/Library/Application Support/OpenImzo`,
/// logs under `~/Library/Logs/OpenImzo`.
///
/// `CoreEngine` uses this to build the `EngineConfig` it constructs the `Engine` with, and
/// `InterimPlatform` uses the same helper for its `appSupportDir()`/`logsDir()` methods, so the
/// two can never disagree about where these directories live. Both callers ask for the
/// directory the same way and then check `exists(_:)` for themselves, since what to do about a
/// creation failure differs: `CoreEngine` turns it into a visible problem state, while
/// `Platform`'s protocol methods are synchronous and non-throwing and can only report the
/// intended path either way.
enum AppDirectories {
    static let folderName = "OpenImzo"

    /// The name this app shipped under before the OpenImzo rename. Read exactly once per
    /// directory, by `migrateLegacyDirectoryIfNeeded`, and nowhere else — everything downstream
    /// of that function only ever sees `folderName`.
    private static let legacyFolderName = "E-IMZO Renewed"

    private static let logger = Logger(subsystem: "io.github.ganiyevuz.openimzo", category: "startup")

    /// `~/Library/Application Support/OpenImzo`. Creates it if absent — after first moving the
    /// old `E-IMZO Renewed` directory into place, if this is the first launch since the rename —
    /// and the directory may still not exist afterward if creation failed (read-only or missing
    /// volume, say). Check `exists(_:)` if that matters to the caller.
    static func appSupportDirectory() -> URL {
        ensuredDirectory(searchPath: .applicationSupportDirectory, extraComponents: [])
    }

    /// `~/Library/Logs/OpenImzo`, same creation caveat and same migration as `appSupportDirectory()`.
    static func logsDirectory() -> URL {
        ensuredDirectory(searchPath: .libraryDirectory, extraComponents: ["Logs"])
    }

    static func exists(_ url: URL) -> Bool {
        var isDirectory: ObjCBool = false
        let found = FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
        return found && isDirectory.boolValue
    }

    private static func ensuredDirectory(searchPath: FileManager.SearchPathDirectory, extraComponents: [String]) -> URL {
        // `FileManager` not knowing its own `Library` domain would be a broken installation,
        // not something this app can repair — falls back to a plain path under the home
        // directory so callers still get *something* to report rather than a crash.
        let fallback = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true).appendingPathComponent("Library", isDirectory: true)
        var base = FileManager.default.urls(for: searchPath, in: .userDomainMask).first ?? fallback
        for component in extraComponents {
            base.appendPathComponent(component, isDirectory: true)
        }
        let url = base.appendingPathComponent(folderName, isDirectory: true)
        migrateLegacyDirectoryIfNeeded(legacyURL: base.appendingPathComponent(legacyFolderName, isDirectory: true), newURL: url)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// One-time migration for anyone who already ran the app under its previous name: moves —
    /// never copies — the old per-user directory to the new one, so `settings.json`, `sites.json`
    /// (the origin allow-list someone may have spent real effort building) and `tls/` all carry
    /// over rather than the app starting empty and silently discarding them. A move rather than a
    /// copy so there is exactly one home afterward and no drift between two copies.
    ///
    /// Silent when there is nothing to migrate — no old directory, or the new one already exists
    /// (already migrated, or a fresh install that never had the old name) — because that is the
    /// ordinary case for the overwhelming majority of launches, first ones very much included, and
    /// an ordinary case does not belong in the log at any level.
    ///
    /// If the move itself fails, the old directory is left exactly as it was — no partial
    /// migration, no data removed from the only place it still exists — and the one thing this
    /// does is say so in the log; the caller falls through to creating a fresh, empty new
    /// directory regardless, so a failure here never stops the app from starting.
    private static func migrateLegacyDirectoryIfNeeded(legacyURL: URL, newURL: URL) {
        guard !exists(newURL), exists(legacyURL) else { return }
        do {
            try FileManager.default.moveItem(at: legacyURL, to: newURL)
        } catch {
            logger.error(
                "Could not migrate \(legacyURL.path, privacy: .public) to \(newURL.path, privacy: .public): \(error.localizedDescription, privacy: .public); starting fresh at the new location instead."
            )
        }
    }
}
