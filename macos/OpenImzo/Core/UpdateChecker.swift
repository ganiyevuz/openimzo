import Foundation

/// Asks GitHub whether a newer release has been published, and remembers the answer.
///
/// Deliberately does not install anything. This app's whole argument is that you can read what it
/// does and build it yourself; an updater that silently replaces the binary on disk would be the
/// one component nobody could check, and it would be the most attractive thing in the app to
/// attack. So the most this does is open the release page in a browser and let a person decide.
/// That is also why there is no Sparkle dependency here: it would be third-party code with write
/// access to the app bundle, in a project whose CI deliberately runs no third-party actions.
@MainActor
@Observable
final class UpdateChecker {
    /// What the last check found. `Equatable` so a view can diff it without re-rendering on
    /// every unrelated change.
    enum Outcome: Equatable {
        case notCheckedYet
        case upToDate
        case updateAvailable(version: String, page: URL)
        /// Already human-readable and already in the app's language.
        case failed(String)
    }

    /// Once a day. Checking more often tells a person nothing new — releases are not published
    /// hourly — and every check is a request that reveals this machine's address to GitHub.
    private static let checkInterval: TimeInterval = 24 * 60 * 60

    /// After a check that failed, though: an hour. A launch with the network still coming up is
    /// the ordinary way this fails, and waiting a full day to try again would mean a person who
    /// was briefly offline hears nothing about an update until tomorrow.
    private static let retryInterval: TimeInterval = 60 * 60

    private(set) var outcome: Outcome = .notCheckedYet
    private(set) var isChecking = false
    private(set) var lastChecked: Date? = UserSettings.lastUpdateCheck

    /// Whether to check without being asked. Stored here as well as in `UserDefaults` because
    /// `@Observable` tracks stored properties, not computed ones reading through to somewhere
    /// else — a computed passthrough would leave the Settings toggle not redrawing itself.
    var automaticChecks: Bool {
        didSet { UserSettings.automaticUpdateChecks = automaticChecks }
    }

    /// A version the person chose not to be told about again. Cleared the moment they ask for a
    /// check themselves: asking is asking to be told.
    private var skippedVersion: String? {
        didSet { UserSettings.skippedUpdateVersion = skippedVersion }
    }

    init() {
        automaticChecks = UserSettings.automaticUpdateChecks
        skippedVersion = UserSettings.skippedUpdateVersion
    }

    /// The update worth showing a banner for: an available one the person has not skipped.
    var pendingUpdate: (version: String, page: URL)? {
        guard case let .updateAvailable(version, page) = outcome else { return nil }
        guard version != skippedVersion else { return nil }
        return (version, page)
    }

    /// A check the person asked for. Always runs, always reports, and un-skips whatever they had
    /// skipped, so pressing the button after skipping a version does not silently do nothing.
    func checkNow() async {
        skippedVersion = nil
        await check()
    }

    /// The check that happens on its own: only if it is switched on, and only once a day.
    ///
    /// Called at launch and whenever the main window appears, rather than from a repeating timer.
    /// This app is a menu-bar app that spends most of its life with no window open, so a timer
    /// would only be racing to have the answer ready a fraction of a second before opening the
    /// window can fetch it anyway — at the cost of a background task running for weeks.
    func checkAutomaticallyIfDue() async {
        guard automaticChecks else { return }
        let due: TimeInterval = if case .failed = outcome { Self.retryInterval } else { Self.checkInterval }
        if let lastChecked, Date.now.timeIntervalSince(lastChecked) < due { return }
        await check()
    }

    /// Stops the banner for this version without switching checking off.
    func skipPendingVersion() {
        guard case let .updateAvailable(version, _) = outcome else { return }
        skippedVersion = version
    }

    private struct LatestRelease: Decodable {
        let tagName: String
        let htmlUrl: String
    }

    private func check() async {
        guard !isChecking else { return }
        guard let endpoint = AppIdentity.latestReleaseEndpoint else {
            outcome = .failed(t("Update checking is not configured in this build."))
            return
        }
        guard let current = AppVersion.current else {
            outcome = .failed(t("This build does not report a version to compare against."))
            return
        }

        isChecking = true
        defer {
            isChecking = false
            let now = Date.now
            lastChecked = now
            UserSettings.lastUpdateCheck = now
        }

        var request = URLRequest(url: endpoint, timeoutInterval: 20)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        // GitHub refuses an API request with no User-Agent outright, so this names the app rather
        // than leaving URLSession's default and getting a 403 that looks like rate limiting.
        request.setValue("\(AppIdentity.productName)/\(current)", forHTTPHeaderField: "User-Agent")
        // The answer is the point; a cached one from yesterday is not.
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                outcome = .failed(t("GitHub gave an answer this app could not read."))
                return
            }
            switch http.statusCode {
            case 200:
                break
            case 404:
                // Also what a private repository answers to a request with no credentials, which
                // is the honest thing to say either way: there is nothing published to compare to.
                outcome = .failed(t("There is no published release to compare against yet."))
                return
            case 403, 429:
                outcome = .failed(t("GitHub is rate-limiting update checks right now. Try again later."))
                return
            default:
                outcome = .failed(t("GitHub answered %@.", String(http.statusCode)))
                return
            }

            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase
            let release = try decoder.decode(LatestRelease.self, from: data)

            guard let latest = AppVersion(release.tagName) else {
                outcome = .failed(t("The newest release is tagged %@, which this app cannot compare to its own version.", release.tagName))
                return
            }
            guard let page = URL(string: release.htmlUrl) else {
                outcome = .failed(t("GitHub gave an answer this app could not read."))
                return
            }
            outcome = latest > current ? .updateAvailable(version: latest.description, page: page) : .upToDate
        } catch is CancellationError {
            // The window closed mid-check. Not a failure to report.
        } catch let error as URLError where error.code == .cancelled {
            // The same thing, as URLSession reports it.
        } catch {
            outcome = .failed(error.localizedDescription)
        }
    }

    /// These strings are built in a model, not a view, so they cannot come from a `Text` literal —
    /// they go through the same catalogue lookup `CoreEngine`'s own error messages use.
    private func t(_ key: String, _ arguments: CVarArg...) -> String {
        UserSettings.appLanguage.locale.localizedAppString(key, arguments: arguments)
    }
}
