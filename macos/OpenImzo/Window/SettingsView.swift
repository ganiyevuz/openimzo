import ServiceManagement
import SwiftUI

/// Not `private`: `FirstRunFlow`'s own launch-at-login step reuses this exact row rather than
/// duplicating `SMAppService`'s register/unregister error handling a second time.
struct LaunchAtLoginRow: View {
    var coreEngine: CoreEngine
    let settings: Settings

    @State private var isEnabled = SMAppService.mainApp.status == .enabled
    @State private var isWorking = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Toggle("Launch at Login", isOn: Binding(get: { isEnabled }, set: setEnabled))
                .disabled(isWorking)
            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }

    private func setEnabled(_ enabled: Bool) {
        errorMessage = nil
        isWorking = true
        Task {
            do {
                if enabled {
                    try SMAppService.mainApp.register()
                } else {
                    try await SMAppService.mainApp.unregister()
                }
                isEnabled = enabled
                var updated = settings
                updated.launchAtLogin = enabled
                await coreEngine.updateSettings(updated)
            } catch {
                errorMessage = error.localizedDescription
            }
            isWorking = false
        }
    }
}

private struct PortStatusRow: View {
    /// `LocalizedStringKey`, not `String`: `LabeledContent(label)` has both a `LocalizedStringKey`
    /// overload and a disfavoured verbatim `StringProtocol` one, and a plain `String` field picks
    /// the latter, silently skipping the string catalogue.
    let label: LocalizedStringKey
    let isUp: Bool
    let port: UInt16

    var body: some View {
        LabeledContent(label) {
            HStack(spacing: 6) {
                Circle()
                    .fill(isUp ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                // `String(port)`, not a bare `\(port)`: `LocalizedStringKey` interpolation needs
                // a `String` argument to reliably produce a `%@` catalogue placeholder — leaving
                // an integer to pick its own format specifier is a needless way to get this wrong.
                Text(isUp ? "Listening on \(String(port))" : "Not listening")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

/// Language, launch at login, TLS trust, port status, developer mode, password memory, seed
/// policy, and activity persistence — the design spec's own list for this screen — plus, per the
/// controller addendum, the construction failure banner: a construction failure has to say what
/// went wrong, with a retry, rather than showing the same problem triangle every time.
struct SettingsView: View {
    var coreEngine: CoreEngine
    var updateChecker: UpdateChecker

    @Environment(\.locale) private var locale
    @State private var isInstallingTrust = false

    var body: some View {
        Form {
            if let constructionError = coreEngine.constructionError {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("\(AppIdentity.productName) could not start", systemImage: "exclamationmark.triangle.fill")
                            .font(.headline)
                            .foregroundStyle(.red)
                        Text(constructionError)
                            .font(.callout)
                        Button("Retry") { coreEngine.retryConstruction() }
                    }
                    .padding(.vertical, 4)
                }
            }

            // Outside the `if let settings` below deliberately: the app's own chrome language
            // does not depend on `Settings` having loaded — `coreEngine.appLanguage` is read
            // from `UserDefaults` at construction (`UserSettings.appLanguage`) — so a person can
            // still switch it even while `coreEngine.settings` is `nil` (still loading, or the
            // engine failed to construct).
            Section("Language") {
                Picker("Language", selection: languageBinding) {
                    ForEach(AppLanguage.allCases) { language in
                        // `verbatim:` deliberately — see `AppLanguage.displayName`'s own doc
                        // comment: a language's own name for itself is never re-expressed in
                        // whichever language happens to be selected right now.
                        Text(verbatim: language.displayName).tag(language)
                    }
                }
            }

            if let settings = coreEngine.settings {
                Section("Startup") {
                    LaunchAtLoginRow(coreEngine: coreEngine, settings: settings)
                }

                Section("Server") {
                    if let status = coreEngine.status {
                        PortStatusRow(label: "Plain (WS)", isUp: status.ws, port: status.wsPort)
                        PortStatusRow(label: "TLS (WSS)", isUp: status.wss, port: status.wssPort)
                        Toggle("Developer Mode", isOn: toggleBinding(settings, \.developerMode))
                    } else {
                        Text("Status not yet known.").foregroundStyle(.secondary)
                    }
                }

                Section("TLS Trust") {
                    if let status = coreEngine.status {
                        LabeledContent("Trust Status") {
                            Label(
                                status.tlsTrusted ? "Trusted" : "Not Trusted",
                                systemImage: status.tlsTrusted ? "lock.fill" : "lock.slash.fill"
                            )
                            .foregroundStyle(status.tlsTrusted ? .green : .red)
                        }
                        HStack {
                            Text("Installs into your login keychain only.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Button(isInstallingTrust ? "Installing…" : "Install Trust") {
                                Task {
                                    isInstallingTrust = true
                                    _ = await coreEngine.installTlsTrust()
                                    isInstallingTrust = false
                                }
                            }
                            .disabled(isInstallingTrust || status.tlsTrusted)
                        }
                    }
                }

                Section("Passwords") {
                    Toggle("Remember Passwords for 6 Hours", isOn: toggleBinding(settings, \.rememberPasswords))
                    Button("Clear Cached Passwords Now") {
                        Task { await coreEngine.clearPasswordCache() }
                    }
                }

                Section("Randomness") {
                    Toggle("Ask Before Seeding From a Website", isOn: toggleBinding(settings, \.askBeforeRandseed))
                }

                Section("Activity") {
                    Toggle("Keep Activity Log Across Launches", isOn: toggleBinding(settings, \.keepActivityLog))
                }

                updatesSection
            } else {
                Section {
                    HStack {
                        ProgressView()
                        Text("Loading settings…").foregroundStyle(.secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
        // No `.navigationTitle` here: `MainWindow` sets the window's title bar itself, for all
        // five sections in one place — see its own doc comment for why.
        .task { await coreEngine.refreshSettings() }
    }

    /// Update management: whether to check on its own, a button to check now, and what the last
    /// check found.
    ///
    /// The line about what a check sends is not decoration. This app asks people to trust it with
    /// their signing key; a feature that quietly makes a network request to a third party has to
    /// say so where the switch for it is, not in a policy document nobody opens.
    @ViewBuilder private var updatesSection: some View {
        Section("Updates") {
            Toggle("Check for Updates Automatically", isOn: Binding(
                get: { updateChecker.automaticChecks },
                set: { updateChecker.automaticChecks = $0 }
            ))
            Text("Asks GitHub once a day whether a newer release exists. It sends nothing about you or your keys — but, like opening any web page, it does tell GitHub this computer's address.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Text(lastCheckDescription)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button(updateChecker.isChecking ? "Checking…" : "Check Now") {
                    Task { await updateChecker.checkNow() }
                }
                .disabled(updateChecker.isChecking)
            }

            switch updateChecker.outcome {
            case .notCheckedYet:
                EmptyView()
            case .upToDate:
                Label("This is the newest release.", systemImage: "checkmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.green)
            case let .updateAvailable(version, page):
                HStack {
                    Label("Version \(String(version)) is available.", systemImage: "arrow.down.circle.fill")
                        .font(.caption)
                    Spacer()
                    Link("Open Release Page", destination: page)
                        .font(.caption)
                }
            case let .failed(reason):
                // `Text(verbatim:)`: the reason is already a resolved sentence in the app's own
                // language (or the system's, for a URLSession error), never a catalogue key.
                Label { Text(verbatim: reason) } icon: { Image(systemName: "exclamationmark.triangle.fill") }
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// "Never checked." or "Last checked <when>", in the app's language rather than the system's
    /// — which is why the date goes through `Locale.localizedAppString(_:_:)` with an explicitly
    /// localized date string rather than a plain `Text(date, style:)`.
    private var lastCheckDescription: String {
        guard let lastChecked = updateChecker.lastChecked else {
            return locale.localizedAppString("Never checked.")
        }
        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return locale.localizedAppString("Last checked %@", formatter.string(from: lastChecked))
    }

    private func toggleBinding(_ settings: Settings, _ keyPath: WritableKeyPath<Settings, Bool>) -> Binding<Bool> {
        Binding(
            get: { settings[keyPath: keyPath] },
            set: { newValue in
                var updated = settings
                updated[keyPath: keyPath] = newValue
                Task { await coreEngine.updateSettings(updated) }
            }
        )
    }

    /// Drives the app's own chrome language through `CoreEngine.setAppLanguage(_:)`, which also
    /// tells the core (per task 6's controller addendum) — never `updateSettings` directly, same
    /// as everywhere else in this app: `CoreEngine` is the only place a core call is made.
    private var languageBinding: Binding<AppLanguage> {
        Binding(
            get: { coreEngine.appLanguage },
            set: { newValue in Task { await coreEngine.setAppLanguage(newValue) } }
        )
    }
}
