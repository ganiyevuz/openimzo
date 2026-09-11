import SwiftUI

/// The three icon states the menu bar item can show, computed from `CoreEngine`'s real data —
/// never guessed. `idle` needs both listeners up and no request in flight; anything else that
/// isn't a request in progress counts as a problem, including not knowing yet (`status == nil`,
/// e.g. before the first refresh completes).
@MainActor
enum MenuBarIconState {
    case idle
    case requestInFlight
    case problem

    init(coreEngine: CoreEngine) {
        if coreEngine.constructionError != nil {
            self = .problem
        } else if coreEngine.isRequestInFlight {
            self = .requestInFlight
        } else if let status = coreEngine.status, status.ws, status.wss {
            self = .idle
        } else {
            self = .problem
        }
    }

    var symbolName: String {
        switch self {
        case .idle: "checkmark.seal"
        case .requestInFlight: "ellipsis.circle"
        case .problem: "exclamationmark.triangle"
        }
    }

    /// `LocalizedStringKey`, not `String`: a plain `String` here would make
    /// `.accessibilityLabel(state.accessibilityDescription)` render verbatim in whatever
    /// language this literal was written in, never looked up in the string catalogue.
    var accessibilityDescription: LocalizedStringKey {
        switch self {
        case .idle: "\(AppIdentity.productName) is running"
        case .requestInFlight: "\(AppIdentity.productName) has a request in progress"
        case .problem: "\(AppIdentity.productName) has a problem"
        }
    }
}

/// The menu bar item's label (the glyph shown in the menu bar itself).
struct MenuBarIcon: View {
    var coreEngine: CoreEngine

    var body: some View {
        let state = MenuBarIconState(coreEngine: coreEngine)
        Image(systemName: state.symbolName)
            .accessibilityLabel(state.accessibilityDescription)
    }
}

/// What drops down when the menu bar item is clicked.
///
/// "Developer Mode" and "Launch at Login" are deliberately shown here read-only and disabled
/// rather than removed: both are real settings a person can change, one screen away in Settings,
/// and the menu is the fastest place to see what they are currently set to. A control that is
/// visibly disabled says "not here"; a missing one says "not anywhere".
///
/// "Check for Updates" is wired. It was a placeholder for a Sparkle integration that this project
/// then decided against — see `UpdateChecker`, which asks GitHub and never installs anything —
/// and leaving it greyed out afterwards would have been claiming a feature was missing while it
/// sat finished one menu away.
struct MenuBarContent: View {
    var coreEngine: CoreEngine
    var updateChecker: UpdateChecker

    @Environment(\.openWindow) private var openWindow
    @Environment(\.locale) private var locale
    @AppStorage(UserSettings.maskSensitiveDataKey) private var maskSensitiveData = false

    var body: some View {
        Group {
            Button("Open \(AppIdentity.productName)") {
                openMainWindow()
            }

            Menu("Keys") {
                if coreEngine.keys.isEmpty {
                    Text("No keys found")
                        .disabled(true)
                } else {
                    ForEach(coreEngine.keys, id: \.fullPath) { key in
                        // An Uzbek key file is named after the identifier inside it, so the file
                        // name is exactly the thing Settings' masking switch exists to hide. The
                        // validity word beside it stays, which is what makes the entry still
                        // worth having while masked.
                        Button("\(SensitiveText.render(key.name, hidden: maskSensitiveData)) — \(validityWord(for: key))") {
                            coreEngine.pendingKeySelection = key.fullPath
                            openMainWindow()
                        }
                    }
                }
            }

            Divider()

            Toggle("Developer Mode", isOn: .constant(coreEngine.status?.devMode ?? false))
                .disabled(true)
            Menu("Language") {
                ForEach(AppLanguage.allCases) { language in
                    Button {
                        Task { await coreEngine.setAppLanguage(language) }
                    } label: {
                        // `verbatim:` deliberately: a language's own name for itself is never
                        // re-expressed in whichever language happens to be selected right now —
                        // see `AppLanguage.displayName`'s own doc comment.
                        if coreEngine.appLanguage == language {
                            Label {
                                Text(verbatim: language.displayName)
                            } icon: {
                                Image(systemName: "checkmark")
                            }
                        } else {
                            Text(verbatim: language.displayName)
                        }
                    }
                }
            }
            Toggle("Launch at Login", isOn: .constant(false))
                .disabled(true)
            Button(updateChecker.isChecking ? "Checking…" : "Check for Updates…") {
                Task {
                    await updateChecker.checkNow()
                    // Opening the window is the point: the result lands in Settings, and a
                    // banner appears there and on every other section if there is an update.
                    openMainWindow()
                }
            }
            .disabled(updateChecker.isChecking)

            Divider()

            Button("Quit \(AppIdentity.productName)") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q")
        }
        .task {
            await coreEngine.refreshStatus()
            await coreEngine.refreshKeys()
        }
    }

    /// `openWindow(id:)` alone creates the window the first time, but this app has no Dock icon
    /// (`LSUIElement`) — an accessory app doesn't automatically raise or activate an existing
    /// window the way a regular app's would, so once the person has clicked away from it (or
    /// closed it) a second `openWindow` call can leave it open but not actually in front, with no
    /// Dock icon to click to bring it back. `NSApp.activate` is the same call
    /// `RequestPanelController.present()` already makes for request panels, for the same reason.
    private func openMainWindow() {
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: MainWindow.id)
    }

    /// `key.name` is data, interpolated as-is; the validity word beside it is chrome text, and
    /// must not be. Resolving it explicitly, rather than interpolating a raw `"expired"`/`"valid"`
    /// ternary straight into the button's title string, is what makes it actually translate:
    /// a literal nested inside a larger interpolated string is substituted verbatim, never looked
    /// up in the catalogue — the exact mistake this task's brief calls out.
    private func validityWord(for key: KeyEntry) -> String {
        locale.localizedAppString(key.expired ? "Expired" : "Valid")
    }
}
