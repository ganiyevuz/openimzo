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

/// What drops down when the menu bar item is clicked. "Open OpenImzo", the Keys submenu,
/// Language, and "Quit" are wired; Developer Mode, Launch at Login, and Check for Updates are a
/// later task's job (Sparkle updates: a later phase) and are shown visibly disabled rather than
/// silently doing nothing, so nobody mistakes an unwired control for a broken one.
struct MenuBarContent: View {
    var coreEngine: CoreEngine

    @Environment(\.openWindow) private var openWindow
    @Environment(\.locale) private var locale

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
                        Button("\(key.name) — \(validityWord(for: key))") {
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
            Button("Check for Updates…") {}
                .disabled(true)

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
