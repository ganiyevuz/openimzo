import SwiftUI

/// Owns `CoreEngine` and intercepts app termination. Marked `@MainActor` so it can hold a
/// `CoreEngine` (itself `@MainActor`) as a plain stored property — `NSApplicationDelegateAdaptor`
/// creates this on the main thread before any scene renders, which is also why `OpenImzoApp`
/// reads `appDelegate.coreEngine` rather than each owning a separate one that would need to be
/// kept in sync.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let coreEngine = CoreEngine()
    let updateChecker = UpdateChecker()

    /// Shows `FirstRunFlow` once, the very first time this app is ever launched — a no-op on
    /// every later launch (`UserSettings.hasCompletedFirstRun`). Here rather than anywhere in the
    /// `Scene` graph because nothing in `OpenImzoApp.body` runs exactly once at launch the way
    /// this delegate callback does; `FirstRunFlow` builds its own window directly, the same way
    /// `MacUiDelegate`'s request panels do, rather than needing a `Scene` of its own.
    func applicationDidFinishLaunching(_ notification: Notification) {
        FirstRunFlow.presentIfNeeded(coreEngine: coreEngine)
        // Detached from launch rather than awaited: a slow or unreachable GitHub must not hold
        // up the app starting, and nothing on screen is waiting for the answer.
        Task { await updateChecker.checkAutomaticallyIfDue() }
    }

    /// Quit must not kill the process out from under an open panel (controller addendum #3):
    /// `.terminateLater` holds termination open while `CoreEngine.prepareForQuit()` takes down
    /// any open request panel and stops the engine, bounded so a stop that hangs cannot make
    /// Quit hang either.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        Task {
            await coreEngine.prepareForQuit()
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}

@main
struct OpenImzoApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        // Forces every view to look strings up in `appLanguage`'s language, rather than the
        // system's — the original itself defaults to Russian regardless of the Mac's own
        // language, and task 6's own brief asks for the same. Read here, on `CoreEngine` (an
        // `@Observable` type), so a language change re-evaluates this `body` and every view picks
        // it up together, the moment `Settings` or the menu bar's own Language submenu changes it
        // — see `CoreEngine.setAppLanguage(_:)`.
        //
        // Applied to each root *view*, not via `Scene.environment(_:_:)` on the scenes
        // themselves: that modifier exists, but empirically does not reach `MenuBarExtra`'s
        // `label` closure or its content's own environment lookups reliably — verified by
        // running the app and reading the menu bar in each language (task 6's own verification
        // requirement) — while environment set directly on each root view always does.
        let locale = appDelegate.coreEngine.appLanguage.locale

        MenuBarExtra {
            MenuBarContent(coreEngine: appDelegate.coreEngine)
                .environment(\.locale, locale)
        } label: {
            MenuBarIcon(coreEngine: appDelegate.coreEngine)
                .environment(\.locale, locale)
        }
        .menuBarExtraStyle(.menu)

        // `AppIdentity.productName`, not a literal: this is a `String` value, not a string
        // literal, so it picks `Window`'s verbatim initializer — correct, since a product name
        // is never translated (see `AppIdentity`'s own doc comment) — and it means this is the
        // window scene's title, found the same single-search way as every other occurrence.
        Window(AppIdentity.productName, id: MainWindow.id) {
            MainWindow(coreEngine: appDelegate.coreEngine, updateChecker: appDelegate.updateChecker)
                .environment(\.locale, locale)
        }
        .defaultSize(width: 900, height: 560)
    }
}
