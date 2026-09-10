import SwiftUI
import os

/// The real request panels, replacing `InterimUiDelegate`. Every method here does the one thing
/// that decides whether this app is trustworthy: show exactly what asked, naming the website
/// from the request's own origin, floating above whatever else is on screen and focused the
/// moment it opens — and never answer on the person's behalf.
///
/// Named `MacUiDelegate` rather than the brief's suggested `UiDelegateImpl`, for the same reason
/// `MacPlatform` (Task 3) isn't `PlatformImpl`: `macos/Generated/openimzo.swift` already declares
/// `open class UiDelegateImpl: UiDelegate` as uniffi's own FFI wrapper for the trait, so that
/// exact name is reserved and would fail to compile as a redeclaration.
@MainActor
final class MacUiDelegate: UiDelegate {
    /// Told whenever a panel opens or closes, so `CoreEngine` can reflect it in the menu bar
    /// icon (`isRequestInFlight`). `CoreEngine` wires this in after constructing both itself and
    /// this delegate, since `Engine.init` needs the delegate before `CoreEngine` exists to hand
    /// a reference to.
    var onActivityChange: ((Bool) -> Void)?

    /// The app's own chrome language, applied to every panel this delegate presents. Panels are
    /// hosted in their own `NSHostingView` (`RequestPanelController`), built directly here rather
    /// than through the `App`/`Scene` graph `OpenImzoApp` sets `.environment(\.locale, _:)`
    /// on — so without this, every panel would render in whatever the system's own language is,
    /// regardless of what the person picked in this app. Kept in sync by
    /// `CoreEngine.setAppLanguage(_:)`; defaults to the persisted choice so the very first panel,
    /// before any in-process language change, still gets it right.
    var locale: Locale = UserSettings.appLanguage.locale

    private let logger = Logger(subsystem: "io.github.ganiyevuz.openimzo", category: "ui")

    /// The one panel currently on screen, if any. The core only ever asks for one at a time
    /// (`openimzo_rpc::ui::UiBroker` serializes every request), so this app does not build a queue
    /// on top of that — there is never more than one entry here.
    private var activePanel: (any CancellableRequestPanel)?

    func askPassword(request: PasswordRequest) async -> PasswordAnswer? {
        await present(cancelledAnswer: nil, deadlineSecs: request.deadlineSecs) { finish, deadline in
            AnyView(PasswordPanelView(request: request, deadline: deadline, onSubmit: finish, onCancel: { finish(nil) }))
        }
    }

    func askPermission(request: PermissionRequest) async -> PermissionAnswer {
        await present(cancelledAnswer: .deny, deadlineSecs: request.deadlineSecs) { finish, deadline in
            AnyView(PermissionPanelView(origin: request.origin, deadline: deadline, onAnswer: finish))
        }
    }

    func askNewPfx(request: NewPfxRequest) async -> NewPfxAnswer? {
        await present(cancelledAnswer: nil, deadlineSecs: request.deadlineSecs) { finish, deadline in
            AnyView(NewPfxPanelView(request: request, deadline: deadline, onSubmit: finish, onCancel: { finish(nil) }))
        }
    }

    func confirmLegacyAlgorithm(origin: String, requested: String, suggested: String, deadlineSecs: UInt32) async -> Bool {
        await present(cancelledAnswer: false, deadlineSecs: deadlineSecs) { finish, deadline in
            AnyView(LegacyAlgorithmPanelView(origin: origin, requested: requested, suggested: suggested, deadline: deadline, onAnswer: finish))
        }
    }

    func confirmRandseed(origin: String, deadlineSecs: UInt32) async -> Bool {
        await present(cancelledAnswer: false, deadlineSecs: deadlineSecs) { finish, deadline in
            AnyView(RandseedPanelView(origin: origin, deadline: deadline, onAnswer: finish))
        }
    }

    func notify(level: String, title: String, text: String) async {
        // No dedicated notification UI exists yet — the design spec's Activity log (Task 5's
        // main window) is the eventual home for this. Logged rather than dropped in the
        // meantime. Never carries a password or PIN: the protocol reserves those for
        // `askPassword`/`askNewPfx`, which never route through here.
        logger.log(level: level == "ERROR" ? .error : .info, "\(title, privacy: .public): \(text, privacy: .public)")
    }

    func cancel(requestId: String) async {
        // Only one panel is ever open — the core serializes requests and this app doesn't queue
        // on top of that — so there is nothing to match `requestId` against; whatever is
        // showing is the request being cancelled.
        activePanel?.cancelFromCore()
    }

    /// The same effect as `cancel(requestId:)`, but called by `CoreEngine.prepareForQuit()`
    /// rather than by the core: Quit must take down any open panel itself (controller addendum
    /// #3) rather than waiting for the deadline the core would otherwise enforce, or for the
    /// process exiting to close the window out from under whatever request was in flight.
    func forceCloseActivePanel() {
        activePanel?.cancelFromCore()
    }

    /// Shared plumbing for all five request kinds: builds the panel, tracks it as the single
    /// active one, flips the menu bar's "request in flight" state around its lifetime, and
    /// resumes the calling `UiDelegate` method's continuation exactly once with whatever answer
    /// the panel resolves — a real one from the person, or `cancelledAnswer` if the core calls
    /// `cancel` first. `deadlineSecs` always comes from the request itself (every one of the
    /// five now carries its own), never a guess held here, so the countdown can never drift from
    /// the deadline the core's own broker actually enforces.
    private func present<Answer>(
        cancelledAnswer: Answer,
        deadlineSecs: UInt32,
        content: @escaping (@escaping (Answer) -> Void, Date) -> AnyView
    ) async -> Answer {
        await withCheckedContinuation { continuation in
            let deadline = Date().addingTimeInterval(TimeInterval(deadlineSecs))
            let controller = RequestPanelController<Answer>(cancelledAnswer: cancelledAnswer) { [weak self] answer in
                self?.activePanel = nil
                self?.onActivityChange?(false)
                continuation.resume(returning: answer)
            } content: { finish in
                // `.environment(\.locale, locale)` here, once, rather than on each of the five
                // panel views individually — see `locale`'s own doc comment for why this is
                // needed at all.
                content(finish, deadline).environment(\.locale, locale)
            }
            activePanel = controller
            onActivityChange?(true)
            controller.present()
        }
    }
}
