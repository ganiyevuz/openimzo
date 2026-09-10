import AppKit
import SwiftUI
import os

/// Conformed to by `RequestPanelController<Answer>` regardless of what `Answer` is, so
/// `MacUiDelegate` can hold "whatever panel is on screen right now" as a single property and
/// tell it to close without needing to know which of the five request kinds it is.
@MainActor
protocol CancellableRequestPanel: AnyObject {
    /// The core's deadline passed and the answer is no longer wanted (`UiDelegate.cancel`):
    /// take the panel down and resolve with its cancellation value, exactly as if the person had
    /// pressed Cancel. This is not an error path.
    func cancelFromCore()
}

/// Lets the SwiftUI content resolve the request without capturing `RequestPanelController`
/// itself. A plain class (not an `NSObject` subclass) has no two-phase-init restriction, so the
/// content closure can be built and wired to this box before the controller — which does need
/// `super.init()` first, being an `NSWindowDelegate` — exists at all.
///
/// Both `RequestPanelController.cancelFromCore()` and the panel's own Cancel/Submit buttons
/// funnel through the same `finish(with:)`, so whichever fires first — a person answering, or
/// the core's deadline passing — wins, and the other is a no-op.
@MainActor
private final class RequestFinishBox<Answer> {
    var resolve: ((Answer) -> Void)?
    var window: NSWindow?

    func finish(with answer: Answer) {
        guard let resolve else { return }
        self.resolve = nil
        resolve(answer)
        window?.close()
    }
}

/// Presents one SwiftUI view as a floating panel and turns its callback-based answer into the
/// single continuation `MacUiDelegate` is awaiting. Every one of the five request panels is
/// shown through this same controller, so all five get identical trust-critical behaviour:
///
/// - On top of every other window, including a full-screen browser's own Space
///   (`level = .floating`, `.canJoinAllSpaces`), and the app is activated the moment it opens
///   (`present()`). A signing prompt a person cannot see is a security failure, not a
///   cosmetic one.
/// - Resolves exactly once. The person answering and the core calling `cancel` at the same
///   moment must never both fire — see `RequestFinishBox`.
///
/// The window's size is computed once, synchronously, from the content's own ideal size before
/// the window is ever shown — deliberately not via `NSHostingController.sizingOptions`, which
/// tracks `preferredContentSize` reactively. That reactive path is what a real crash during this
/// task's own manual verification traced back to: a `preferredContentSize` change reaching
/// `-[NSWindow(NSDisplayCycle) _postWindowNeedsUpdateConstraints]` while a display cycle was
/// already in flight aborts the process. Every panel's shape is static for its whole lifetime
/// once shown (typing into a field changes a value, never adds or removes a row), so a size
/// computed once, up front, is exactly right for it — and never touches that path again.
@MainActor
final class RequestPanelController<Answer>: NSObject, NSWindowDelegate, CancellableRequestPanel {
    private let window: NSPanel
    private let cancelledAnswer: Answer
    private let box: RequestFinishBox<Answer>

    init<Content: View>(
        cancelledAnswer: Answer,
        resolve: @escaping (Answer) -> Void,
        @ViewBuilder content: (@escaping (Answer) -> Void) -> Content
    ) {
        self.cancelledAnswer = cancelledAnswer

        let box = RequestFinishBox<Answer>()
        box.resolve = resolve
        self.box = box

        let hostingView = NSHostingView(rootView: content { answer in box.finish(with: answer) })
        // A one-time layout pass, computed off screen, before this becomes any window's content
        // view — not an ongoing, reactive measurement.
        let size = hostingView.fittingSize
        hostingView.frame = NSRect(origin: .zero, size: size)

        let panel = NSPanel(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.titled, .closable, .utilityWindow],
            backing: .buffered,
            defer: false
        )
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.titleVisibility = .hidden
        panel.contentView = hostingView
        window = panel
        box.window = panel

        super.init()
        window.delegate = self
    }

    /// Activates the app and brings the panel to the front, focused. Called once, right after
    /// construction.
    func present() {
        NSApp.activate(ignoringOtherApps: true)
        window.center()
        window.makeKeyAndOrderFront(nil)
    }

    func cancelFromCore() {
        box.finish(with: cancelledAnswer)
    }

    /// The person closed the panel with the titlebar button rather than Escape or a Cancel
    /// button — the same cancellation, by a different route.
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        box.finish(with: cancelledAnswer)
        return true
    }
}

/// Calls `onBecomeKey` when the view's own window actually becomes key, rather than assuming one
/// runloop hop after `.onAppear` is always enough — that exact assumption caused this same
/// keyboard-focus bug twice already (`PasswordPanelView`, `NewPfxPanelView`): it holds today, but
/// nothing in the API guarantees it, and a slower machine or extra latency inside
/// `NSApp.activate`/`makeKeyAndOrderFront` leaves the window key while the field is not focused.
///
/// A zero-size `NSViewRepresentable` rather than a SwiftUI-only mechanism, because SwiftUI gives a
/// view no way to observe its own `NSWindow` directly. `makeNSView` runs before this view's
/// hosting window exists yet (`RequestPanelController` measures the hosting view's `fittingSize`
/// before ever assigning it as a panel's content view), so reading `.window` is deferred one
/// runloop turn — not a guess about *when the window becomes key*, only about when the view has
/// been attached to it. Covers both orderings: a window that is already key by the time the
/// observer attaches, and one that becomes key some time after.
///
/// That deferral is itself an assumption — that SwiftUI has materialized this representable's
/// view into the hierarchy within one runloop turn — and it is an assumption about SwiftUI's
/// AppKit bridging rather than anything the public API promises. Checking once and giving up
/// would fail silently and land in exactly the original symptom, keystrokes going nowhere, for
/// the third time in this panel. So it retries until the window appears and says so in the log
/// if it never does, which makes a future recurrence diagnosable instead of invisible.
struct WindowKeyObserver: NSViewRepresentable {
    let onBecomeKey: () -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView(frame: .zero)
        context.coordinator.attach(to: view)
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onBecomeKey: onBecomeKey)
    }

    @MainActor
    final class Coordinator {
        /// Runloop turns to wait for the view to reach a window before giving up. One is enough
        /// in every observed case; this is the margin, not the expectation. Bounded because a
        /// view that never reaches a window — a panel torn down before it was shown — must not
        /// leave something rescheduling itself forever.
        private static let maxAttempts = 60

        private let logger = Logger(subsystem: "io.github.ganiyevuz.openimzo", category: "ui")
        private let onBecomeKey: () -> Void
        private var token: NSObjectProtocol?
        private var attempts = 0

        init(onBecomeKey: @escaping () -> Void) {
            self.onBecomeKey = onBecomeKey
        }

        /// Waits for `view` to reach a window, then observes it. Holds `view` weakly so a panel
        /// dismissed while this is still waiting is free to deallocate, which also ends the
        /// retries.
        func attach(to view: NSView) {
            DispatchQueue.main.async { [weak self, weak view] in
                guard let self, let view, self.token == nil else { return }
                if let window = view.window {
                    self.observe(window: window)
                    return
                }
                self.attempts += 1
                guard self.attempts < Self.maxAttempts else {
                    self.logger.error(
                        "request panel: the view never reached a window, so keyboard focus was not set"
                    )
                    return
                }
                self.attach(to: view)
            }
        }

        private func observe(window: NSWindow) {
            guard token == nil else { return }
            if window.isKeyWindow {
                onBecomeKey()
            }
            // The observation block is `@Sendable`, so it cannot touch this main-actor-isolated
            // class directly. `queue: .main` already guarantees it runs on the main thread, which
            // is precisely the condition `assumeIsolated` exists to assert — rather than a `Task`
            // hop, which would delay focus by another turn for no reason.
            token = NotificationCenter.default.addObserver(
                forName: NSWindow.didBecomeKeyNotification,
                object: window,
                queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.onBecomeKey() }
            }
        }

        deinit {
            if let token {
                NotificationCenter.default.removeObserver(token)
            }
        }
    }
}

/// A `mm:ss`-style countdown to `deadline`, ticking once a second. Purely a display: the actual
/// timeout is enforced by the core (`eimzo_rpc::ui::UiBroker`), which calls
/// `UiDelegate.cancel(requestId:)` when it passes — this label only shows how much time is left
/// before that happens.
struct CountdownLabel: View {
    let deadline: Date

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let remaining = max(0, Int(deadline.timeIntervalSince(context.date).rounded(.up)))
            Text(String(format: "0:%02d", remaining))
                .font(.callout.monospacedDigit())
                .foregroundStyle(remaining <= 10 ? Color.red : Color.secondary)
                // `String(remaining)`, not a bare `\(remaining)`: an `Int` interpolated straight
                // into a `LocalizedStringKey` picks its own format specifier, which is a needless
                // way to get the string catalogue's key wrong; a `String` argument always
                // produces a plain `%@`.
                .accessibilityLabel(Text("\(String(remaining)) seconds remaining"))
        }
    }
}

/// The header every panel opens with: an icon, a description of what's being asked, the
/// requesting website's origin, and the countdown. The origin is the one field that lets a
/// person tell a real request from a malicious one, so it is always the largest, most prominent
/// text in the header — never truncated to the point of being unreadable, and selectable so it
/// can be copied out and checked.
struct RequestPanelHeader: View {
    let symbolName: String
    /// `LocalizedStringKey`, not `String`: every one of the five panels passes a literal here
    /// ("Password requested by", "Permission requested by", ...) meant to be translated — a
    /// `String` field feeding `Text(subtitle)` would render it verbatim instead, in whatever
    /// language it happened to be written in, no matter what the string catalogue says.
    let subtitle: LocalizedStringKey
    let origin: String
    let deadline: Date

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbolName)
                .font(.system(size: 26))
                .foregroundStyle(.secondary)
                .frame(width: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text(origin)
                    .font(.headline)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 8)
            CountdownLabel(deadline: deadline)
        }
    }
}
