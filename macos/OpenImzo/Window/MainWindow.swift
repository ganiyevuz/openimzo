import SwiftUI

/// The sidebar sections of the main window. Deliberately excludes Tokens: hardware tokens are a
/// later phase, and the controller addendum for this task is explicit that an empty section is
/// worse than no section at all — no row, no disabled item, no "coming soon" line.
enum MainWindowSection: String, CaseIterable, Identifiable, Hashable {
    case keys, sites, activity, settings, about

    var id: String { rawValue }

    /// `LocalizedStringKey`, not `String`: the sidebar's `Label(section.title, ...)` would
    /// otherwise render this verbatim in whatever language it was written in, never looked up in
    /// the string catalogue — the app's own chrome, sitting right in the most visible part of the
    /// window, would silently stay English regardless of the language chosen in Settings.
    var title: LocalizedStringKey {
        switch self {
        case .keys: "Keys"
        case .sites: "Sites"
        case .activity: "Activity"
        case .settings: "Settings"
        case .about: "About"
        }
    }

    var symbolName: String {
        switch self {
        case .keys: "key.fill"
        case .sites: "globe"
        case .activity: "clock.arrow.circlepath"
        case .settings: "gearshape"
        case .about: "info.circle"
        }
    }
}

/// The window a person opens from the menu bar and judges the app by: a sidebar over the five
/// sections the design spec lists for phase 3 (Keys, Sites, Activity, Settings, About — Tokens
/// is phase 2 and is not shown, see `MainWindowSection`).
struct MainWindow: View {
    /// The `Window` scene id this is registered under in `OpenImzoApp`, reused by
    /// `MenuBarContent` so the two never disagree about which window "Open OpenImzo" opens.
    static let id = "main"

    var coreEngine: CoreEngine

    @Environment(\.locale) private var locale
    @State private var selection: MainWindowSection? = .keys
    /// Keyboard focus for the sidebar, which is what makes the two `onKeyPress` handlers below
    /// receive the arrow keys at all — see `sidebarRow`'s own doc comment for why this screen no
    /// longer trusts `List`'s built-in focus and selection bridging to do that on its own.
    ///
    /// Set on appear, so the arrow keys work the instant the window opens rather than only
    /// after a first click. That used to draw a focus ring around the *whole* sidebar — the bug
    /// this screen was reported for, where the entire list looked highlighted and nothing said
    /// which section was actually showing. The ring was never the focus itself: it was the focus
    /// *effect*, which `.focusEffectDisabled()` below removes. With that in place, taking focus
    /// costs nothing visually, and the only thing that ever looks selected is the row this
    /// sidebar draws itself from `selection` (`sidebarRow`).
    @FocusState private var sidebarFocused: Bool

    var body: some View {
        NavigationSplitView {
            List(MainWindowSection.allCases, selection: $selection) { section in
                sidebarRow(section)
            }
            .focusable()
            .focused($sidebarFocused)
            // `List`'s own arrow-key row navigation does not reliably reach `selection` on this
            // SDK either (same finding as `sidebarRow`'s doc comment) — confirmed by giving the
            // sidebar real accessibility focus and sending both arrows through `System Events`
            // scoped to this app's own process and observing the window title never change.
            // Handling the two keys explicitly removes the dependency on that bridging entirely.
            .onKeyPress(.downArrow) { moveSelection(by: 1); return .handled }
            .onKeyPress(.upArrow) { moveSelection(by: -1); return .handled }
            // The whole reason the owner saw "the sidebar" highlighted rather than a row: a
            // focusable `List` draws the system focus ring around the entire list when it holds
            // keyboard focus, which on a five-row sidebar reads as the whole column lighting up.
            // The ring is redundant here anyway — `sidebarRow` draws the selected row itself, and
            // that is the state a person is actually looking for — so the effect is turned off
            // and the focusability (which the two handlers above need) is kept.
            .focusEffectDisabled()
            .navigationSplitViewColumnWidth(min: 150, ideal: 170, max: 220)
        } detail: {
            switch selection ?? .keys {
            case .keys: KeysView(coreEngine: coreEngine)
            case .sites: SitesView(coreEngine: coreEngine)
            case .activity: ActivityView(coreEngine: coreEngine)
            case .settings: SettingsView(coreEngine: coreEngine)
            case .about: AboutView()
            }
        }
        .frame(minWidth: 760, minHeight: 460)
        // Set here, once, on the split view — not left to each detail view's own
        // `.navigationTitle` — and resolved to a plain `String` rather than passed as a
        // `LocalizedStringKey`: running the app and reading the actual window title bar in each
        // language (task 6's own verification requirement) showed that macOS's title-bar bridging
        // resolves a `LocalizedStringKey` navigation title against the system's own language,
        // not this app's `\.locale` environment override, so it silently stayed English. A title
        // already resolved through `Locale.localizedAppString(_:)` sidesteps that: the window
        // receives the correct text outright, regardless of which lookup path sets it.
        .navigationTitle(resolvedTitle(for: selection ?? .keys))
        .onAppear { sidebarFocused = true }
        .onChange(of: coreEngine.pendingKeySelection) { _, newValue in
            // The menu bar's Keys submenu sets this just before opening this window, wanting a
            // specific key selected rather than just landing on the list — see
            // `MenuBarContent` and `KeysView`.
            guard newValue != nil else { return }
            selection = .keys
        }
    }

    /// One sidebar row, with its own accessibility label, selected state and activation action
    /// restated explicitly rather than left to `List`'s automatic bridging.
    ///
    /// This screen's sidebar was reported unreachable by accessibility in three separate testing
    /// passes (tasks 5, 6 and 8), each of which treated it as an automation limitation of their
    /// own rig. Driving a real build directly through the accessibility tree (`System Events`,
    /// scoped to this app's own process, no raw coordinates) for this task shows it is a genuine
    /// defect in this SDK's `List`/`NavigationSplitView` bridging, not a rig limitation: every
    /// row's `AXRow` reports `name: missing value` and `selected: false` regardless of which
    /// section is actually showing, and none of `select`, `AXPress` on the row, `AXPress` on the
    /// row's content, or a plain `click` on that content changes the selection or the window's
    /// own title — confirmed against a clean Debug build of exactly this file before this fix.
    /// `.accessibilityAction` below is a real SwiftUI action this app's own code runs; it does not
    /// depend on whatever `List` does or does not do with the row's default action internally.
    private func sidebarRow(_ section: MainWindowSection) -> some View {
        let isSelected = (selection ?? .keys) == section
        // The icon is a plain, non-interactive `Image`, and only the text is the `Button`:
        // driving a real build through the accessibility tree showed that whenever this SDK's
        // `List` row synthesizes an `AXButton` for content that pairs an SF Symbol image with
        // text — a `Label`, an `HStack`, or a real `Button` around either — it builds that
        // `AXButton` from the image specifically, with no title or description attribute at all,
        // discarding the text every time regardless of which of the three actually carried the
        // action. Removing the image from the actionable element entirely is what finally leaves
        // a `Button` whose title survives.
        // Keeping the `Button` text-only is what makes the accessibility tree work, but on its
        // own it also makes the text the only thing a pointer can hit — not the icon, not the
        // padding, not the rest of a sidebar column two hundred points wide. A row where the
        // label works and the space beside it does nothing is exactly the kind of "almost" this
        // app exists to replace, so the whole row takes the click as well.
        //
        // Deliberately a tap gesture on the container rather than a larger `Button`: a gesture
        // is not an accessibility element, so it adds a pointer target without putting anything
        // new in the tree — and putting the image back inside an actionable element is the very
        // thing that was discarding the button's title above. A tap that lands on the text still
        // goes to the `Button`, which is nearer, so the two never both fire.
        //
        // Because the row is hand-built, its selected state has to be hand-drawn too: `List`'s
        // own selection rendering is part of the same bridging that does not work here, so before
        // this fix `isSelected` was computed and then used for nothing but the accessibility
        // trait — the sidebar tracked the current section perfectly and never showed it. The
        // accent-filled capsule below is that missing half. It is drawn from `selection` alone,
        // not from focus, so the current section stays visible whether or not the sidebar holds
        // keyboard focus, which is what someone opening the window from the menu bar sees first.
        return HStack(spacing: 6) {
            Image(systemName: section.symbolName)
                .foregroundStyle(isSelected ? Color.white : Color.secondary)
                .accessibilityHidden(true)
            Button(section.title) { select(section) }
                .buttonStyle(.plain)
                .foregroundStyle(isSelected ? Color.white : Color.primary)
                .accessibilityAddTraits(isSelected ? .isSelected : [])
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            if isSelected {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color.accentColor)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { select(section) }
        // The row's own padding above is what gives the filled background its shape, so the
        // list's default row insets are pulled in to match rather than stacking on top of it.
        .listRowInsets(EdgeInsets(top: 1, leading: 6, bottom: 1, trailing: 6))
    }

    /// Selecting a section, from a click on the row or on its label. Takes keyboard focus at the
    /// same time, which is what keeps the arrow keys working now that nothing grabs focus when
    /// the window appears — see `sidebarFocused`.
    private func select(_ section: MainWindowSection) {
        selection = section
        sidebarFocused = true
    }

    /// Moves `selection` to the next or previous `MainWindowSection`, clamped rather than
    /// wrapping — the arrow key simply does nothing at either end, matching a plain macOS list.
    private func moveSelection(by offset: Int) {
        let all = MainWindowSection.allCases
        guard let current = all.firstIndex(of: selection ?? .keys) else { return }
        let next = current + offset
        guard all.indices.contains(next) else { return }
        selection = all[next]
    }

    /// Same catalogue entries as `MainWindowSection.title` — this only exists because the
    /// window's title bar needs a resolved `String` (see the doc comment above), while the
    /// sidebar's `Label` needs a `LocalizedStringKey` to react live the ordinary way; both read
    /// the same source strings, so both translate from the same catalogue keys.
    private func resolvedTitle(for section: MainWindowSection) -> String {
        switch section {
        case .keys: locale.localizedAppString("Keys")
        case .sites: locale.localizedAppString("Sites")
        case .activity: locale.localizedAppString("Activity")
        case .settings: locale.localizedAppString("Settings")
        case .about: locale.localizedAppString("About")
        }
    }
}
