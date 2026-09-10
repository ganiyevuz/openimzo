import AppKit
import Foundation
import SwiftUI

/// The four steps the design spec's §4.1 lists, in its own order, shown once — the very first
/// time this app is ever launched (`AppDelegate.applicationDidFinishLaunching`,
/// `UserSettings.hasCompletedFirstRun`):
///
/// 1. If the original is running, explain the port conflict and offer to quit it and remove its
///    login item.
/// 2. Offer TLS trust into the login keychain (`CoreEngine.installTlsTrust()` — always
///    `systemWide: false`, a security boundary this project does not relax here; see that
///    method's own doc comment).
/// 3. Offer launch at login (`SMAppService`, via `SettingsView`'s own `LaunchAtLoginRow`, reused
///    rather than duplicated).
/// 4. Import the original's own preferences, if any: language, the PFX search folder, and —
///    the step most likely to earn goodwill — every API key the person already verified with a
///    website, re-verified through the core's own signature check rather than trusted on the
///    file's word (`ApiKeyImporter`, `PreferencesImporter`).
///
/// Each step acts immediately when its own button is pressed — there is no final "Save": closing
/// the window early (the titlebar button, or `Finish`) loses nothing already done, which is also
/// why `presentIfNeeded` marks the flow as shown before the person has necessarily finished it.
enum FirstRunFlow {
    @MainActor
    static func presentIfNeeded(coreEngine: CoreEngine) {
        guard !UserSettings.hasCompletedFirstRun else { return }
        UserSettings.hasCompletedFirstRun = true
        FirstRunWindowController.show(coreEngine: coreEngine)
    }
}

/// Hosts `FirstRunFlowView` in a plain, titled `NSWindow` — not a `Scene` in `OpenImzoApp`,
/// for the same reason the five request panels aren't (`RequestPanel.swift`'s own doc comment):
/// this app has no Dock icon, and a `Scene`'s `openWindow` has already shown itself unreliable
/// for raising an accessory app's own window (`MenuBarContent.openMainWindow`'s doc comment).
///
/// Sized once, synchronously, from the content's own `fittingSize` before the hosting view is
/// ever assigned as the window's content — the exact `RequestPanelController` technique, and for
/// the same reason: a reactive `NSHostingController.sizingOptions` resize after the window is
/// already showing is what crashed this app during an earlier task's own manual verification
/// (`RequestPanelController`'s doc comment). Unlike a request panel, this wizard's *content*
/// genuinely changes shape across its four steps, so the fixed frame is imposed on the SwiftUI
/// side instead (`FirstRunFlowView`'s own `.frame(width:height:)`, with a `ScrollView` inside it
/// for whichever step's content runs long) — `fittingSize` then always measures that same fixed
/// frame, regardless of which step is showing, so it is computed once, correctly, for the whole
/// flow's lifetime.
@MainActor
private final class FirstRunWindowController: NSObject, NSWindowDelegate {
    /// At most one at a time; a second `presentIfNeeded` call in the same run (there is none
    /// today, but nothing enforces that) raises the existing window rather than opening another.
    private static var current: FirstRunWindowController?

    private var window: NSWindow?

    static func show(coreEngine: CoreEngine) {
        if let current {
            NSApp.activate(ignoringOtherApps: true)
            current.window?.makeKeyAndOrderFront(nil)
            return
        }
        let controller = FirstRunWindowController()
        controller.open(coreEngine: coreEngine)
        current = controller
    }

    private func open(coreEngine: CoreEngine) {
        // Same reasoning as every other separately-hosted surface in this app
        // (`MacUiDelegate.locale`, `OpenImzoApp`'s own root-view environment): a window built
        // directly, outside the `Scene` graph, does not inherit `\.locale` from anywhere and must
        // be given it explicitly.
        let locale = coreEngine.appLanguage.locale
        let content = FirstRunFlowView(coreEngine: coreEngine, onFinished: { [weak self] in self?.window?.close() })
            .environment(\.locale, locale)

        let hostingView = NSHostingView(rootView: content)
        let size = hostingView.fittingSize
        hostingView.frame = NSRect(origin: .zero, size: size)

        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = locale.localizedAppString("Welcome to %@", AppIdentity.productName)
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.center()
        window.delegate = self
        self.window = window

        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    func windowWillClose(_ notification: Notification) {
        Self.current = nil
    }
}

private enum FirstRunStep: Int, CaseIterable {
    case originCheck, tlsTrust, launchAtLogin, importPreferences
}

/// The wizard's shell: a fixed-size frame with a step indicator, a scrollable content area for
/// whichever step is current, and Back/Next/Finish navigation. Every step commits its own change
/// immediately when its own control is used — this shell only moves between them.
struct FirstRunFlowView: View {
    var coreEngine: CoreEngine
    var onFinished: () -> Void

    @State private var step: FirstRunStep = .originCheck

    var body: some View {
        VStack(spacing: 0) {
            stepDots
                .padding(.top, 20)
                .padding(.bottom, 12)

            ScrollView {
                stepContent
                    .padding(.horizontal, 24)
                    .padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Divider()

            HStack {
                if step != .originCheck {
                    Button("Back") { step = previous(step) }
                }
                Spacer()
                if step == .importPreferences {
                    Button("Finish", action: onFinished)
                        .keyboardShortcut(.defaultAction)
                } else {
                    Button("Next") { step = next(step) }
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding(16)
        }
        .frame(width: 520, height: 560)
        // Harmless if the engine's own construction `Task` already delivered a status by the time
        // this appears — `CoreEngine.refreshStatus()` is a plain re-read, not a toggle — and
        // necessary if this window opens before that first read lands, which is the ordinary case
        // right after launch.
        .task { await coreEngine.refreshStatus() }
    }

    @ViewBuilder private var stepContent: some View {
        switch step {
        case .originCheck: OriginCheckStepView()
        case .tlsTrust: TlsTrustStepView(coreEngine: coreEngine)
        case .launchAtLogin: LaunchAtLoginStepView(coreEngine: coreEngine)
        case .importPreferences: ImportStepView(coreEngine: coreEngine)
        }
    }

    /// Purely visual — four dots, no text — so the step count needs no translated "Step %@ of
    /// %@" string at all.
    private var stepDots: some View {
        HStack(spacing: 8) {
            ForEach(FirstRunStep.allCases, id: \.self) { candidate in
                Circle()
                    .fill(candidate == step ? Color.accentColor : Color.secondary.opacity(0.3))
                    .frame(width: 7, height: 7)
            }
        }
    }

    private func previous(_ step: FirstRunStep) -> FirstRunStep {
        FirstRunStep(rawValue: step.rawValue - 1) ?? .originCheck
    }

    private func next(_ step: FirstRunStep) -> FirstRunStep {
        FirstRunStep(rawValue: step.rawValue + 1) ?? .importPreferences
    }
}

// MARK: - Step 1: the original

/// If the original is running, offers to quit it and remove its own classic "Login Item" —
/// added by its own `autostart` script (`tell application "System Events" to make new login
/// item`, not a `LaunchAgent`) — reusing `MacPlatform`'s own detection rather than a second one,
/// per the controller addendum. Specifically `isLegacyClientProcessRunning()`, not the combined
/// `isLegacyClientRunning()`: running the built app for this task's own verification showed
/// that method's port-probe half reports a false "yes" once this app's *own* engine has already
/// bound the very same production ports, which by the time a person reaches this step has
/// usually already happened — see that method's own doc comment for the full reasoning.
private struct OriginCheckStepView: View {
    @State private var isRunning = MacPlatform().isLegacyClientProcessRunning()
    @State private var isWorking = false
    @State private var didAct = false
    @State private var quitOK = false
    @State private var removedOK = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("The Original E-IMZO", systemImage: "exclamationmark.triangle")
                .font(.headline)

            if isRunning {
                // Real string interpolation, not a literal "%@": only an actual `\(...)`
                // argument gives `LocalizedStringKey` something to substitute into the resolved
                // template — a literal "%@" would show up on screen unreplaced.
                Text(
                    "\(AppIdentity.productName) and the original use the same two ports, so only one can run at a time. Quit the original and remove it from your login items to avoid the conflict."
                )
                .font(.callout)

                if didAct {
                    Label("Quit the original app", systemImage: quitOK ? "checkmark.circle.fill" : "xmark.circle")
                        .foregroundStyle(quitOK ? .green : .secondary)
                    Label(
                        "Remove it from your login items",
                        systemImage: removedOK ? "checkmark.circle.fill" : "xmark.circle"
                    )
                    .foregroundStyle(removedOK ? .green : .secondary)
                    if !quitOK || !removedOK {
                        Text("You can also do this yourself in System Settings, under General > Login Items.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Button {
                        Task { await act() }
                    } label: {
                        if isWorking {
                            ProgressView().controlSize(.small)
                        } else {
                            Text("Quit the Original and Remove It From Login Items")
                        }
                    }
                    .disabled(isWorking)
                }
            } else {
                Text("The original E-IMZO isn't running right now — nothing to do here.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func act() async {
        isWorking = true
        let workspace = NSWorkspace.shared
        let originalRunning = { workspace.runningApplications.contains { $0.bundleIdentifier == MacPlatform.legacyBundleIdentifier } }
        let apps = workspace.runningApplications.filter { $0.bundleIdentifier == MacPlatform.legacyBundleIdentifier }
        for app in apps { _ = app.terminate() }
        // `NSRunningApplication.terminate()` only requests termination; give it a moment to
        // actually happen before reporting failure; ten tries at 300ms is a low, arbitrary bound
        // — not a promise the original always quits this fast, only that this step doesn't hang
        // waiting on a process that refuses to.
        if !apps.isEmpty {
            for _ in 0..<10 {
                try? await Task.sleep(for: .milliseconds(300))
                if !originalRunning() { break }
            }
        }
        quitOK = !originalRunning()
        removedOK = await LoginItemRemover.removeOriginalLoginItem()
        isWorking = false
        didAct = true
        isRunning = MacPlatform().isLegacyClientProcessRunning()
    }
}

/// Removes the original's own classic "Login Item" — confirmed against a real install: it is
/// registered as `tell application "System Events" to make new login item at end with
/// properties {path:"/Applications/E-IMZO.app", …}`, not as a `LaunchAgent`. Undoing that means asking System Events for whichever login item's path
/// matches the original's actual installed location — found via `NSWorkspace`, never assumed to
/// be `/Applications/E-IMZO.app` for every install — and deleting that one entry.
///
/// `false` covers every way this can fail to happen — the original isn't installed at all, no
/// login item matches, the person has never granted (or has denied) this app's own Automation
/// permission for System Events, or System Events simply doesn't answer — uniformly, and always
/// without throwing: per the controller addendum, this is reported as "could not find it" and
/// the rest of first run keeps working, never a failure of the flow itself. The very first call a
/// person ever makes into this raises the OS's own Automation permission prompt — another
/// OS-owned window this app cannot and must not script past, the same category as `Engine
/// .installTlsTrust`'s keychain prompt.
private enum LoginItemRemover {
    static func removeOriginalLoginItem() async -> Bool {
        guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: MacPlatform.legacyBundleIdentifier) else {
            return false
        }
        let escapedPath = appURL.path
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = """
        tell application "System Events"
            set matchingItems to every login item whose path is "\(escapedPath)"
            repeat with oneItem in matchingItems
                delete oneItem
            end repeat
            return (count of matchingItems) as string
        end tell
        """
        let output = await run(script)
        return (Int(output.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0) > 0
    }

    /// `NSAppleScript` runs synchronously and can block for as long as System Events takes to
    /// answer (including the time a person spends looking at the Automation permission prompt),
    /// so it runs off the main actor rather than freezing this window's UI while that happens.
    private static func run(_ source: String) async -> String {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                var error: NSDictionary?
                let result = NSAppleScript(source: source)?.executeAndReturnError(&error)
                continuation.resume(returning: result?.stringValue ?? "")
            }
        }
    }
}

// MARK: - Step 2: TLS trust

/// Reuses `SettingsView`'s own "TLS Trust" vocabulary word for word — the same screen a person
/// would otherwise find this in later, so first run and Settings never describe the same toggle
/// two different ways. `CoreEngine.installTlsTrust()` always installs into the login keychain
/// only; see that method's own doc comment for why the System keychain is out of scope here, not
/// merely unfinished.
private struct TlsTrustStepView: View {
    var coreEngine: CoreEngine

    @State private var isInstalling = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("TLS Trust", systemImage: "lock.shield")
                .font(.headline)

            Text(
                "Websites talk to \(AppIdentity.productName) over a local, encrypted connection. Trusting its certificate in your login keychain stops your browser from warning about it."
            )
            .font(.callout)

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
                    Button {
                        Task {
                            isInstalling = true
                            _ = await coreEngine.installTlsTrust()
                            isInstalling = false
                        }
                    } label: {
                        Text(isInstalling ? "Installing…" : "Install Trust")
                    }
                    .disabled(isInstalling || status.tlsTrusted)
                }
            } else {
                ProgressView()
            }
        }
    }
}

// MARK: - Step 3: launch at login

/// `LaunchAtLoginRow` is `SettingsView`'s own row, reused rather than duplicated — same
/// `SMAppService` register/unregister handling, same error surfacing, in both places.
private struct LaunchAtLoginStepView: View {
    var coreEngine: CoreEngine

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Startup", systemImage: "arrow.clockwise.circle")
                .font(.headline)

            Text("Start \(AppIdentity.productName) automatically when you log in, the way the original did.")
                .font(.callout)

            if let settings = coreEngine.settings {
                LaunchAtLoginRow(coreEngine: coreEngine, settings: settings)
            } else {
                ProgressView()
            }
        }
    }
}

// MARK: - Step 4: import

private enum ImportRowStatus {
    case pending, verifying, verified, notVerified, couldNotCheck
}

private struct ImportRow: Identifiable {
    let id: String
    var status: ImportRowStatus
}

private enum ImportScanState {
    case scanning
    case nothingFound
    case found(ImportedPreferences)
}

/// The step most likely to earn goodwill, per the brief: a person who already trusted a dozen
/// government sites in the original should not have to approve them again. Scanning is a plain
/// read (`PreferencesImporter`, on appear, always safe); importing is an explicit action — the
/// same "explain, then let a button do it" shape as steps 2 and 3 — because it makes real calls
/// into the running engine and changes settings, not because there is anything to hide about it.
///
/// Every verified pair is re-verified through the core's own real signature check
/// (`ApiKeyImporter`, one `apikey` RPC call per pair over this engine's own plain WebSocket
/// listener) rather than copied on the preferences file's word — a preferences file is not a
/// trusted source, and the core already has the exact verifier that would refuse an invalid one.
private struct ImportStepView: View {
    var coreEngine: CoreEngine

    @State private var scanState: ImportScanState = .scanning
    @State private var rows: [ImportRow] = []
    @State private var isImporting = false
    @State private var hasImported = false
    @State private var listenerUnavailable = false
    @State private var verifiedCount = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Import From the Original", systemImage: "tray.and.arrow.down")
                .font(.headline)

            switch scanState {
            case .scanning:
                ProgressView()
            case .nothingFound:
                // A calm, success-shaped state, not an error one — this is the ordinary outcome
                // for most people running this for the first time, per the controller addendum,
                // and must never look like something went wrong.
                Label("Nothing to Import", systemImage: "checkmark.circle")
                    .font(.subheadline)
                Text("No previous E-IMZO settings were found on this Mac — you're starting fresh.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .found(let imported):
                foundView(imported)
            }
        }
        .task {
            // Off the main actor: `PreferencesImporter.find()` does real file I/O against a path
            // this app does not control the other end of — see its own doc comment for why a
            // plain, ordinary stalled network home directory is reason enough on its own, quite
            // apart from a hostile symlink.
            let found = await Task.detached(priority: .userInitiated) {
                PreferencesImporter.find()
            }.value
            scanState = found.map(ImportScanState.found) ?? .nothingFound
        }
    }

    @ViewBuilder
    private func foundView(_ imported: ImportedPreferences) -> some View {
        Text("Found settings from the original E-IMZO:")
            .font(.callout)

        VStack(alignment: .leading, spacing: 4) {
            if let lang = imported.lang, let language = AppLanguage(rawValue: lang) {
                Text("Interface language: \(language.displayName)")
            }
            if let folder = imported.pfxSearchFolder, folder != "/Volumes" {
                Text("Key search folder: \(folder)")
            }
            if !imported.apiKeys.isEmpty {
                Text("\(String(imported.apiKeys.count)) verified sites")
            }
        }
        .font(.callout)
        .foregroundStyle(.secondary)

        if !hasImported {
            Button {
                Task { await performImport(imported) }
            } label: {
                Text(isImporting ? "Importing…" : "Import")
            }
            .disabled(isImporting)
        }

        if listenerUnavailable {
            Text(
                "\(AppIdentity.productName)'s own listener isn't running yet, most likely because the original is still running. Finish the previous step, then try again."
            )
            .font(.caption)
            .foregroundStyle(.orange)
        }

        if !rows.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(rows) { row in
                    HStack {
                        Text(verbatim: row.id)
                        Spacer()
                        rowStatusView(row.status)
                    }
                    .font(.caption)
                }
            }
        }

        if hasImported, !imported.apiKeys.isEmpty {
            Text("Imported \(String(verifiedCount)) of \(String(imported.apiKeys.count)) sites.")
                .font(.callout)
        }
    }

    @ViewBuilder
    private func rowStatusView(_ status: ImportRowStatus) -> some View {
        switch status {
        case .pending:
            EmptyView()
        case .verifying:
            ProgressView().controlSize(.small)
        case .verified:
            Label("Verified", systemImage: "checkmark.circle.fill")
                .labelStyle(.iconOnly)
                .foregroundStyle(.green)
        case .notVerified:
            Label("Not Verified", systemImage: "xmark.circle")
                .labelStyle(.iconOnly)
                .foregroundStyle(.secondary)
        case .couldNotCheck:
            Label("Could Not Check", systemImage: "questionmark.circle")
                .labelStyle(.iconOnly)
                .foregroundStyle(.secondary)
        }
    }

    /// Applies the language and folder immediately — neither needs the engine's own WebSocket
    /// listener — then, if there are any API keys, re-verifies each one in turn. One connection
    /// per pair, never the bulk `apikey domain,key,domain,key,…` form: the core's own handler
    /// (`main_::apikey` in `eimzo-rpc`) aborts the whole call at the first pair that fails to
    /// verify, which would silently skip every entry listed after a single bad one — exactly the
    /// failure this import must not have.
    ///
    /// `hasImported` — which hides the Import button — is set only on a path that actually ran an
    /// import (language/folder alone, or a completed verification pass), never on the
    /// listener-unavailable bail-out below: nothing was imported in that case, so the button stays
    /// available to retry right here once the listener comes up, rather than only coming back
    /// after a Back/Next round trip remounts this view from scratch.
    private func performImport(_ imported: ImportedPreferences) async {
        isImporting = true
        defer { isImporting = false }

        if let lang = imported.lang, let language = AppLanguage(rawValue: lang) {
            await coreEngine.setAppLanguage(language)
        }
        if let folder = imported.pfxSearchFolder, folder != "/Volumes", !UserSettings.extraKeyFolders.contains(folder) {
            UserSettings.extraKeyFolders.append(folder)
            await coreEngine.rescanKeys()
        }

        guard !imported.apiKeys.isEmpty else {
            hasImported = true
            return
        }
        rows = imported.apiKeys.map { ImportRow(id: $0.domain, status: .pending) }

        await coreEngine.refreshStatus()
        guard let status = coreEngine.status, status.ws else {
            listenerUnavailable = true
            rows = []
            return
        }
        listenerUnavailable = false
        hasImported = true
        verifiedCount = 0
        for index in imported.apiKeys.indices {
            rows[index].status = .verifying
            let pair = imported.apiKeys[index]
            let outcome = await ApiKeyImporter.verify(domain: pair.domain, key: pair.key, wsPort: status.wsPort)
            switch outcome {
            case .verified:
                rows[index].status = .verified
                verifiedCount += 1
            case .rejected:
                rows[index].status = .notVerified
            case .networkFailure:
                rows[index].status = .couldNotCheck
            }
        }
    }
}

/// What `PreferencesImporter` found in a throwaway copy of the original's preferences — nothing
/// has been verified or applied yet.
struct ImportedPreferences: Sendable {
    /// `/uz/yt/eimzo/websocket/server`'s `lang` leaf — `"ru"` or `"uz"`, exactly as stored.
    var lang: String?
    /// `/uz/yt/eimzo/websocket/server/menu/ext`'s `pfx.search.folder` leaf.
    var pfxSearchFolder: String?
    /// Every `(domain, apikey)` pair under `/uz/yt/eimzo/websocket/server/endpoint`, sorted by
    /// domain only for a stable display order — nothing about verification depends on the order.
    var apiKeys: [(domain: String, key: String)]

    var isEmpty: Bool { lang == nil && pfxSearchFolder == nil && apiKeys.isEmpty }
}

/// Reads the original's own preferences — never trusting anything in them beyond what
/// `ImportStepView` re-verifies through the core — from whichever of the two files a Java
/// preferences implementation on macOS is known to write them to (the controller addendum):
/// `~/Library/Preferences/uz.yt.eimzo.plist`, the original's own dedicated file, or — on other
/// JDKs — the shared `~/Library/Preferences/com.the original.util.prefs.plist` every Java
/// process's "user root" preferences can land in. `nil` covers the ordinary case: neither file
/// exists, or neither has anything under `/uz/yt/eimzo` — most people running this for the first
/// time never installed the original at all.
///
/// **Never reads the live file's path directly.** Each candidate is first copied to a throwaway
/// location under the system temporary directory and only the copy is ever opened — parsed, then
/// deleted again — so nothing this app does can be mistaken by `java.util.prefs` (or anything
/// else) for a write to the live file. The original's own preferences are read-only from this
/// app's point of view: someone may still want to run the original while they try this one.
///
/// **Never called from the main actor.** `find()` is a plain synchronous function — its caller
/// (`ImportStepView`) runs it inside `Task.detached`, off the main actor, before ever touching
/// `@State`. This is not only about a hostile symlink (`isRegularFile` below closes that case on
/// its own, by refusing to open anything the live path resolves to that isn't a plain file); an
/// entirely ordinary stalled or slow network home directory — not unusual in exactly the
/// institutional settings this app targets — would otherwise hang the very first screen anyone
/// ever sees, with no attacker involved at all.
enum PreferencesImporter {
    private static let candidateRelativePaths = [
        "Library/Preferences/uz.yt.eimzo.plist",
        "Library/Preferences/com.the original.util.prefs.plist",
    ]

    static func find() -> ImportedPreferences? {
        let home = FileManager.default.homeDirectoryForCurrentUser
        for relativePath in candidateRelativePaths {
            let liveURL = home.appendingPathComponent(relativePath)
            guard isRegularFile(liveURL) else { continue }
            guard let copyURL = copyToThrowawayLocation(liveURL) else { continue }
            defer { try? FileManager.default.removeItem(at: copyURL) }
            guard let top = readPlistDictionary(copyURL), let root = eimzoRoot(in: top) else { continue }
            let imported = extract(from: root)
            if !imported.isEmpty { return imported }
        }
        return nil
    }

    /// True only for a plain regular file at `url` — never a symlink (which could point
    /// anywhere, including a device file like `/dev/zero` that never reaches end-of-file) and
    /// never any other special file type. Checked with `attributesOfItem`, which — unlike
    /// `fileExists`, which follows a symlink to whatever it points at — reports on the item
    /// found at `url` itself.
    private static func isRegularFile(_ url: URL) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path) else { return false }
        return (attributes[.type] as? FileAttributeType) == .typeRegular
    }

    private static func copyToThrowawayLocation(_ liveURL: URL) -> URL? {
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("openimzo-import-\(UUID().uuidString).plist")
        do {
            try FileManager.default.copyItem(at: liveURL, to: destination)
            return destination
        } catch {
            return nil
        }
    }

    private static func readPlistDictionary(_ url: URL) -> [String: Any]? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        return object as? [String: Any]
    }

    /// Descends `path`, one node segment at a time (each stored as `"<segment>/"`, `java.util
    /// .prefs`'s own on-disk convention — see the controller addendum for the real, observed
    /// shape of both candidate files), returning the dictionary of leaf key/value pairs and
    /// further child nodes found there, or `nil` the moment a segment along the way is missing.
    private static func descend(_ node: [String: Any], _ path: [String]) -> [String: Any]? {
        guard let first = path.first else { return node }
        guard let next = node["\(first)/"] as? [String: Any] else { return nil }
        return descend(next, Array(path.dropFirst()))
    }

    /// The `/uz/yt/eimzo` node, whichever of the two file shapes `top` is: the dedicated file
    /// stores it under one key holding the whole absolute path; the shared file decomposes the
    /// same path one segment at a time from its own `"/"` root (that file's own top-level
    /// `java.util.prefs` "user root", shared by every Java process that lands in it).
    private static func eimzoRoot(in top: [String: Any]) -> [String: Any]? {
        if let dedicated = top["/uz/yt/eimzo/"] as? [String: Any] {
            return dedicated
        }
        guard let sharedRoot = top["/"] as? [String: Any] else { return nil }
        return descend(sharedRoot, ["uz", "yt", "eimzo"])
    }

    private static func extract(from eimzoRoot: [String: Any]) -> ImportedPreferences {
        guard let server = descend(eimzoRoot, ["websocket", "server"]) else {
            return ImportedPreferences(lang: nil, pfxSearchFolder: nil, apiKeys: [])
        }
        let lang = server["lang"] as? String
        let folder = descend(server, ["menu", "ext"])?["pfx.search.folder"] as? String
        let apiKeys = (descend(server, ["endpoint"]) ?? [:])
            .compactMap { domain, value in (value as? String).map { (domain: domain, key: $0) } }
            .sorted { $0.domain < $1.domain }
        return ImportedPreferences(lang: lang, pfxSearchFolder: folder, apiKeys: apiKeys)
    }
}

/// Re-verifies one `(domain, apikey)` pair the exact way a real website would: a single `apikey`
/// RPC call over this engine's own plain WebSocket listener (`EngineStatus.wsPort`) — the one
/// place the core's real signature check (`eimzo_crypto::apikey::verify_domain`, reached through
/// `ApikeyService::register`) actually runs. A verified pair is cached and persisted by the core
/// itself as a side effect of this same call (`sites.json`), exactly as it would be for a real
/// site's own `apikey` call, so there is nothing further this app needs to persist on success.
///
/// The plain listener, not the TLS one: verifying an api key needs no encryption of its own (the
/// core generates the TLS certificate itself, and trusting it is step 2's own separate concern,
/// possibly not even done yet by the time this step runs), and connecting plain sidesteps every
/// certificate-trust question entirely.
enum ApiKeyImporter {
    enum Outcome { case verified, rejected, networkFailure }

    static func verify(domain: String, key: String, wsPort: UInt16) async -> Outcome {
        guard let url = URL(string: "ws://127.0.0.1:\(wsPort)/service/cryptapi") else { return .networkFailure }
        var request = URLRequest(url: url)
        request.setValue("https://\(domain)", forHTTPHeaderField: "Origin")
        let task = URLSession.shared.webSocketTask(with: request)
        task.resume()
        defer { task.cancel(with: .normalClosure, reason: nil) }

        let payload: [String: Any] = ["plugin": "", "name": "apikey", "arguments": [domain, key]]
        guard let body = try? JSONSerialization.data(withJSONObject: payload),
              let text = String(data: body, encoding: .utf8) else {
            return .networkFailure
        }

        do {
            try await task.send(.string(text))
            let message = try await withTimeout(seconds: 5) { try await task.receive() }
            guard case .string(let reply) = message,
                  let data = reply.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let success = object["success"] as? Bool
            else {
                return .networkFailure
            }
            return success ? .verified : .rejected
        } catch {
            return .networkFailure
        }
    }
}

/// `operation()`'s result, or a thrown `CancellationError` if `seconds` elapses first. Guards
/// `ApiKeyImporter.verify`'s own `receive()` against ever hanging this step indefinitely — every
/// real call the local dispatcher answers is fast (`apikey` is pure in-process signature
/// verification, no network lookup of its own), so this bound only ever matters when something
/// is actually wrong.
private func withTimeout<T: Sendable>(seconds: Double, operation: @escaping () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(for: .seconds(seconds))
            throw CancellationError()
        }
        // `next()` only returns `nil` once every task has already been consumed, which cannot
        // yet be true for the first call on a group that was just given two — but the project
        // rule is no force-unwrap reachable at runtime regardless of provable safety, so this is
        // a plain `guard` rather than `!`.
        guard let result = try await group.next() else {
            throw CancellationError()
        }
        group.cancelAll()
        return result
    }
}
