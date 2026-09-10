import AppKit
import SwiftUI

/// A pragmatic reader for the BouncyCastle-style DN string `KeyEntry.subjectName` carries —
/// `CN=Test User,O=Org,C=UZ,1.2.860.3.16.1.2=123,SERIALNUMBER=X`, per `crates/eimzo-pki/src/dn.rs`
/// — good enough for the handful of attributes this view shows. Not a general X.500 parser, and
/// never used for anything security-relevant: `KeyEntry.subjectName` itself is display-only,
/// same as everywhere else this app shows it.
///
/// `KeyEntry` carries no separate "national identifier" or "organisation" field (only the raw
/// subject DN) — the design spec's own bullet lists those as things the Keys view should show,
/// so this is what turns the one string the core actually gives into them. The Uzbek PKI OID arc
/// `1.2.860.3.16.1.x` has no symbolic name in `crates/eimzo-pki/src/dn.rs`'s own `SYMBOLS` table
/// (it stays numeric, matching the original BouncyCastle-based client's own output) —
/// `1.2.860.3.16.1.1` is INN (legal entities), `1.2.860.3.16.1.2` is PINFL (individuals), the
/// standard pair of national identifiers used across Uzbek digital-signature certificates.
private struct KeySubjectInfo {
    let commonName: String?
    let organisation: String?
    let nationalIdentifier: (label: String, value: String)?
    /// `false` for a PFX whose password hasn't been given yet — `Discovery` can't read a PFX's
    /// certificate without it, so every field above is empty for those (see `KeyEntry.disk`'s
    /// sibling doc comment in `crates/eimzo-ffi/src/engine.rs`) — unless `unlocked` supplies the
    /// summary `CoreEngine.unlockKey(_:password:)` already fetched for this row this session.
    let hasCertificateDetails: Bool

    init(_ key: KeyEntry, unlocked: CertificateSummary? = nil) {
        let subjectName = unlocked?.subjectName ?? key.subjectName
        hasCertificateDetails = !subjectName.isEmpty
        let attributes = Self.parseDN(subjectName)
        commonName = attributes["CN"]
        organisation = attributes["O"]
        if let pinfl = attributes["1.2.860.3.16.1.2"] {
            nationalIdentifier = ("PINFL", pinfl)
        } else if let inn = attributes["1.2.860.3.16.1.1"] {
            nationalIdentifier = ("INN", inn)
        } else {
            nationalIdentifier = nil
        }
    }

    private static func parseDN(_ dn: String) -> [String: String] {
        var result: [String: String] = [:]
        for component in dn.split(separator: ",") {
            guard let equals = component.firstIndex(of: "=") else { continue }
            let key = component[component.startIndex..<equals].trimmingCharacters(in: .whitespaces)
            let value = component[component.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { continue }
            result[key] = value
        }
        return result
    }
}

private struct ValidityBadge: View {
    let hasDetails: Bool
    let expired: Bool

    var body: some View {
        if !hasDetails {
            Label("Unknown", systemImage: "questionmark.circle")
                .foregroundStyle(.secondary)
        } else if expired {
            Label("Expired", systemImage: "xmark.seal.fill")
                .foregroundStyle(.red)
        } else {
            Label("Valid", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
        }
    }
}

private struct KeyRow: View {
    let key: KeyEntry
    var coreEngine: CoreEngine
    @Binding var activeSheet: KeysView.ActiveSheet?

    private var unlocked: CertificateSummary? { coreEngine.unlockedSummary(for: key) }
    private var subject: KeySubjectInfo { KeySubjectInfo(key, unlocked: unlocked) }
    private var isExpired: Bool { unlocked?.expired ?? key.expired }
    private var isPfx: Bool { key.fullPath.lowercased().hasSuffix(".pfx") }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "key.fill")
                .foregroundStyle(.secondary)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 3) {
                Text(subject.commonName ?? key.name)
                    .font(.headline)
                if subject.hasCertificateDetails {
                    if let organisation = subject.organisation {
                        Text(organisation)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    if let nationalIdentifier = subject.nationalIdentifier {
                        Text("\(nationalIdentifier.label): \(nationalIdentifier.value)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("Certificate details need the password to read")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    // Per key, per session, and only on request — never scanned automatically —
                    // matching the constraint `Engine.unlock_key` itself is built to (see its own
                    // doc comment in `crates/eimzo-ffi/src/engine.rs`).
                    Button("Unlock…") { activeSheet = .unlock(key) }
                        .font(.caption)
                        .buttonStyle(.link)
                }
            }
            .textSelection(.enabled)

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 4) {
                ValidityBadge(hasDetails: subject.hasCertificateDetails, expired: isExpired)
                    .font(.caption)
                Text(key.disk)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Menu {
                Button("Change Password…") { activeSheet = .changePassword(key) }
                Button(isPfx ? "Convert to YKS…" : "Convert to PFX…") { activeSheet = .convert(key) }
                if isPfx {
                    Button("Export QR-key…") { activeSheet = .exportQrKey(key) }
                }
                Divider()
                Button("Reveal in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: key.fullPath)])
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
        .padding(.vertical, 4)
    }
}

/// Asks for one password and runs `perform` with it — shared by Convert and Export QR-key, which
/// (unlike Change Password) both only ever need the file's existing password.
///
/// `title` and `confirmTitle` are `LocalizedStringKey`, not `String`: a plain `String` field fed
/// into `Text`/`Button` renders verbatim, in whatever language the literal at the call site
/// happened to be written in, never looked up in the string catalogue — `subject` stays `String`
/// deliberately, since it is `key.name`, the core's own data, not chrome text.
private struct PasswordPromptSheet: View {
    let title: LocalizedStringKey
    let subject: String
    let confirmTitle: LocalizedStringKey
    let perform: (String) async throws -> Void
    let onDone: () -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.locale) private var locale
    @State private var password = ""
    @State private var isWorking = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title).font(.headline)
            Text(subject)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)

            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)
                .privacySensitive()

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(confirmTitle, action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty || isWorking)
            }
        }
        .padding(20)
        .frame(width: 360)
        .disabled(isWorking)
    }

    private func submit() {
        errorMessage = nil
        isWorking = true
        Task {
            do {
                try await perform(password)
                isWorking = false
                dismiss()
                onDone()
            } catch let error as EngineError {
                isWorking = false
                errorMessage = error.userMessage(locale: locale)
            } catch {
                isWorking = false
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct ChangePasswordSheet: View {
    let key: KeyEntry
    var coreEngine: CoreEngine

    @Environment(\.dismiss) private var dismiss
    @Environment(\.locale) private var locale
    @State private var oldPassword = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var isWorking = false
    @State private var errorMessage: String?

    private var canSubmit: Bool {
        !oldPassword.isEmpty && !newPassword.isEmpty && newPassword == confirmPassword
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Change Password").font(.headline)
            Text(key.name)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)

            SecureField("Current password", text: $oldPassword)
                .textFieldStyle(.roundedBorder)
                .privacySensitive()
            SecureField("New password", text: $newPassword)
                .textFieldStyle(.roundedBorder)
                .privacySensitive()
            SecureField("Confirm new password", text: $confirmPassword)
                .textFieldStyle(.roundedBorder)
                .privacySensitive()

            if !confirmPassword.isEmpty, newPassword != confirmPassword {
                Label("Passwords do not match", systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
            } else if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Change", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSubmit || isWorking)
            }
        }
        .padding(20)
        .frame(width: 360)
        .disabled(isWorking)
    }

    private func submit() {
        errorMessage = nil
        isWorking = true
        Task {
            do {
                try await coreEngine.changePassword(path: key.fullPath, old: oldPassword, new: newPassword)
                isWorking = false
                dismiss()
            } catch let error as EngineError {
                isWorking = false
                errorMessage = error.userMessage(locale: locale)
            } catch {
                isWorking = false
                errorMessage = error.localizedDescription
            }
        }
    }
}

/// The list of folders `MacPlatform.volumesRoots()` searches, beyond the fixed `/Volumes`: add
/// or remove one and this both writes `UserSettings.extraKeyFolders` and rescans, so the list on
/// screen and what the core just searched never disagree.
private struct FoldersPopover: View {
    @Binding var extraFolders: [String]
    let onChange: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Key Search Folders").font(.headline)

            Label("/Volumes", systemImage: "externaldrive")
                .font(.callout)
                .foregroundStyle(.secondary)

            if extraFolders.isEmpty {
                Text("No extra folders added.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(extraFolders, id: \.self) { folder in
                    HStack {
                        Text(folder)
                            .font(.callout)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer(minLength: 8)
                        Button {
                            remove(folder)
                        } label: {
                            Image(systemName: "minus.circle")
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }

            Divider()

            Button("Add Folder…", action: addFolder)
        }
        .padding(12)
        .frame(width: 320)
    }

    private func addFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.begin { response in
            guard response == .OK else { return }
            var updated = extraFolders
            for url in panel.urls where !updated.contains(url.path) {
                updated.append(url.path)
            }
            extraFolders = updated
            UserSettings.extraKeyFolders = updated
            onChange()
        }
    }

    private func remove(_ folder: String) {
        extraFolders.removeAll { $0 == folder }
        UserSettings.extraKeyFolders = extraFolders
        onChange()
    }
}

/// Key file, subject, national identifier, organisation, validity, and disk — the design spec's
/// own list for this screen — plus change password, convert, export QR-key, reveal in Finder,
/// add or remove a search folder, and rescan.
struct KeysView: View {
    enum ActiveSheet: Identifiable {
        case changePassword(KeyEntry)
        case convert(KeyEntry)
        case exportQrKey(KeyEntry)
        case unlock(KeyEntry)

        var id: String {
            switch self {
            case let .changePassword(key): "change-\(key.fullPath)"
            case let .convert(key): "convert-\(key.fullPath)"
            case let .exportQrKey(key): "export-\(key.fullPath)"
            case let .unlock(key): "unlock-\(key.fullPath)-\(key.alias)"
            }
        }
    }

    var coreEngine: CoreEngine

    @Environment(\.locale) private var locale
    @State private var activeSheet: ActiveSheet?
    @State private var extraFolders = UserSettings.extraKeyFolders
    @State private var showingFolders = false
    @State private var selectedKeyPath: String?
    @State private var exportedQrData: Data?

    var body: some View {
        Group {
            if coreEngine.keys.isEmpty {
                ContentUnavailableView(
                    "No Keys Found",
                    systemImage: "key.slash",
                    description: Text("Insert a disk with a key file, or add a search folder from the toolbar.")
                )
            } else {
                List(coreEngine.keys, id: \.fullPath, selection: $selectedKeyPath) { key in
                    KeyRow(key: key, coreEngine: coreEngine, activeSheet: $activeSheet)
                }
            }
        }
        // No `.navigationTitle` here: `MainWindow` sets the window's title bar itself, for all
        // five sections in one place — see its own doc comment for why.
        .toolbar {
            ToolbarItemGroup {
                Button {
                    Task { await coreEngine.rescanKeys() }
                } label: {
                    Label("Rescan", systemImage: "arrow.clockwise")
                }
                Button {
                    showingFolders = true
                } label: {
                    Label("Folders", systemImage: "folder.badge.gearshape")
                }
                .popover(isPresented: $showingFolders) {
                    FoldersPopover(extraFolders: $extraFolders) {
                        Task { await coreEngine.rescanKeys() }
                    }
                    // A popover, like a sheet, is its own attached window — running the app and
                    // reading this exact popover in each language (task 6's own verification
                    // requirement) showed it does not inherit `\.locale` from its presenting
                    // view the way ordinary child views do, so it needs the override restated.
                    .environment(\.locale, locale)
                }
            }
        }
        .onAppear { adoptPendingSelection() }
        .onChange(of: coreEngine.pendingKeySelection) { _, _ in adoptPendingSelection() }
        .sheet(item: $activeSheet) { sheet in
            // `Group { switch ... }.environment(...)`, not the environment modifier on each
            // case: a sheet is its own attached window — running the app and reading each of
            // these three sheets in each language (task 6's own verification requirement) showed
            // none of them inherit `\.locale` from `KeysView` the way an ordinary child view
            // would, so it needs restating here, once, for the sheet as a whole.
            Group {
                switch sheet {
                case let .changePassword(key):
                    ChangePasswordSheet(key: key, coreEngine: coreEngine)
                case let .convert(key):
                    PasswordPromptSheet(
                        title: isPfx(key) ? "Convert to YKS" : "Convert to PFX",
                        subject: key.name,
                        confirmTitle: "Convert",
                        perform: { password in
                            if isPfx(key) {
                                try await coreEngine.convertPfxToYks(path: key.fullPath, password: password)
                            } else {
                                try await coreEngine.convertYksToPfx(path: key.fullPath, password: password)
                            }
                        },
                        onDone: { Task { await coreEngine.refreshKeys() } }
                    )
                case let .exportQrKey(key):
                    PasswordPromptSheet(
                        title: "Export QR-key",
                        subject: key.name,
                        confirmTitle: "Export",
                        perform: { password in
                            exportedQrData = try await coreEngine.exportQrKey(path: key.fullPath, password: password)
                        },
                        onDone: { presentSavePanel(for: key) }
                    )
                case let .unlock(key):
                    PasswordPromptSheet(
                        title: "Unlock Key",
                        subject: key.name,
                        confirmTitle: "Unlock",
                        perform: { password in
                            try await coreEngine.unlockKey(key, password: password)
                        },
                        onDone: {}
                    )
                }
            }
            .environment(\.locale, locale)
        }
    }

    private func isPfx(_ key: KeyEntry) -> Bool {
        key.fullPath.lowercased().hasSuffix(".pfx")
    }

    private func adoptPendingSelection() {
        guard let pending = coreEngine.pendingKeySelection else { return }
        selectedKeyPath = pending
        coreEngine.pendingKeySelection = nil
    }

    private func presentSavePanel(for key: KeyEntry) {
        guard let data = exportedQrData else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(key.name).qrkey"
        panel.begin { response in
            defer { exportedQrData = nil }
            guard response == .OK, let url = panel.url else { return }
            try? data.write(to: url)
        }
    }
}
