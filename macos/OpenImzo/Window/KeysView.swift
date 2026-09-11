import AppKit
import SwiftUI

/// Replaces a value with dots while masking is on.
///
/// The mask is a fixed run, never the length of what it hides. A mask that grows and shrinks with
/// its value leaks the length of a name and the number of digits in an identifier — and for a
/// national identifier, whose format is public and whose length is fixed, length plus format is
/// most of the way to knowing its shape. Eight dots for everything, always.
enum SensitiveText {
    static let mask = "••••••••"

    static func render(_ value: String, hidden: Bool) -> String {
        guard hidden, !value.isEmpty else { return value }
        return mask
    }
}

/// The eye beside a key: shows what this one row is hiding, without turning masking off
/// everywhere. Reveal is per key and lives only in memory, so closing the window puts it back.
private struct RevealButton: View {
    let isHidden: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: isHidden ? "eye" : "eye.slash")
        }
        .buttonStyle(.borderless)
        .foregroundStyle(.secondary)
        .accessibilityLabel(isHidden ? "Show this key's details" : "Hide this key's details")
        .help(isHidden ? "Show this key's details" : "Hide this key's details")
    }
}

/// How a key's validity reads at a glance.
///
/// `unknown` is a real state and not a synonym for "fine": a locked PFX whose alias carries no
/// `validto` has no expiry date to judge, and a badge that quietly said "Valid" for it would be
/// asserting something nobody has checked.
enum KeyValidity {
    case unknown
    case valid(daysRemaining: Int64)
    case expiringSoon(daysRemaining: Int64)
    case expired

    /// A month. Long enough that someone can still get a new key issued before the old one stops
    /// working, which is the only thing this warning is for.
    static let soonThresholdDays: Int64 = 30

    init(hasValidity: Bool, expired: Bool, daysRemaining: Int64) {
        if !hasValidity {
            self = .unknown
        } else if expired {
            self = .expired
        } else if daysRemaining <= Self.soonThresholdDays {
            self = .expiringSoon(daysRemaining: daysRemaining)
        } else {
            self = .valid(daysRemaining: daysRemaining)
        }
    }
}

private struct ValidityBadge: View {
    let validity: KeyValidity

    var body: some View {
        switch validity {
        case .unknown:
            Label("Unknown", systemImage: "questionmark.circle")
                .foregroundStyle(.secondary)
        case .expired:
            Label("Expired", systemImage: "xmark.seal.fill")
                .foregroundStyle(.red)
        case .expiringSoon:
            Label("Expires soon", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        case .valid:
            Label("Valid", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
        }
    }
}

/// Everything one row of the Keys list shows, resolved once.
///
/// The certificate summary, when the person has unlocked this key this session, wins over what
/// the row was scanned with — that is the whole point of unlocking one.
struct KeyPresentation {
    let identity: KeyIdentity
    let validity: KeyValidity
    let validFrom: String
    let validTo: String
    let issuerName: String
    let serialNumber: String
    let publicKeyAlgName: String
    let subjectName: String
    /// True only for a PFX still waiting on its password. A YKS with nothing to show cannot be
    /// unlocked, so it never offers to be.
    let isLocked: Bool

    init(_ key: KeyEntry, unlocked: CertificateSummary?) {
        identity = unlocked?.identity ?? key.identity
        issuerName = unlocked?.issuerName ?? key.issuerName
        serialNumber = unlocked?.serialNumber ?? key.serialNumber
        publicKeyAlgName = unlocked?.publicKeyAlgName ?? key.publicKeyAlgName
        subjectName = unlocked?.subjectName ?? key.subjectName
        isLocked = unlocked == nil && key.locked
        if let unlocked {
            validFrom = unlocked.validFrom
            validTo = unlocked.validTo
            validity = KeyValidity(hasValidity: true, expired: unlocked.expired, daysRemaining: unlocked.daysRemaining)
        } else {
            validFrom = key.validFrom
            validTo = key.validTo
            validity = KeyValidity(hasValidity: key.hasValidity, expired: key.expired, daysRemaining: key.daysRemaining)
        }
    }

    /// What to call this key. The alias names the person even when the certificate cannot be
    /// read, which is why a locked PFX is not anonymous; the file name is the last resort.
    func displayName(fallback: String) -> String {
        if !identity.commonName.isEmpty { return identity.commonName }
        if !identity.organisation.isEmpty { return identity.organisation }
        return fallback
    }

    /// The national identifier to show in the list, with the label the original uses for it.
    /// An organisation's key leads with the organisation's tax number; a person's with PINFL.
    var primaryIdentifier: (label: LocalizedStringKey, value: String)? {
        if identity.isOrganisation, !identity.tinOrganisation.isEmpty {
            return ("TIN", identity.tinOrganisation)
        }
        if !identity.pinfl.isEmpty { return ("PINFL", identity.pinfl) }
        if !identity.tinIndividual.isEmpty { return ("TIN", identity.tinIndividual) }
        if !identity.tinOrganisation.isEmpty { return ("TIN", identity.tinOrganisation) }
        return nil
    }
}

private struct KeyRow: View {
    let key: KeyEntry
    var coreEngine: CoreEngine
    @Binding var activeSheet: KeysView.ActiveSheet?
    /// True when this row's name and identifier are dots right now.
    let isHidden: Bool
    let onToggleReveal: () -> Void
    /// Whether masking is on at all. Without it the eye would sit on every row forever, offering
    /// to reveal something already in plain sight.
    let maskingEnabled: Bool

    private var presentation: KeyPresentation {
        KeyPresentation(key, unlocked: coreEngine.unlockedSummary(for: key))
    }

    var body: some View {
        let shown = presentation
        // Hoisted out of the `Button(...)` below deliberately: `scripts/check-localization.py`
        // scans a localizable initializer's whole first-argument span for string literals, so a
        // `key.format == "PFX"` written inline there makes it hunt the catalogue for a
        // translation of the word PFX. The check is a source-level heuristic and this is the
        // shape that confuses it; keeping the comparison out of the argument is free.
        let isPfxKey = key.format == "PFX"
        HStack(alignment: .top, spacing: 12) {
            // The format, not a generic key icon: PFX and YKS behave differently — only a PFX can
            // be unlocked, exported as a QR-key, or converted to YKS — so which one a row is is
            // worth more than a picture of a key repeated down the column.
            Text(verbatim: key.format)
                .font(.caption2.monospaced().weight(.semibold))
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.secondary.opacity(0.15), in: RoundedRectangle(cornerRadius: 4))
                .frame(width: 44, alignment: .leading)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    if shown.isLocked {
                        Image(systemName: "lock.fill")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .accessibilityHidden(true)
                    }
                    Text(verbatim: SensitiveText.render(shown.displayName(fallback: key.name), hidden: isHidden))
                        .font(.headline)
                    if maskingEnabled {
                        RevealButton(isHidden: isHidden, action: onToggleReveal)
                            .font(.caption)
                    }
                }
                HStack(spacing: 8) {
                    Text(shown.identity.isOrganisation ? "Organisation" : "Individual")
                    if let identifier = shown.primaryIdentifier {
                        Text(verbatim: "·")
                        Text(identifier.label)
                        Text(verbatim: SensitiveText.render(identifier.value, hidden: isHidden))
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                if shown.isLocked {
                    // Per key, per session, and only on request — never scanned automatically —
                    // matching the constraint `Engine.unlock_key` itself is built to (see its own
                    // doc comment in `crates/openimzo-ffi/src/engine.rs`).
                    Button("Unlock to read the certificate…") { activeSheet = .unlock(key) }
                        .font(.caption)
                        .buttonStyle(.link)
                }
            }
            .textSelection(.enabled)

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 4) {
                ValidityBadge(validity: shown.validity)
                    .font(.caption)
                switch shown.validity {
                case let .valid(days), let .expiringSoon(days):
                    // `String(days)`, not a bare interpolation: a `LocalizedStringKey` needs a
                    // `String` argument to reliably produce a `%@` catalogue placeholder.
                    Text(days == 0 ? "Expires today" : "\(String(days)) days left")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                case .expired, .unknown:
                    if !shown.validTo.isEmpty {
                        Text(verbatim: shown.validTo)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Menu {
                Button("Change Password…") { activeSheet = .changePassword(key) }
                Button(isPfxKey ? "Convert to YKS…" : "Convert to PFX…") { activeSheet = .convert(key) }
                if isPfxKey {
                    Button("Export QR-key…") { activeSheet = .exportQrKey(key) }
                    if shown.isLocked {
                        Button("Unlock…") { activeSheet = .unlock(key) }
                    }
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

/// One label-and-value line in the detail panel. Left out entirely when the value is empty,
/// rather than shown as a dash: a panel of twenty rows where half read "—" hides the six that
/// say something.
private struct DetailRow: View {
    let label: LocalizedStringKey
    let value: String
    /// A second, dimmer line under the value — the OID an identifier came from, say.
    var note: String?
    /// Whether this particular field is one of the ones masking covers. The note is never
    /// masked: an OID is a public constant, and hiding it would hide what the row means rather
    /// than what it says.
    var sensitive: Bool = false
    var isHidden: Bool = false

    var body: some View {
        if !value.isEmpty {
            LabeledContent {
                VStack(alignment: .leading, spacing: 1) {
                    // Two branches rather than one `Text` with a conditional modifier:
                    // `.textSelection(_:)` is generic over the selectability type, so
                    // `cond ? .disabled : .enabled` is two different types in one expression and
                    // does not compile. Selection is off while masked so the real value cannot
                    // be copied out of a row that is showing dots.
                    if sensitive && isHidden {
                        Text(verbatim: SensitiveText.mask)
                            .textSelection(.disabled)
                    } else {
                        Text(verbatim: value)
                            .textSelection(.enabled)
                    }
                    if let note, !note.isEmpty {
                        Text(verbatim: note)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
            } label: {
                Text(label)
            }
        }
    }
}

/// The trailing inspector: everything known about the selected key, grouped the way someone
/// checking a certificate reads it — who, which numbers, how long, with what, from where.
struct KeyDetailPanel: View {
    let key: KeyEntry
    var coreEngine: CoreEngine
    @Binding var activeSheet: KeysView.ActiveSheet?
    let isHidden: Bool
    let onToggleReveal: () -> Void
    let maskingEnabled: Bool

    var body: some View {
        let shown = KeyPresentation(key, unlocked: coreEngine.unlockedSummary(for: key))
        Form {
            if maskingEnabled {
                Section {
                    HStack {
                        Label(
                            isHidden ? "Details are hidden" : "Details are showing",
                            systemImage: isHidden ? "eye.slash" : "eye"
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        Spacer()
                        Button(isHidden ? "Show" : "Hide", action: onToggleReveal)
                    }
                }
            }

            Section("Identity") {
                DetailRow(label: "Name", value: shown.identity.commonName, sensitive: true, isHidden: isHidden)
                DetailRow(label: "Surname", value: shown.identity.surname, sensitive: true, isHidden: isHidden)
                DetailRow(label: "Given name", value: shown.identity.givenName, sensitive: true, isHidden: isHidden)
                DetailRow(label: "Organisation", value: shown.identity.organisation, sensitive: true, isHidden: isHidden)
                // Position and country are not masked: a job title and a two-letter country
                // identify nobody on their own, and leaving them visible keeps the panel
                // readable enough to still be worth opening while masked.
                DetailRow(label: "Position", value: shown.identity.position)
                DetailRow(label: "Country", value: shown.identity.country)
            }

            Section("Identifiers") {
                DetailRow(label: "PINFL", value: shown.identity.pinfl, note: "1.2.860.3.16.1.2", sensitive: true, isHidden: isHidden)
                DetailRow(label: "Tax number (person)", value: shown.identity.tinIndividual, note: "UID", sensitive: true, isHidden: isHidden)
                DetailRow(label: "Tax number (organisation)", value: shown.identity.tinOrganisation, note: "1.2.860.3.16.1.1", sensitive: true, isHidden: isHidden)
                // Labelled apart from the certificate's serial number below on purpose: they are
                // different numbers, and a DN attribute called SERIALNUMBER shown as "serial
                // number" beside a certificate is exactly how they get confused.
                DetailRow(label: "Subject serial", value: shown.identity.aliasSerialNumber, note: "SERIALNUMBER", sensitive: true, isHidden: isHidden)
                DetailRow(label: "Certificate serial", value: shown.serialNumber, sensitive: true, isHidden: isHidden)
            }

            Section("Validity") {
                DetailRow(label: "Valid from", value: shown.validFrom)
                DetailRow(label: "Valid to", value: shown.validTo)
                LabeledContent("Status") {
                    HStack(spacing: 6) {
                        ValidityBadge(validity: shown.validity)
                        switch shown.validity {
                        case let .valid(days), let .expiringSoon(days):
                            Text(days == 0 ? "Expires today" : "\(String(days)) days left")
                                .foregroundStyle(.secondary)
                        case .expired, .unknown:
                            EmptyView()
                        }
                    }
                    .font(.callout)
                }
            }

            Section("Cryptography") {
                DetailRow(label: "Key algorithm", value: shown.publicKeyAlgName)
                DetailRow(label: "Issuer", value: shown.issuerName)
                // The whole subject DN, which contains the name and every identifier above.
                // Masking the parts and leaving the string they came from in the clear would be
                // a mask with a hole in it.
                DetailRow(label: "Subject", value: shown.subjectName, sensitive: true, isHidden: isHidden)
            }

            Section("File") {
                DetailRow(label: "Format", value: key.format)
                // The file name of an Uzbek key file is the identifier with an extension on it,
                // and the path contains the file name. Both are masked for that reason, not
                // because a path is private in general.
                DetailRow(label: "File name", value: key.name, sensitive: true, isHidden: isHidden)
                DetailRow(label: "Disk", value: key.disk)
                DetailRow(label: "Full path", value: key.fullPath, sensitive: true, isHidden: isHidden)
            }

            if shown.isLocked {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("This key's certificate cannot be read without its password. What is shown above comes from the file's own alias.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Button("Unlock…") { activeSheet = .unlock(key) }
                    }
                }
            }
        }
        .formStyle(.grouped)
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
    @AppStorage(UserSettings.maskSensitiveDataKey) private var maskSensitiveData = false
    /// Keys the person has chosen to show while masking is on, by file path. In memory only:
    /// a reveal is meant to last as long as you are looking at it, not to quietly undo the
    /// setting for good.
    @State private var revealedKeys: Set<String> = []
    @State private var activeSheet: ActiveSheet?
    @State private var extraFolders = UserSettings.extraKeyFolders
    @State private var showingFolders = false
    @State private var selectedKeyPath: String?
    @State private var exportedQrData: Data?
    @State private var showingDetails = true

    /// The selected key, or `nil` — resolved from `coreEngine.keys` on every read rather than
    /// held as a copy, so a rescan that changes a key's details updates the panel with it.
    private var selectedKey: KeyEntry? {
        guard let selectedKeyPath else { return nil }
        return coreEngine.keys.first { $0.fullPath == selectedKeyPath }
    }

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
                    KeyRow(
                        key: key,
                        coreEngine: coreEngine,
                        activeSheet: $activeSheet,
                        isHidden: isHidden(key),
                        onToggleReveal: { toggleReveal(key) },
                        maskingEnabled: maskSensitiveData
                    )
                }
            }
        }
        // An inspector rather than a second split view: this screen already sits inside
        // `MainWindow`'s own `NavigationSplitView`, and a third column that could not be put away
        // would leave the list itself too narrow to read on a small window. An inspector
        // collapses, and remembers nothing a person has to undo.
        .inspector(isPresented: $showingDetails) {
            if let selectedKey {
                KeyDetailPanel(
                    key: selectedKey,
                    coreEngine: coreEngine,
                    activeSheet: $activeSheet,
                    isHidden: isHidden(selectedKey),
                    onToggleReveal: { toggleReveal(selectedKey) },
                    maskingEnabled: maskSensitiveData
                )
                .inspectorColumnWidth(min: 260, ideal: 320, max: 420)
            } else {
                ContentUnavailableView(
                    "No Key Selected",
                    systemImage: "sidebar.right",
                    description: Text("Select a key in the list to see everything its file says about it.")
                )
                .inspectorColumnWidth(min: 260, ideal: 320, max: 420)
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
                Button {
                    showingDetails.toggle()
                } label: {
                    Label("Details", systemImage: "sidebar.trailing")
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

    /// Whether this key's name and identifiers are dots right now: masking is on and nobody has
    /// asked for this particular one back.
    private func isHidden(_ key: KeyEntry) -> Bool {
        maskSensitiveData && !revealedKeys.contains(key.fullPath)
    }

    /// Reveals one key, or hides it again. Switching masking off entirely is Settings' job; this
    /// is only ever about the row in front of you.
    private func toggleReveal(_ key: KeyEntry) {
        if revealedKeys.contains(key.fullPath) {
            revealedKeys.remove(key.fullPath)
        } else {
            revealedKeys.insert(key.fullPath)
        }
    }

    /// The core already decided this from the file's extension (`KeyEntry.format`), so this asks
    /// it rather than deciding again from the path and risking the two disagreeing.
    private func isPfx(_ key: KeyEntry) -> Bool {
        key.format == "PFX"
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
