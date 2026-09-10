import SwiftUI

/// The password rules the original enforces when creating a new PFX file
/// (`NewPFXKeyDialogController`): only Latin letters and digits, at least 10
/// characters, and at least 2 lowercase, 2 uppercase letters and 1 digit. The core
/// only rejects a bad password after the person has already committed to it, so this panel
/// checks the same rules live as they type.
struct NewPfxPasswordRules {
    let password: String

    private var lowercaseCount: Int { password.lazy.filter { $0.isASCII && $0.isLowercase }.count }
    private var uppercaseCount: Int { password.lazy.filter { $0.isASCII && $0.isUppercase }.count }
    private var digitCount: Int { password.lazy.filter { $0.isASCII && $0.isNumber }.count }

    var onlyLatinLettersAndDigits: Bool {
        !password.isEmpty && password.allSatisfy { ($0.isASCII && $0.isLetter) || ($0.isASCII && $0.isNumber) }
    }

    var isLongEnough: Bool { password.count >= 10 }

    var hasRequiredVariety: Bool { lowercaseCount >= 2 && uppercaseCount >= 2 && digitCount >= 1 }

    var isValid: Bool { onlyLatinLettersAndDigits && isLongEnough && hasRequiredVariety }
}

private struct PasswordRuleRow: View {
    let satisfied: Bool
    /// `LocalizedStringKey`, not `String`: a `String` field feeding `Text(text)` renders
    /// verbatim, in whatever language the literal at the call site was written in, never looked
    /// up in the string catalogue.
    let text: LocalizedStringKey

    var body: some View {
        Label {
            Text(text)
        } icon: {
            Image(systemName: satisfied ? "checkmark.circle.fill" : "circle")
        }
        .foregroundStyle(satisfied ? Color.green : Color.secondary)
    }
}

/// Asks where and with what password to create a new PFX key file, for a website's PKCS#10
/// request. The disk and path are the core's own candidates — this panel never invents one — and
/// the password is validated live against the same rules the core would otherwise reject it with
/// only after the person has already committed to it.
struct NewPfxPanelView: View {
    let request: NewPfxRequest
    let deadline: Date
    let onSubmit: (NewPfxAnswer) -> Void
    let onCancel: () -> Void

    @State private var selectedDisk: String
    @State private var password = ""
    @State private var confirmation = ""
    @FocusState private var passwordFocused: Bool

    init(request: NewPfxRequest, deadline: Date, onSubmit: @escaping (NewPfxAnswer) -> Void, onCancel: @escaping () -> Void) {
        self.request = request
        self.deadline = deadline
        self.onSubmit = onSubmit
        self.onCancel = onCancel
        _selectedDisk = State(initialValue: request.disks.first ?? "")
    }

    private var rules: NewPfxPasswordRules { NewPfxPasswordRules(password: password) }
    private var passwordsMatch: Bool { !password.isEmpty && password == confirmation }
    private var canSubmit: Bool { rules.isValid && passwordsMatch && !selectedDisk.isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            RequestPanelHeader(
                symbolName: "doc.badge.plus",
                subtitle: "New key requested by",
                origin: request.origin,
                deadline: deadline
            )

            VStack(alignment: .leading, spacing: 4) {
                Text("File").font(.caption).foregroundStyle(.secondary)
                if request.disks.count > 1 {
                    Picker("Disk", selection: $selectedDisk) {
                        ForEach(request.disks, id: \.self) { disk in
                            Text(displayPath(disk: disk)).tag(disk)
                        }
                    }
                    .labelsHidden()
                } else {
                    Text(displayPath(disk: selectedDisk))
                        .font(.callout)
                        .foregroundStyle(selectedDisk.isEmpty ? Color.red : Color.primary)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                SecureField("New password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .focused($passwordFocused)
                    .privacySensitive()
                SecureField("Confirm password", text: $confirmation)
                    .textFieldStyle(.roundedBorder)
                    .privacySensitive()

                VStack(alignment: .leading, spacing: 2) {
                    PasswordRuleRow(satisfied: rules.isLongEnough, text: "At least 10 characters")
                    PasswordRuleRow(
                        satisfied: rules.hasRequiredVariety,
                        text: "At least 2 lowercase, 2 uppercase letters, and 1 digit"
                    )
                    PasswordRuleRow(satisfied: rules.onlyLatinLettersAndDigits, text: "Only Latin letters and digits")
                    // Always shown, never conditionally added: the panel's window is sized once,
                    // up front, from its content's shape at that moment (see
                    // `RequestPanelController`), so nothing here may add or remove a row later.
                    PasswordRuleRow(satisfied: passwordsMatch, text: "Passwords match")
                }
                .font(.caption)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button("Create") {
                    onSubmit(NewPfxAnswer(disk: selectedDisk, password: password))
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canSubmit)
            }
        }
        .padding(20)
        .frame(width: 420)
        // See `PasswordPanelView`: focus follows the window's real `didBecomeKeyNotification`
        // rather than a timing guess.
        .background(WindowKeyObserver { passwordFocused = true })
    }

    private func displayPath(disk: String) -> String {
        disk.hasSuffix("/") ? disk + request.filePath : disk + "/" + request.filePath
    }
}
