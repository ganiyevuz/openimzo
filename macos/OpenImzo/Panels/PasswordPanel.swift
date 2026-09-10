import SwiftUI

/// Asks for the password that opens a key. The most common of the five requests, and the one
/// the design spec's own dialog semantics (retry loop, 60 s auto-cancel) describe in the most
/// detail.
///
/// The password lives only in `password`, this view's own `@State`, for exactly as long as the
/// panel is on screen: it is handed to `onSubmit` and never copied anywhere else, never logged,
/// and is dropped along with this view the moment `MacUiDelegate` releases the panel that owns
/// it.
struct PasswordPanelView: View {
    let request: PasswordRequest
    let deadline: Date
    let onSubmit: (PasswordAnswer) -> Void
    let onCancel: () -> Void

    @State private var password = ""
    @State private var remember = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            RequestPanelHeader(
                symbolName: "lock.shield",
                subtitle: "Password requested by",
                origin: request.origin,
                deadline: deadline
            )

            VStack(alignment: .leading, spacing: 8) {
                Text(request.subject)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)

                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .focused($passwordFocused)
                    .privacySensitive()
                    .onSubmit(submit)

                // `request.error` is treated as a boolean, not displayed — per task 6's
                // controller addendum, this is the one core-sourced string that reaches a
                // panel (`crates/openimzo-rpc/src/plugins/keystore.rs`'s
                // `key.password.is.incorrect.or.key.file.is.corrupted`, in whichever of the
                // core's own two languages it's currently running in). `error != nil` means only
                // "the previous attempt was rejected"; the message shown is this app's own,
                // translated the same way as everything else in this panel, not the core's.
                if request.error != nil {
                    Label("The password was incorrect, or the key file is corrupted.", systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.red)
                }

                if request.allowRemember {
                    Toggle("Remember for 6 hours", isOn: $remember)
                        .toggleStyle(.checkbox)
                }
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button("OK", action: submit)
                    .keyboardShortcut(.defaultAction)
                    // Matches the original: an empty password does nothing rather than being
                    // treated as an answer, so there is nothing to submit yet.
                    .disabled(password.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 380)
        // Set focus when the window actually becomes key, not on a timing guess — see
        // `WindowKeyObserver`. This exact bug (keystrokes not reaching the field) was found
        // twice already with the runloop-hop version this replaced.
        .background(WindowKeyObserver { passwordFocused = true })
    }

    private func submit() {
        guard !password.isEmpty else { return }
        onSubmit(PasswordAnswer(password: password, remember: remember))
    }
}
