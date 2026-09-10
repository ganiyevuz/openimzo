import AppKit
import SwiftUI

/// Version, licence, and a button to open the logs directory — the design spec's own list for
/// this screen. There is nothing to fetch from `CoreEngine` here: everything shown either comes
/// from the app's own bundle or is a fixed fact about the project, so this view takes no
/// dependency on it.
struct AboutView: View {
    private var shortVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
    }

    private var buildNumber: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "—"
    }

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 4) {
                    Text(verbatim: AppIdentity.productName)
                        .font(.title2.bold())
                    Text("Version \(shortVersion) (\(buildNumber))")
                        .foregroundStyle(.secondary)
                    Text("A native replacement for the original E-IMZO desktop client.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }

            Section("Licence") {
                Text("\(AppIdentity.productName) is released under the MIT licence.")
                // One literal, not two joined with `+`: a `String` built by concatenation is
                // passed to `Text` via its verbatim, non-localizing overload, so it would never
                // be looked up in the string catalogue no matter what the catalogue said.
                Text("It links a small number of open-source Rust libraries for cryptography, certificate handling, and networking, each under its own permissive licence.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Diagnostics") {
                Button("Open Logs Folder…") {
                    NSWorkspace.shared.open(AppDirectories.logsDirectory())
                }
            }
        }
        .formStyle(.grouped)
        // No `.navigationTitle` here: `MainWindow` sets the window's title bar itself, for all
        // five sections in one place — see its own doc comment for why.
    }
}
