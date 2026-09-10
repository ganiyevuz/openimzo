import AppKit
import SwiftUI

/// Version, licence, the two addresses this project lives at, and a button to open the logs
/// directory — the design spec's own list for this screen, plus the links the owner asked for.
/// There is nothing to fetch from `CoreEngine` here: everything shown either comes from the app's
/// own bundle or is a fixed fact about the project, so this view takes no dependency on it.
struct AboutView: View {
    /// The two addresses the Links section offers. `URL(string:)` is failable, and these are
    /// fixed literals this file owns rather than anything a person types or a server sends, so
    /// `nil` could only ever mean this file itself was edited into an invalid address. That is a
    /// mistake to notice while editing, not a reason to force-unwrap and crash a shipped app in
    /// front of someone: the row for a `nil` address is simply left out below.
    private static let developerURL = URL(string: "https://jakhongir.dev")

    private var shortVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
    }

    private var buildNumber: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "—"
    }

    /// Versions here are dates (`2026.09.11`), and the build number is normally the same date —
    /// see `Info.plist`. Printing it twice tells a reader nothing, so the parenthesis appears
    /// only when the two actually differ, which happens when a day needed a second build.
    @ViewBuilder private var versionLine: some View {
        if buildNumber == shortVersion {
            Text("Version \(shortVersion)")
        } else {
            Text("Version \(shortVersion) (\(buildNumber))")
        }
    }

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 4) {
                    Text(verbatim: AppIdentity.productName)
                        .font(.title2.bold())
                    versionLine
                        .foregroundStyle(.secondary)
                    Text("A native replacement for the original E-IMZO desktop client.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }

            Section("Licence") {
                // GPL-3.0-or-later, not MIT: `LICENSE` in the repository root is the GPL-3.0 text
                // verbatim and every crate in the workspace declares `license =
                // "GPL-3.0-or-later"`. A licence line that names the wrong licence is worse than
                // no licence line at all, so this one names it and then says, in one sentence,
                // what it actually lets a reader do.
                Text("\(AppIdentity.productName) is released under the GNU General Public License, version 3 or later (GPL-3.0-or-later).")
                // One literal, not two joined with `+`: a `String` built by concatenation is
                // passed to `Text` via its verbatim, non-localizing overload, so it would never
                // be looked up in the string catalogue no matter what the catalogue said.
                Text("Anyone may use, study, modify and redistribute it, and a modified version they distribute must also be published under the same licence.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                // Deliberately does not characterise those licences as "permissive": the
                // dependency audit found MPL-2.0 crates alongside the permissive ones, and
                // THIRD_PARTY_LICENSES.md is where the actual per-crate list lives.
                Text("It links a small number of open-source Rust libraries for cryptography, certificate handling, and networking, each under its own open-source licence, listed in THIRD_PARTY_LICENSES.md.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Links") {
                if let developerURL = Self.developerURL {
                    LabeledContent("Developer") {
                        // `Link`, not a `Button` around `NSWorkspace.open`: it is the same
                        // external open, and it is the control macOS already knows how to render
                        // and describe as a link. `Text(verbatim:)` for the address itself — a web
                        // address is not translated, and passing it as a literal would otherwise
                        // send it to the catalogue looking for a translation of a domain name.
                        Link(destination: developerURL) {
                            Text(verbatim: "jakhongir.dev")
                        }
                        .accessibilityLabel("Developer website, opens in your browser")
                    }
                }
                if let projectURL = AppIdentity.repositoryURL {
                    LabeledContent("Project") {
                        Link(destination: projectURL) {
                            Text(verbatim: AppIdentity.repositoryLabel)
                        }
                        .accessibilityLabel("Project on GitHub, opens in your browser")
                    }
                }
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
