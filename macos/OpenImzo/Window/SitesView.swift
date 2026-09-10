import SwiftUI

private struct SiteRow: View {
    let site: Site
    let onRevoke: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(site.origin)
                    .font(.headline)
                    .textSelection(.enabled)
                HStack(spacing: 8) {
                    if site.registered {
                        Label("Verified", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                    }
                    if site.allowedAlways {
                        Label("Always Allowed", systemImage: "hand.thumbsup.fill")
                            .foregroundStyle(.blue)
                    }
                }
                .font(.caption)
            }

            Spacer(minLength: 8)

            Button("Revoke", role: .destructive, action: onRevoke)
                .buttonStyle(.bordered)
        }
        .padding(.vertical, 4)
    }
}

/// Every site that has either a verified API key cached or a standing "always allow" decision,
/// with a way to revoke both at once — `ApikeyService::forget_site` on the core side doesn't
/// distinguish, so neither does this screen.
struct SitesView: View {
    var coreEngine: CoreEngine

    var body: some View {
        Group {
            if coreEngine.sites.isEmpty {
                ContentUnavailableView(
                    "No Sites Yet",
                    systemImage: "globe",
                    description: Text("Sites that verify an API key or that you've allowed will appear here.")
                )
            } else {
                List(coreEngine.sites, id: \.origin) { site in
                    SiteRow(site: site) {
                        Task { await coreEngine.forgetSite(site.origin) }
                    }
                }
            }
        }
        // No `.navigationTitle` here: `MainWindow` sets the window's title bar itself, for all
        // five sections in one place — see its own doc comment for why.
        .toolbar {
            ToolbarItem {
                Button {
                    Task { await coreEngine.refreshSites() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
        }
        .task { await coreEngine.refreshSites() }
    }
}
