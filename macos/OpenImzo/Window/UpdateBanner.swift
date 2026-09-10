import SwiftUI

/// The strip across the top of the main window when a newer release exists.
///
/// A banner rather than an alert: an alert interrupts whatever a person opened the window to do,
/// and an update is not urgent enough to earn that. This waits where it will be read, and both
/// ways out of it — download, or skip this version — are one click, so it never becomes something
/// people learn to dismiss without reading.
struct UpdateBanner: View {
    let version: String
    let page: URL
    let onSkip: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "arrow.down.circle.fill")
                .font(.title3)
                .foregroundStyle(Color.accentColor)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                // `String(version)`, not a bare interpolation: `LocalizedStringKey` interpolation
                // needs a `String` argument to reliably produce a `%@` catalogue placeholder,
                // the same reason `PortStatusRow` spells out `String(port)`.
                Text("Version \(String(version)) is available")
                    .font(.callout.weight(.semibold))
                Text("Opens the release page in your browser. Nothing is installed automatically.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 8)

            Button("Skip This Version", action: onSkip)
                .buttonStyle(.link)
            Link("Download", destination: page)
                .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.thinMaterial)
        .overlay(alignment: .bottom) {
            // A hairline rather than a border all the way round: this sits directly above the
            // detail view, and the only edge that needs separating is the one they share.
            Rectangle()
                .fill(Color.primary.opacity(0.12))
                .frame(height: 1)
        }
    }
}
