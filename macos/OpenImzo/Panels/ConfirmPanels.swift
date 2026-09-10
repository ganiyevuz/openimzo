import SwiftUI

/// Confirms using a suggested (modern) algorithm in place of one a website requested. `true`
/// means "use the suggested algorithm"; `false` — including on cancel — keeps the algorithm the
/// site originally asked for, matching `InterimUiDelegate`'s own refuse-by-default value: doing
/// nothing must never silently substitute a different algorithm than the one requested.
struct LegacyAlgorithmPanelView: View {
    let origin: String
    let requested: String
    let suggested: String
    let deadline: Date
    let onAnswer: (Bool) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            RequestPanelHeader(
                symbolName: "exclamationmark.shield",
                subtitle: "Legacy signing algorithm requested by",
                origin: origin,
                deadline: deadline
            )

            VStack(alignment: .leading, spacing: 4) {
                Text("Requested: \(requested)").font(.callout)
                Text("Suggested: \(suggested)").font(.callout)
            }

            Text("Using the suggested algorithm is the modern, recommended choice.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Spacer()
                Button("Keep Requested", role: .cancel) { onAnswer(false) }
                    .keyboardShortcut(.cancelAction)
                Button("Use Suggested") { onAnswer(true) }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 380)
    }
}

/// Consents to a website contributing randomness to key generation on this computer
/// (`Settings.askBeforeRandseed`). Denying is the safe default, matching cancellation and
/// `InterimUiDelegate`'s own refusal.
struct RandseedPanelView: View {
    let origin: String
    let deadline: Date
    let onAnswer: (Bool) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            RequestPanelHeader(
                symbolName: "shuffle",
                subtitle: "Random seed requested by",
                origin: origin,
                deadline: deadline
            )

            Text("This site wants to contribute randomness to key generation on this computer.")
                .font(.callout)

            HStack {
                Spacer()
                Button("Deny", role: .cancel) { onAnswer(false) }
                    .keyboardShortcut(.cancelAction)
                Button("Allow") { onAnswer(true) }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 380)
    }
}
