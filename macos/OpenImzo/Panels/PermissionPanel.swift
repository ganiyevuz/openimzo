import SwiftUI

/// Asks whether a website may call OpenImzo's functions at all — the gate a site has to
/// pass before it can even reach a password or signing prompt. Denying is the safe default:
/// it is both the "no" answer and the value used when the request is cancelled, matching
/// `InterimUiDelegate`'s own refuse-by-default behaviour.
struct PermissionPanelView: View {
    let origin: String
    let deadline: Date
    let onAnswer: (PermissionAnswer) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            RequestPanelHeader(
                symbolName: "hand.raised",
                subtitle: "Permission requested by",
                origin: origin,
                deadline: deadline
            )

            Text("This site wants permission to call \(AppIdentity.productName) functions.")
                .font(.callout)

            HStack {
                Button("Deny", role: .cancel) { onAnswer(.deny) }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Always Allow") { onAnswer(.allowAlways) }
                Button("Allow Once") { onAnswer(.allowOnce) }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 380)
    }
}
