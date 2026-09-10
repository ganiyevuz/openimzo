import SwiftUI

private struct ActivityRow: View {
    let entry: ActivityEntry

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(entry.at)
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 170, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.origin)
                    .font(.callout)
                Text(entry.function)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Text(entry.outcome)
                .font(.caption)
                .foregroundStyle(entry.outcome.lowercased() == "ok" ? Color.green : Color.orange)
        }
        .padding(.vertical, 2)
    }
}

/// One request per completed call (`Event.activity`), always shown live for as long as the app
/// has been running — there is no "fetch the last N" call on the core, so this is the only
/// history there is unless `Settings.keepActivityLog` is on, in which case `CoreEngine` also
/// reads `activity.jsonl` back at launch. Log lines (`Event.log`) appear here too, but only
/// while that same setting is on — see `CoreEngine.appendLogLine`.
struct ActivityView: View {
    var coreEngine: CoreEngine

    private var isPersisting: Bool { coreEngine.settings?.keepActivityLog == true }

    var body: some View {
        VStack(spacing: 0) {
            if !isPersisting {
                Label(
                    "Activity persistence is off — showing only what has arrived since this app started. Turn it on in Settings to keep history across launches.",
                    systemImage: "info.circle"
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.08))
            }

            if coreEngine.activity.isEmpty && coreEngine.logLines.isEmpty {
                ContentUnavailableView(
                    "No Activity Yet",
                    systemImage: "clock.arrow.circlepath",
                    description: Text("Calls a website makes to \(AppIdentity.productName) will appear here.")
                )
                .frame(maxHeight: .infinity)
            } else {
                List {
                    if !coreEngine.activity.isEmpty {
                        Section("Requests") {
                            ForEach(Array(coreEngine.activity.reversed().enumerated()), id: \.offset) { _, entry in
                                ActivityRow(entry: entry)
                            }
                        }
                    }
                    if isPersisting, !coreEngine.logLines.isEmpty {
                        Section("Log") {
                            ForEach(Array(coreEngine.logLines.reversed().enumerated()), id: \.offset) { _, line in
                                Text(line)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }
                        }
                    }
                }
            }
        }
        // No `.navigationTitle` here: `MainWindow` sets the window's title bar itself, for all
        // five sections in one place — see its own doc comment for why.
        .toolbar {
            ToolbarItem {
                Button(role: .destructive) {
                    coreEngine.clearActivity()
                } label: {
                    Label("Clear", systemImage: "trash")
                }
                .disabled(coreEngine.activity.isEmpty && coreEngine.logLines.isEmpty)
            }
        }
    }
}
