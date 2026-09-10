import Foundation

/// A dotted-integer version, which is what this app's versions are: dates —
/// `2026.09.11`, with a fourth component on a day that needed a second build. See
/// `Info.plist` for why they are dates rather than semantic version numbers.
///
/// Compared component by component as integers, never as strings. `9` and `09` are the same
/// version, and `2026.09.2` correctly precedes `2026.09.11` — which a string comparison gets
/// backwards the moment one component's width changes, and the release that would first show it
/// is the one nobody would be told about.
struct AppVersion: Comparable, CustomStringConvertible {
    let components: [Int]
    let text: String

    /// `nil` for anything that is not one or more dot-separated non-negative integers. A release
    /// tagged `nightly`, or `2026.09.11-rc1`, is not something this app can place relative to its
    /// own version, and guessing goes wrong in both directions: nagging about an "update" older
    /// than what is installed, or staying quiet about a real one. A leading `v` is accepted
    /// because that is how the git tags are written.
    init?(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let body = trimmed.hasPrefix("v") ? String(trimmed.dropFirst()) : trimmed
        let parts = body.split(separator: ".", omittingEmptySubsequences: false)
        guard !parts.isEmpty else { return nil }
        var parsed: [Int] = []
        for part in parts {
            guard let value = Int(part), value >= 0 else { return nil }
            parsed.append(value)
        }
        components = parsed
        text = body
    }

    var description: String { text }

    /// Missing trailing components count as zero, so `2026.09.11` and `2026.09.11.0` are the same
    /// version and `2026.09.11.2` is newer than both — which is exactly what a same-day second
    /// build means.
    static func < (lhs: AppVersion, rhs: AppVersion) -> Bool {
        for index in 0 ..< max(lhs.components.count, rhs.components.count) {
            let left = index < lhs.components.count ? lhs.components[index] : 0
            let right = index < rhs.components.count ? rhs.components[index] : 0
            if left != right { return left < right }
        }
        return false
    }

    static func == (lhs: AppVersion, rhs: AppVersion) -> Bool {
        !(lhs < rhs) && !(rhs < lhs)
    }

    /// What this build reports. `nil` only if `CFBundleShortVersionString` is missing or is not a
    /// dotted-integer version, in which case there is nothing to compare a release against and
    /// `UpdateChecker` says so rather than picking a side.
    static var current: AppVersion? {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String).flatMap(AppVersion.init)
    }
}
