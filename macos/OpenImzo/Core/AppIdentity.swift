import Foundation

/// The product's own name, in one place. Every sentence that mentions the app interpolates
/// `productName` rather than typing "OpenImzo" into its own literal — across three
/// languages and a dozen-odd strings, that would otherwise mean retyping the name into every one
/// of them, in every language, and a rename missing one. That is exactly why this held for the
/// rename to OpenImzo: only this one literal, `project.yml`'s `PRODUCT_NAME`, and
/// `AppDirectories.folderName` needed to change.
///
/// Never translated, by design: a product name reads the same in every language, the same way a
/// language's own name does — see `AppLanguage.displayName`'s doc comment for that same
/// reasoning. `Text`/`Button`/etc. calls that use it directly (rather than interpolating it into
/// a longer sentence) use `verbatim:` for exactly this reason.
///
/// Not the single source for *every* occurrence of the name in this app: `AppDirectories
/// .folderName` (the `~/Library/Application Support` and `~/Library/Logs` subdirectory name) is
/// already its own single, separately-referenced literal — a rename touching on-disk paths needs
/// a migration, which is `AppDirectories`' own job, not this one's.
enum AppIdentity {
    static let productName = "OpenImzo"

    /// Where this app is published. Two literals rather than one address,
    /// because two different addresses are built from them — the page a person
    /// visits and the API `UpdateChecker` asks — and a project that moved with
    /// only one of them updated would either link nowhere or check the wrong
    /// repository for updates, silently.
    static let repositoryOwner = "ganiyevuz"
    static let repositoryName = "openimzo"

    /// `Optional` rather than force-unwrapped, and constructed from fixed
    /// literals this file owns rather than anything a person types or a server
    /// sends: `nil` could only ever mean this file itself was edited into an
    /// invalid address, which is a mistake to notice while editing, not a
    /// reason to crash a shipped app. Callers leave the row or the check out.
    static let repositoryURL = URL(string: "https://github.com/\(repositoryOwner)/\(repositoryName)")

    /// The newest published, non-draft, non-prerelease release. GitHub's own
    /// `/releases/latest` already excludes the other two, so nothing here has
    /// to filter them out and get that filter wrong.
    static let latestReleaseEndpoint =
        URL(string: "https://api.github.com/repos/\(repositoryOwner)/\(repositoryName)/releases/latest")

    /// What the repository looks like written down, for a link's own text.
    static let repositoryLabel = "github.com/\(repositoryOwner)/\(repositoryName)"
}
