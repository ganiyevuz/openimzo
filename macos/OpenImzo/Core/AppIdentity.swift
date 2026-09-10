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
}
