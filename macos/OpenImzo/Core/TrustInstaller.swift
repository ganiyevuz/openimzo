import Foundation

/// Installs the core's generated TLS certificate into a keychain by
/// shelling out to `security add-trusted-cert`, the same tool a person
/// would run themselves — there is no private API for changing trust
/// settings that doesn't ultimately do the same thing.
///
/// Only the login keychain is handled here. The System keychain variant
/// needs an administrator prompt (`security` run against
/// `/Library/Keychains/System.keychain` requires elevation) and belongs to
/// a later phase; `MacPlatform.installTlsTrust` returns `false` for that
/// case before this type is ever involved, rather than attempting it and
/// pretending an unprompted elevation happened.
enum TrustInstaller {
    static func installIntoLoginKeychain(certPem: String) async -> Bool {
        let certURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("openimzo-trust-\(UUID().uuidString).pem")
        do {
            try certPem.write(to: certURL, atomically: true, encoding: .utf8)
        } catch {
            return false
        }
        defer { try? FileManager.default.removeItem(at: certURL) }

        // The stable path for the current user's login keychain since macOS
        // 10.12 (`login.keychain-db`, not the older bare `login.keychain`).
        let loginKeychain = NSHomeDirectory() + "/Library/Keychains/login.keychain-db"

        return await withCheckedContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
            process.arguments = [
                "add-trusted-cert", "-r", "trustRoot", "-p", "ssl",
                "-k", loginKeychain, certURL.path,
            ]
            process.standardOutput = Pipe()
            process.standardError = Pipe()
            process.terminationHandler = { finished in
                continuation.resume(returning: finished.terminationStatus == 0)
            }
            do {
                try process.run()
            } catch {
                continuation.resume(returning: false)
            }
        }
    }
}
