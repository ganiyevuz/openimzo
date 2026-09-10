import AppKit
import Darwin
import Foundation

/// The real macOS implementation of the generated `Platform` protocol,
/// replacing `InterimPlatform`.
///
/// Named `MacPlatform` rather than the brief's suggested `PlatformImpl`
/// deliberately: uniffi's own generated bindings (`macos/Generated/eimzo.swift`)
/// already declare `open class PlatformImpl: Platform` as its FFI wrapper for
/// the trait (the type `FfiConverterTypePlatform.lift` produces from a raw
/// Rust pointer), so that exact name is reserved and would fail to compile
/// as a redeclaration — the same reason the previous task's stand-ins are
/// `InterimPlatform`/`InterimUiDelegate` rather than `...Impl`.
final class MacPlatform: Platform {
    func appSupportDir() -> String {
        AppDirectories.appSupportDirectory().path
    }

    func logsDir() -> String {
        AppDirectories.logsDirectory().path
    }

    /// `/Volumes`, plus whatever folders the person has added via
    /// `UserSettings.extraKeyFolders` — empty until a folder-management
    /// screen exists to populate it, which turns this into exactly
    /// `["/Volumes"]`, matching the brief. The core treats this method's
    /// first entry as the volumes root and every further one as an extra
    /// folder (`build_discovery` in `crates/eimzo-ffi/src/engine.rs`), so
    /// `/Volumes` must stay first.
    func volumesRoots() -> [String] {
        ["/Volumes"] + UserSettings.extraKeyFolders
    }

    /// True if either independent signal says the original still holds the
    /// ports: a running process with its bundle identifier, or a listener
    /// already on one of its two production ports. Neither check alone is
    /// reliable — the process can be running with a listener not yet (or no
    /// longer) bound, and a listener can briefly outlive the process during
    /// shutdown — so both are checked and combined with OR.
    ///
    /// This deliberately never gates or skips the bind that follows this
    /// call in the core (`Engine::start`): it only lets a bind failure that
    /// already happened be reported as "the original is running" instead of
    /// a bare port conflict. Short-circuiting the bind on this answer was
    /// tried and reverted before this task — see the phase 3 task 2 report.
    func isLegacyClientRunning() -> Bool {
        isLegacyClientProcessRunning() || isLegacyPortOpen()
    }

    /// Not `private`: `FirstRunFlow`'s own original-detection step calls this directly instead
    /// of `isLegacyClientRunning()` — confirmed by actually running the app, this method's own
    /// port-probe half answers a question that is only meaningful before this app's *own* engine
    /// has bound the production ports, which by first run has usually already happened (`CoreEngine
    /// .init()` starts the engine, in production mode, at launch — independently of and typically
    /// before the person ever reaches this step). Once that bind has succeeded, the port being
    /// occupied no longer distinguishes the original from this app's own listener, and
    /// `isLegacyClientRunning()` reports a false "yes, running" for a person who has never even
    /// installed the original. The bundle-identifier check alone is exactly what first run needs
    /// — "is the original itself a running process I could quit" — where `isLegacyClientRunning
    /// ()`'s own use (explaining one of *this* engine's own bind failures, from inside `Engine
    /// ::start`, before this app's own bind is attempted) needs the broader, less precise
    /// combined signal instead.
    func isLegacyClientProcessRunning() -> Bool {
        NSWorkspace.shared.runningApplications.contains { $0.bundleIdentifier == Self.legacyBundleIdentifier }
    }

    private func isLegacyPortOpen() -> Bool {
        legacyPorts.contains { TCPProbe.isListening(port: $0) }
    }

    /// Installs TLS trust into the login keychain for real, by shelling out
    /// to `security add-trusted-cert` (`TrustInstaller`). The System
    /// keychain variant needs an administrator prompt and belongs to a
    /// later phase, so it is answered `false` here rather than attempted.
    func installTlsTrust(certPem: String, systemWide: Bool) async -> Bool {
        guard !systemWide else { return false }
        return await TrustInstaller.installIntoLoginKeychain(certPem: certPem)
    }

    /// The hostname plus every up, non-loopback interface's name and numeric address, gathered
    /// directly with the POSIX `getifaddrs()` call — what `randseed.get`
    /// (`crates/eimzo-rpc/src/plugins/randseed.rs`) packages as this machine's fingerprint,
    /// through `PlatformRandseedProvider` in `crates/eimzo-ffi/src/delegate.rs`. `eimzo-cli`
    /// gathers the same kind of information for the same trait with the `if-addrs`/`hostname`
    /// crates instead, since it has no shell to ask — see that adapter's own doc comment for why
    /// the two are deliberately not the same code. The exact byte layout here is this method's
    /// own: `RandseedProvider::network_description` treats the result as an opaque blob, and nothing
    /// requires it to match the CLI's inner shape, only to carry real, machine-specific bytes.
    func networkDescription() -> Data {
        var lines = [ProcessInfo.processInfo.hostName]
        var addrList: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addrList) == 0, let firstAddr = addrList else {
            return Data(lines.joined(separator: "\n").utf8)
        }
        defer { freeifaddrs(addrList) }

        for cursor in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let flags = cursor.pointee.ifa_flags
            guard flags & UInt32(IFF_UP) != 0, flags & UInt32(IFF_LOOPBACK) == 0, let addr = cursor.pointee.ifa_addr
            else { continue }
            let family = addr.pointee.sa_family
            guard family == sa_family_t(AF_INET) || family == sa_family_t(AF_INET6) else { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let addrLength =
                family == sa_family_t(AF_INET)
                    ? socklen_t(MemoryLayout<sockaddr_in>.size)
                    : socklen_t(MemoryLayout<sockaddr_in6>.size)
            guard getnameinfo(addr, addrLength, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else {
                continue
            }
            lines.append("\(String(cString: cursor.pointee.ifa_name)): \(String(cString: host))")
        }
        return Data(lines.joined(separator: "\n").utf8)
    }

    /// `static` rather than an instance property, and not `private`: `FirstRunFlow`'s own
    /// original-detection step needs the same identifier — to quit the process and to look up
    /// its installed location for the login-item removal — and reusing this constant is what
    /// keeps the two from ever silently drifting apart.
    static let legacyBundleIdentifier = "uz.yt.eimzo"
    private let legacyPorts: [UInt16] = [64646, 64443]
}
