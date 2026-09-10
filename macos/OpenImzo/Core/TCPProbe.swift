import Darwin
import Foundation

/// Whether something is already listening on a loopback TCP port.
///
/// Used by `MacPlatform.isLegacyClientRunning()` to check the original
/// E-IMZO's two production ports independently of finding its process by
/// bundle identifier — a listener can be up for a moment after the process
/// that owns it has already been killed, or vice versa while it is still
/// starting, so neither signal alone is trustworthy on its own.
///
/// The socket is put in non-blocking mode and bounded with `poll` rather
/// than left to a plain blocking `connect`, since this backs a synchronous
/// protocol method the core calls immediately before its own bind attempt:
/// a hang here would delay that bind, not merely this answer.
enum TCPProbe {
    static func isListening(port: UInt16, host: String = "127.0.0.1", timeoutMs: Int32 = 300) -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        let existingFlags = fcntl(sock, F_GETFL, 0)
        guard existingFlags != -1, fcntl(sock, F_SETFL, existingFlags | O_NONBLOCK) != -1 else {
            return false
        }

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr(host)

        let connectResult = withUnsafePointer(to: &address) { addressPointer -> Int32 in
            addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                connect(sock, rebound, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if connectResult == 0 {
            return true
        }
        guard errno == EINPROGRESS else {
            return false
        }

        var pollTarget = pollfd(fd: sock, events: Int16(POLLOUT), revents: 0)
        guard poll(&pollTarget, 1, timeoutMs) > 0, pollTarget.revents & Int16(POLLOUT) != 0 else {
            return false
        }

        var socketError: Int32 = 0
        var errorLength = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(sock, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) == 0 else {
            return false
        }
        return socketError == 0
    }
}
