import Foundation

/// Accepts only addresses that identify a device inside a Tailscale tailnet.
/// The OpenDisplay wire has no authentication of its own, so a public host
/// must never become a supported remote endpoint by accident.
enum RemoteEndpointValidator {
    static func isTailnetHost(_ rawValue: String) -> Bool {
        let host = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !host.isEmpty else { return false }

        if host.hasSuffix(".ts.net") {
            let name = host.dropLast(".ts.net".count)
            return !name.isEmpty && name.allSatisfy {
                $0.isLetter || $0.isNumber || $0 == "-" || $0 == "."
            }
        }

        if host.hasPrefix("fd7a:115c:a1e0:") { return true }

        let octets = host.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4,
              let first = Int(octets[0]), let second = Int(octets[1]),
              octets.allSatisfy({ part in
                  guard let value = Int(part) else { return false }
                  return value >= 0 && value <= 255
              }) else { return false }

        // Tailscale's IPv4 allocation is the CGNAT range 100.64.0.0/10.
        return first == 100 && (64...127).contains(second)
    }
}
