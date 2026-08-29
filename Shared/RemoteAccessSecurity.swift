import Foundation
import Security

/// Pairing-secret storage and validation shared by the Mac and iOS targets.
/// The two apps have separate keychains; the user copies the receiver's code
/// to the Mac once, then both sides retain it outside UserDefaults and logs.
enum RemoteAccessSecurity {
    private static let service = "com.opendisp.remote-access"
    private static let receiverAccount = "receiver-token"
    private static let macAccount = "mac-token"
    private static let tokenByteCount = 20
    private static let tokenCharacterCount = tokenByteCount * 2

    static func receiverToken() -> String {
        if let existing = read(account: receiverAccount), isValid(existing) {
            return normalized(existing)
        }
        var bytes = [UInt8](repeating: 0, count: tokenByteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            preconditionFailure("Unable to generate remote-access credential")
        }
        let token = bytes.map { String(format: "%02X", $0) }.joined()
        write(token, account: receiverAccount)
        return token
    }

    static func regenerateReceiverToken() -> String {
        delete(account: receiverAccount)
        return receiverToken()
    }

    static func macToken() -> String {
        normalized(read(account: macAccount) ?? "")
    }

    static func saveMacToken(_ token: String) {
        let value = normalized(token)
        if value.isEmpty { delete(account: macAccount) }
        else { write(value, account: macAccount) }
    }

    static func normalized(_ token: String) -> String {
        let allowed = Set("0123456789ABCDEF")
        return token.uppercased().filter { allowed.contains($0) }
    }

    static func formatted(_ token: String) -> String {
        let value = normalized(token)
        return stride(from: 0, to: value.count, by: 5).map { start in
            let lower = value.index(value.startIndex, offsetBy: start)
            let upper = value.index(lower, offsetBy: min(5, value.count - start))
            return String(value[lower..<upper])
        }.joined(separator: "-")
    }

    static func isValid(_ token: String) -> Bool {
        normalized(token).count == tokenCharacterCount
    }

    /// Avoids leaking how many prefix bytes matched through early-return timing.
    static func timingSafeEqual(_ lhs: String, _ rhs: String) -> Bool {
        let a = Array(normalized(lhs).utf8)
        let b = Array(normalized(rhs).utf8)
        var difference = UInt8(truncatingIfNeeded: a.count ^ b.count)
        let count = max(a.count, b.count)
        for index in 0..<count {
            let av = index < a.count ? a[index] : 0
            let bv = index < b.count ? b[index] : 0
            difference |= av ^ bv
        }
        return difference == 0
    }

    /// `NWEndpoint` descriptions include brackets/ports, so search bounded
    /// address tokens rather than assuming one presentation format.
    static func isTailnetPeer(_ endpointDescription: String) -> Bool {
        let lower = endpointDescription.lowercased()
        if lower.contains("fd7a:115c:a1e0:") { return true }
        let parts = lower.split { !$0.isNumber && $0 != "." }
        for part in parts {
            let octets = part.split(separator: ".").compactMap { Int($0) }
            if octets.count == 4, octets[0] == 100, (64...127).contains(octets[1]) {
                return true
            }
        }
        return false
    }

    private static func read(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func write(_ value: String, account: String) {
        let key: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(key as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = key
            attributes.forEach { item[$0.key] = $0.value }
            SecItemAdd(item as CFDictionary, nil)
        }
    }

    private static func delete(account: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ] as CFDictionary)
    }
}
