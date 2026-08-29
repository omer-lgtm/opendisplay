import XCTest

final class RemoteAccessSecurityTests: XCTestCase {
    func testNormalizesDisplayedPairingCode() {
        XCTAssertEqual(RemoteAccessSecurity.normalized("01234-56789 abcde"), "0123456789ABCDE")
    }

    func testPairingCodeValidationRequiresEntropy() {
        XCTAssertFalse(RemoteAccessSecurity.isValid("ABC123"))
        XCTAssertTrue(RemoteAccessSecurity.isValid("0123456789ABCDEF0123456789ABCDEF01234567"))
    }

    func testTimingSafeComparisonUsesNormalizedValue() {
        let token = "0123456789ABCDEF0123456789ABCDEF01234567"
        XCTAssertTrue(RemoteAccessSecurity.timingSafeEqual("01234-56789-abcde-f0123-45678-9abcd-ef012-34567", token))
        XCTAssertFalse(RemoteAccessSecurity.timingSafeEqual(token, token + "0"))
        XCTAssertFalse(RemoteAccessSecurity.timingSafeEqual(token, "FEDCBA9876543210FEDCBA9876543210FEDCBA98"))
    }

    func testTailnetPeerDetectionRejectsPublicAndLanAddresses() {
        XCTAssertTrue(RemoteAccessSecurity.isTailnetPeer("100.64.12.9:9000"))
        XCTAssertTrue(RemoteAccessSecurity.isTailnetPeer("[fd7a:115c:a1e0::42]:9000"))
        XCTAssertFalse(RemoteAccessSecurity.isTailnetPeer("192.168.1.20:9000"))
        XCTAssertFalse(RemoteAccessSecurity.isTailnetPeer("8.8.8.8:9000"))
    }
}
