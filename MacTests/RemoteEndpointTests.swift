import XCTest

final class RemoteEndpointTests: XCTestCase {
    func testAcceptsTailscaleIPv4Range() {
        XCTAssertTrue(RemoteEndpointValidator.isTailnetHost("100.64.0.1"))
        XCTAssertTrue(RemoteEndpointValidator.isTailnetHost("100.127.255.254"))
        XCTAssertFalse(RemoteEndpointValidator.isTailnetHost("100.63.255.255"))
        XCTAssertFalse(RemoteEndpointValidator.isTailnetHost("100.128.0.1"))
    }

    func testAcceptsTailscaleIPv6AndFullMagicDNSNames() {
        XCTAssertTrue(RemoteEndpointValidator.isTailnetHost("fd7a:115c:a1e0::1"))
        XCTAssertTrue(RemoteEndpointValidator.isTailnetHost("iphone.example-tailnet.ts.net"))
        XCTAssertTrue(RemoteEndpointValidator.isTailnetHost(" IPAD.EXAMPLE.TS.NET. "))
    }

    func testRejectsPublicAndLocalEndpoints() {
        XCTAssertFalse(RemoteEndpointValidator.isTailnetHost("8.8.8.8"))
        XCTAssertFalse(RemoteEndpointValidator.isTailnetHost("192.168.1.10"))
        XCTAssertFalse(RemoteEndpointValidator.isTailnetHost("localhost"))
        XCTAssertFalse(RemoteEndpointValidator.isTailnetHost("example.com"))
        XCTAssertFalse(RemoteEndpointValidator.isTailnetHost(""))
    }
}
