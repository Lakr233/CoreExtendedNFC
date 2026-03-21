import XCTest

final class CENFCUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testLaunchShowsPrimaryTabs() throws {
        let app = XCUIApplication()
        app.launchEnvironment["CENFC_UI_TESTING"] = "1"
        app.launch()

        let tabBar = app.tabBars["main.tabbar"]
        XCTAssertTrue(tabBar.waitForExistence(timeout: 5))

        let scannerTab = tabBar.buttons["tab.scanner"]
        let dumpTab = tabBar.buttons["tab.dump"]
        let ndefTab = tabBar.buttons["tab.ndef"]
        let passportTab = tabBar.buttons["tab.passport"]
        let toolsTab = tabBar.buttons["tab.tools"]

        XCTAssertTrue(scannerTab.exists)
        XCTAssertTrue(dumpTab.exists)
        XCTAssertTrue(ndefTab.exists)
        XCTAssertTrue(passportTab.exists)
        XCTAssertTrue(toolsTab.exists)

        passportTab.tap()
        XCTAssertTrue(app.navigationBars["nav.passport"].waitForExistence(timeout: 5))

        toolsTab.tap()
        XCTAssertTrue(app.navigationBars["nav.tools"].waitForExistence(timeout: 5))
    }
}
