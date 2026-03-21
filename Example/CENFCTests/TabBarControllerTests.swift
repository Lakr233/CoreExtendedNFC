@testable import CENFC
import Foundation
import Testing
import UIKit

@MainActor
struct TabBarControllerTests {
    @Test("Tab bar exposes stable tabs and automation identifiers")
    func tabBarConfiguration() throws {
        let controller = TabBarController()
        controller.loadViewIfNeeded()

        let viewControllers = try #require(controller.viewControllers)
        let navigationControllers = try #require(viewControllers as? [UINavigationController])

        #expect(controller.tabBar.accessibilityIdentifier == "main.tabbar")
        #expect(navigationControllers.count == 5)
        #expect(navigationControllers.map(\.tabBarItem.accessibilityIdentifier) == [
            "tab.scanner",
            "tab.dump",
            "tab.ndef",
            "tab.passport",
            "tab.tools",
        ])
        #expect(navigationControllers.map(\.navigationBar.accessibilityIdentifier) == [
            "nav.scanner",
            "nav.dump",
            "nav.ndef",
            "nav.passport",
            "nav.tools",
        ])
        #expect(navigationControllers.compactMap { $0.topViewController?.title } == [
            "Scanner",
            "Dump",
            "NDEF",
            "Passport",
            "Tools",
        ])
    }
}
