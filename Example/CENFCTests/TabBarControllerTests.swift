@testable import CENFC
import Foundation
import Testing
import UIKit

@MainActor
struct TabBarControllerTests {
    @Test
    func `Tab bar exposes stable tabs and automation identifiers`() throws {
        let controller = TabBarController()
        controller.loadViewIfNeeded()

        let viewControllers = try #require(controller.viewControllers)
        #expect(controller.tabBar.accessibilityIdentifier == "main.tabbar")
        #expect(viewControllers.count == 5)
        #expect(viewControllers.map(\.tabBarItem.accessibilityIdentifier) == [
            "tab.scanner",
            "tab.dump",
            "tab.ndef",
            "tab.passport",
            "tab.tools",
        ])

        // Scanner, Dump, NDEF and Passport are split views around their list's
        // navigation controller; Tools is a plain navigation controller.
        let splits = viewControllers.prefix(4).compactMap { $0 as? UISplitViewController }
        #expect(splits.count == 4)
        let listNavigations = splits.compactMap(\.recordListNavigationController)
        let tools = try #require(viewControllers.last as? UINavigationController)
        let navigationControllers = listNavigations + [tools]
        #expect(navigationControllers.count == 5)

        #expect(navigationControllers.map(\.navigationBar.accessibilityIdentifier) == [
            "nav.scanner",
            "nav.dump",
            "nav.ndef",
            "nav.passport",
            "nav.tools",
        ])
        let allPreferLargeTitles = navigationControllers.allSatisfy { $0.navigationBar.prefersLargeTitles }
        #expect(allPreferLargeTitles)
        let titles = navigationControllers.compactMap { $0.topViewController?.title }
        #expect(titles.count == 5)
        #expect(titles == [
            String(localized: "Scanner"),
            String(localized: "Dump"),
            String(localized: "NDEF"),
            String(localized: "Passport"),
            String(localized: "Tools"),
        ])
    }

    @Test
    func `List tabs show the record beside the list and start with a placeholder`() throws {
        let controller = TabBarController()
        controller.loadViewIfNeeded()

        let viewControllers = try #require(controller.viewControllers)
        let splits = viewControllers.prefix(4).compactMap { $0 as? UISplitViewController }
        #expect(splits.count == 4)
        for split in splits {
            #expect(split.style == .doubleColumn)
            #expect(split.preferredDisplayMode == .oneBesideSecondary)
            #expect(split.preferredSplitBehavior == .tile)
            // No compact column: UIKit collapses the detail onto the list instead.
            #expect(split.viewController(for: .compact) == nil)
            #expect(split.delegate === controller)
            #expect(split.recordDetailNavigationController?.topViewController is RecordDetailPlaceholderViewController)
            #expect(split.isShowingRecordPlaceholder)
        }
        #expect(splits.map { $0.recordDetailNavigationController?.navigationBar.accessibilityIdentifier } == [
            "nav.scanner.detail",
            "nav.dump.detail",
            "nav.ndef.detail",
            "nav.passport.detail",
        ])
    }

    @Test
    func `Collapsing shows the list while only the placeholder is open`() throws {
        let controller = TabBarController()
        controller.loadViewIfNeeded()
        let split = try #require(controller.viewControllers?.first as? UISplitViewController)

        #expect(controller.splitViewController(split, topColumnForCollapsingToProposedTopColumn: .secondary) == .primary)

        split.showRecordDetailColumn(UIViewController())
        #expect(!split.isShowingRecordPlaceholder)
        #expect(controller.splitViewController(split, topColumnForCollapsingToProposedTopColumn: .secondary) == .secondary)

        split.showRecordPlaceholder()
        #expect(split.isShowingRecordPlaceholder)
    }
}
