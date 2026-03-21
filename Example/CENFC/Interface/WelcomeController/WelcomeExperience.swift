//
//  WelcomeExperience.swift
//  CENFC
//

import Foundation

enum WelcomeExperience {
    private static let seenVersionKey = "WelcomeExperience.lastSeenVersion"
    private static let uiTestingEnvironmentKey = "CENFC_UI_TESTING"

    private static var currentVersion: String {
        "1"
    }

    static var shouldPresent: Bool {
        if ProcessInfo.processInfo.environment[uiTestingEnvironmentKey] == "1" {
            return false
        }
        return UserDefaults.standard.string(forKey: seenVersionKey) != currentVersion
    }

    static func markPresented() {
        UserDefaults.standard.set(currentVersion, forKey: seenVersionKey)
    }
}
