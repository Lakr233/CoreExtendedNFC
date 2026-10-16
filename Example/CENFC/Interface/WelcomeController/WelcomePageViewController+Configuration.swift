//
//  WelcomePageViewController+Configuration.swift
//  CENFC
//

import UIKit

extension WelcomePageViewController {
    struct Configuration {
        var icon: UIImage?
        var title: String
        var highlightedTitle: String
        var subtitle: String
        var buttonTitle: String
        var accentColor: UIColor
        var features: [Feature]
    }

    struct Feature {
        var icon: UIImage
        var title: String
        var detail: String
    }
}

extension WelcomePageViewController.Configuration {
    static var `default`: Self {
        let displayName = Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            ?? Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String
            ?? "CENFC"

        var appIcon: UIImage?
        if let icons = Bundle.main.infoDictionary?["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String],
           let name = files.last
        {
            appIcon = UIImage(named: name)
        }

        return .init(
            icon: appIcon,
            title: String(localized: "Welcome to"),
            highlightedTitle: displayName,
            subtitle: String(localized: "An advanced NFC toolkit for iOS. Scan, identify, dump, and analyze NFC tags — all processed locally on your device."),
            buttonTitle: String(localized: "Get Started"),
            accentColor: AppTheme.accent,
            features: [
                // MARK: - Scanning & Identification

                .init(
                    icon: UIImage(systemName: "sensor.tag.radiowaves.forward.fill")!,
                    title: String(localized: "Tag Scanning"),
                    detail: String(localized: "Identify NFC tags via ATQA/SAK lookup. Supports ISO 14443, FeliCa, and ISO 15693.")
                ),
                .init(
                    icon: UIImage(systemName: "cpu.fill")!,
                    title: String(localized: "Chip Fingerprinting"),
                    detail: String(localized: "Detect precise chip variants — NTAG, Ultralight, DESFire, MIFARE Classic, and more.")
                ),

                // MARK: - Memory & Data

                .init(
                    icon: UIImage(systemName: "internaldrive.fill")!,
                    title: String(localized: "Memory Dump"),
                    detail: String(localized: "Read full card memory with page/block detail. Export as hex, JSON, or binary.")
                ),
                .init(
                    icon: UIImage(systemName: "doc.text.fill")!,
                    title: String(localized: "NDEF Read & Write"),
                    detail: String(localized: "Create, read, and write NDEF records — text, URI, smart poster, MIME, and external types.")
                ),

                // MARK: - Passport

                .init(
                    icon: UIImage(systemName: "person.text.rectangle.fill")!,
                    title: String(localized: "Passport Reading"),
                    detail: String(localized: "Read eMRTD chips with BAC authentication. View MRZ data, photo, and security report.")
                ),
                .init(
                    icon: UIImage(systemName: "checkmark.shield.fill")!,
                    title: String(localized: "Security Verification"),
                    detail: String(localized: "Passive and Active Authentication verify data integrity and chip authenticity.")
                ),

                // MARK: - Tools

                .init(
                    icon: UIImage(systemName: "wrench.and.screwdriver.fill")!,
                    title: String(localized: "Protocol Tools"),
                    detail: String(localized: "CRC calculator, hex converter, ATQA/SAK lookup, access bits decoder, and BER-TLV parser.")
                ),
                .init(
                    icon: UIImage(systemName: "list.bullet.rectangle.fill")!,
                    title: String(localized: "Protocol Logging"),
                    detail: String(localized: "Full protocol trace for every NFC session. Share logs for debugging and analysis.")
                ),

                // MARK: - Privacy & Files

                .init(
                    icon: UIImage(systemName: "lock.fill")!,
                    title: String(localized: "Offline & Private"),
                    detail: String(localized: "All data stays on your device. No network, no cloud, no tracking.")
                ),
                .init(
                    icon: UIImage(systemName: "square.and.arrow.up.fill")!,
                    title: String(localized: "Import & Export"),
                    detail: String(localized: "Share scan records, dumps, and passport data as portable files.")
                ),
            ]
        )
    }
}
