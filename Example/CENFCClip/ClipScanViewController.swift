import CoreExtendedNFC
import Foundation
import SnapKit
import UIKit

/// The App Clip's first screen: one button that scans a card or tag and opens
/// its details. Nothing is stored.
final class ClipScanViewController: UIViewController {
    private let nfcTask = SingleTaskRunner()

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        title = String(localized: "Scanner")
        view.backgroundColor = .systemBackground

        let icon = UIImageView(image: UIImage(systemName: "sensor.tag.radiowaves.forward"))
        icon.preferredSymbolConfiguration = UIImage.SymbolConfiguration(pointSize: 56, weight: .regular)
        icon.tintColor = .tintColor
        icon.contentMode = .scaleAspectFit
        icon.isAccessibilityElement = false

        var configuration = UIButton.Configuration.filled()
        configuration.title = String(localized: "Scan Card")
        configuration.buttonSize = .large
        configuration.cornerStyle = .large
        let scanButton = UIButton(configuration: configuration, primaryAction: UIAction { [weak self] _ in
            self?.performScan()
        })
        scanButton.accessibilityIdentifier = "clip.scan"

        let stack = UIStackView(arrangedSubviews: [icon, scanButton])
        stack.axis = .vertical
        stack.spacing = 32
        view.addSubview(stack)
        stack.snp.makeConstraints { make in
            make.centerY.equalTo(view.safeAreaLayoutGuide)
            make.top.greaterThanOrEqualTo(view.safeAreaLayoutGuide).offset(16)
            make.bottom.lessThanOrEqualTo(view.safeAreaLayoutGuide).offset(-16)
            make.leading.trailing.equalTo(view.layoutMarginsGuide).inset(16)
        }
    }

    // MARK: - Scan

    private func performScan() {
        nfcTask.run { [weak self] in
            await self?.scan()
        }
    }

    /// The full app's default scan (`ScannerViewController.scan(targets:)`)
    /// without the history: poll every tag family, identify, show.
    private func scan() async {
        let manager = NFCSessionManager()
        do {
            let (coarseInfo, transport) = try await manager.scan(for: [.all])
            let refinedInfo = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)
            manager.setAlertMessage(refinedInfo.type.description)
            manager.invalidate()
            show(ScanRecord(cardInfo: refinedInfo), animated: true)
        } catch {
            manager.invalidate(after: error)
            if !presentNFCErrorAlertIfNeeded(for: error, session: manager) {
                presentErrorAlert(for: error)
            }
        }
    }

    /// Shows `record` as the only screen above this one.
    private func show(_ record: ScanRecord, animated: Bool) {
        navigationController?.setViewControllers(
            [self, ClipCardDetailViewController(record: record)],
            animated: animated
        )
    }

    #if DEBUG
        /// Opens the result screen with made-up card data (see `ClipSceneDelegate.route(_:)`).
        func showDebugSample(named name: String) {
            let info = if name == "felica" {
                CardInfo(
                    type: .felicaStandard,
                    uid: Data([0x01, 0x12, 0x03, 0x12, 0x8A, 0x17, 0x4C, 0x05]),
                    systemCode: Data([0x00, 0x03]),
                    idm: Data([0x01, 0x12, 0x03, 0x12, 0x8A, 0x17, 0x4C, 0x05])
                )
            } else {
                CardInfo(
                    type: .ntag215,
                    uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]),
                    atqa: Data([0x44, 0x00]),
                    sak: 0x00
                )
            }
            show(ScanRecord(cardInfo: info), animated: false)
        }
    #endif
}
