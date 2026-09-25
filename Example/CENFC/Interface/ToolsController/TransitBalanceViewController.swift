import ConfigurableKit
import CoreExtendedNFC
import SPIndicator
import SnapKit
import Then
import UIKit

class TransitBalanceViewController: StackScrollController {
    private let dateFormatter = DateFormatter().then {
        $0.dateStyle = .medium
        $0.timeStyle = .none
    }

    private let singaporeDateFormatter = DateFormatter().then {
        $0.dateStyle = .medium
        $0.timeStyle = .medium
        $0.timeZone = TimeZone(secondsFromGMT: 8 * 60 * 60)
    }

    private var resultSentinel = UIView()

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never
        enableExtendedEdge()
    }

    override func setupContentViews() {
        super.setupContentViews()

        addSectionHeader(String(localized: "Transit Balance"))
        buildScanButton(title: String(localized: "Scan Transit Card"), action: #selector(scanTapped))
        addSectionFooter(String(localized: "Supports Japan IC (Suica, PASMO, ICOCA…), Korea T-Money/Cashbee, China T-Union."))

        buildScanButton(title: String(localized: "Test Singapore EZ-Link / CEPAS"), action: #selector(singaporeScanTapped))
        addSectionFooter(
            String(localized: "Experimental; iOS card testing pending. Reads traditional EZ-Link/CEPAS only. SimplyGo history is not supported. Export Logs after testing."))

        stackView.addArrangedSubview(resultSentinel)
    }

    // MARK: - Scan Button

    private func buildScanButton(title: String, action: Selector) {
        let button = UIButton(type: .system).then {
            $0.setTitle(title, for: .normal)
            $0.titleLabel?.font = .preferredFont(forTextStyle: .headline)
            $0.addTarget(self, action: action, for: .touchUpInside)
        }

        stackView.addArrangedSubviewWithMargin(button)
    }

    @objc private func scanTapped() {
        performScan()
    }

    @objc private func singaporeScanTapped() {
        performScan(singapore: true)
    }

    // MARK: - NFC Scan

    private func performScan(singapore: Bool = false) {
        Task {
            let manager = NFCSessionManager()
            if singapore {
                AppLogStore.shared.info("Starting experimental Singapore CEPAS scan", source: "Singapore")
            }
            do {
                let (coarseInfo, transport) = try await manager.scan(for: singapore ? [.iso14443] : [.all])
                let balance: TransitBalance
                if singapore {
                    AppLogStore.shared.info("Detected tag; initial AID=\(coarseInfo.initialSelectedAID ?? "none")", source: "Singapore")
                    guard let iso7816 = transport as? any ISO7816TagTransporting else {
                        throw NFCError.unsupportedOperation(String(localized: "This card was not detected as a compatible Singapore CEPAS card."))
                    }
                    // CEPAS uses its default application; refinement may select another application.
                    manager.setAlertMessage(String(localized: "Reading..."))
                    balance = try await CoreExtendedNFC.readSingaporeTransitBalance(transport: iso7816)
                    AppLogStore.shared.info(
                        "Read succeeded: balance=\(balance.balanceRaw) \(balance.currencyCode), transactions=\(balance.transactions.count)",
                        source: "Singapore"
                    )
                } else {
                    let refinedInfo = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)
                    manager.setAlertMessage(String(localized: "Reading..."))
                    balance = try await CoreExtendedNFC.readTransitBalance(info: refinedInfo, transport: transport)
                }
                manager.setAlertMessage(String(localized: "Done"))
                manager.invalidate()

                displayResults(balance)
            } catch is CancellationError {
                manager.invalidate()
                if singapore {
                    AppLogStore.shared.info("Singapore CEPAS scan cancelled", source: "Singapore")
                }
                return
            } catch {
                manager.invalidate()
                if singapore {
                    AppLogStore.shared.error("Singapore CEPAS scan failed: \(error)", source: "Singapore")
                }
                if !presentNFCErrorAlertIfNeeded(for: error) {
                    presentErrorAlert(for: error)
                }
            }
        }
    }

    // MARK: - Display Results

    private func displayResults(_ balance: TransitBalance) {
        dateFormatter.timeZone = balance.currencyCode == "SGD" ? TimeZone(secondsFromGMT: 8 * 60 * 60) : .current
        clearResults()

        // Card Info
        addSectionHeader(String(localized: "Card Info"))

        addInfoRow(
            icon: "creditcard",
            title: String(localized: "Card"),
            value: balance.cardName
        )

        if !balance.serialNumber.isEmpty {
            addInfoRow(
                icon: "number",
                title: String(localized: "Serial Number"),
                value: balance.serialNumber
            )
        }

        if let validFrom = balance.validFrom {
            addInfoRow(
                icon: "calendar",
                title: String(localized: "Valid From"),
                value: dateFormatter.string(from: validFrom)
            )
        }

        if let validUntil = balance.validUntil {
            addInfoRow(
                icon: "calendar.badge.clock",
                title: String(localized: "Valid Until"),
                value: dateFormatter.string(from: validUntil)
            )
        }

        // Balance
        addSectionHeader(String(localized: "Balance"))

        addInfoRow(
            icon: "banknote",
            title: String(localized: "Balance"),
            value: balance.formattedBalance
        )

        addInfoRow(
            icon: "info.circle",
            title: String(localized: "Raw"),
            value: "\(balance.balanceRaw) \(balance.currencyCode)"
        )

        // Transaction History
        if !balance.transactions.isEmpty {
            addSectionHeader(String(localized: "Transaction History"))

            for (index, tx) in balance.transactions.enumerated() {
                let typeLabel =
                    switch tx.type {
                    case .trip: String(localized: "Trip")
                    case .topup: String(localized: "Top-up")
                    case .purchase: String(localized: "Purchase")
                    case .unknown: String(localized: "Unknown")
                    }

                var details = [typeLabel]
                if let date = tx.date {
                    if balance.currencyCode == "SGD" {
                        details.append(String(localized: "\(singaporeDateFormatter.string(from: date)) (Singapore time)"))
                    } else {
                        details.append(dateFormatter.string(from: date))
                    }
                }
                if let entry = tx.entryStation {
                    details.append(String(localized: "Entry: \(entry)"))
                }
                if let exit = tx.exitStation {
                    details.append(String(localized: "Exit: \(exit)"))
                }
                if let route = tx.metadata["busRoute"] {
                    details.append(String(localized: "Bus: \(route)"))
                }

                let value: String
                if balance.currencyCode == "SGD", let change = tx.metadata["balanceChange"] {
                    value = String(localized: "\(change) SGD cents")
                } else {
                    value = tx.balanceAfter.map { "\(tx.amount) → \($0)" } ?? "\(tx.amount)"
                }
                addInfoRow(
                    icon: tx.type == .topup ? "plus.circle" : "arrow.right.circle",
                    title: "#\(index + 1)",
                    description: details.joined(separator: " · "),
                    value: value
                )
            }

            addSectionFooter(String(localized: "\(balance.transactions.count) transaction(s)"))
        }
    }

    private func clearResults() {
        if let idx = stackView.arrangedSubviews.firstIndex(of: resultSentinel) {
            let toRemove = stackView.arrangedSubviews.suffix(from: idx + 1)
            for view in toRemove {
                view.removeFromSuperview()
            }
        }
    }

    // MARK: - Error Handling

    private func presentErrorAlert(for error: Error) {
        let alert = UIAlertController(
            title: String(localized: "Error"),
            message: String(describing: error),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
        present(alert, animated: true)
    }
}
