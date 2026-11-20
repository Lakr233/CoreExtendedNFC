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
        $0.timeZone = TimeZone(identifier: "Asia/Singapore")
    }

    private var resultSentinel = UIView()
    private let scanTask = SingleTaskRunner()

    /// The time zone the card's readers record dates in.
    ///
    /// The library builds dates at local midnight in the issuing region, so they
    /// must be shown in that zone or users west of it see the previous day.
    nonisolated static func cardTimeZone(forCurrency currencyCode: String) -> TimeZone {
        let identifier: String? = switch currencyCode {
        case "JPY": "Asia/Tokyo"
        case "KRW": "Asia/Seoul"
        case "CNY": "Asia/Shanghai"
        case "HKD": "Asia/Hong_Kong"
        case "SGD": "Asia/Singapore"
        case "TWD": "Asia/Taipei"
        case "NZD": "Pacific/Auckland"
        default: nil
        }
        return identifier.flatMap(TimeZone.init(identifier:)) ?? .current
    }

    /// Formats a signed amount stored in the currency's minor unit
    /// (yen, won, fen, cents), matching ``TransitBalance/formattedBalance``.
    nonisolated static func formatAmount(minorUnits: Int, currencyCode: String) -> String {
        let sign = minorUnits < 0 ? "−" : ""
        let magnitude = minorUnits.magnitude
        let major = Double(magnitude) / 100
        let body = switch currencyCode {
        case "JPY": "¥\(magnitude)"
        case "KRW": "₩\(magnitude)"
        case "TWD": "NT$\(magnitude)"
        case "CNY": String(format: "¥%.2f", major)
        case "HKD": String(format: "HK$%.2f", major)
        case "SGD": String(format: "S$%.2f", major)
        case "NZD": String(format: "NZ$%.2f", major)
        default: "\(magnitude) \(currencyCode)"
        }
        return sign + body
    }

    /// Formats a transaction's amount with the direction it moved the balance.
    ///
    /// ``TransitTransaction/amount`` is an unsigned magnitude for every reader, so
    /// the sign comes from the transaction: "−" for trips and purchases, "+" for
    /// top-ups. CEPAS records the signed balance change, which wins when present.
    nonisolated static func formatTransactionAmount(_ transaction: TransitTransaction, currencyCode: String) -> String? {
        guard let amount = transaction.amount else { return nil }
        let body = formatAmount(minorUnits: Int(amount.magnitude), currencyCode: currencyCode)
        let sign: String
        if let change = transaction.metadata["balanceChange"].flatMap(Int.init) {
            sign = change < 0 ? "−" : change > 0 ? "+" : ""
        } else {
            sign = switch transaction.type {
            case .trip, .purchase: "−"
            case .topup: "+"
            case .unknown: ""
            }
        }
        return sign + body
    }

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
        buildScanButton()
        addSectionFooter(
            String(
                localized:
                    "Supports Japan IC (Suica, PASMO, ICOCA…), Japanese e-money (Rakuten Edy, WAON, nanaco), Hong Kong Octopus, Korea T-Money/Cashbee, China T-Union, and traditional Singapore EZ-Link/CEPAS. SimplyGo history is not supported."
            ))

        stackView.addArrangedSubview(resultSentinel)
    }

    // MARK: - Scan Button

    private func buildScanButton() {
        let button = UIButton(type: .system).then {
            $0.setTitle(String(localized: "Scan Transit Card"), for: .normal)
            $0.titleLabel?.font = .preferredFont(forTextStyle: .headline)
            $0.addTarget(self, action: #selector(scanTapped), for: .touchUpInside)
        }

        stackView.addArrangedSubviewWithMargin(button)
    }

    @objc private func scanTapped() {
        performScan()
    }

    // MARK: - NFC Scan

    /// The log line for a successful read. The log is kept and can be exported,
    /// so it names the card type and transaction count but never the balance
    /// or transaction amounts.
    nonisolated static func readSucceededLogMessage(for balance: TransitBalance) -> String {
        "Read succeeded: card=\(balance.cardName), transactions=\(balance.transactions.count)"
    }

    private func performScan() {
        scanTask.run { [weak self] in
            await self?.scanCard()
        }
    }

    private func scanCard() async {
        let manager = NFCSessionManager()
        AppLogStore.shared.info("Starting transit card scan", source: "Transit")
        do {
            do {
                let (info, transport) = try await manager.scan(for: [.all])
                AppLogStore.shared.info("Detected tag; initial AID=\(info.initialSelectedAID ?? "none")", source: "Transit")
                // Transit detection must run before refinement changes the selected application.
                manager.setAlertMessage(String(localized: "Reading Card…"))
                let balance = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)
                AppLogStore.shared.info(Self.readSucceededLogMessage(for: balance), source: "Transit")
                manager.setAlertMessage(String(localized: "Done"))
                manager.invalidate()

                displayResults(balance)
            } catch {
                manager.invalidate(after: error)
                guard !NFCErrorMessage.isCancellation(error, session: manager) else {
                    AppLogStore.shared.info("Transit card scan cancelled", source: "Transit")
                    return
                }
                AppLogStore.shared.error("Transit card scan failed: \(error)", source: "Transit")
                if !presentNFCErrorAlertIfNeeded(for: error, session: manager) {
                    presentErrorAlert(for: error)
                }
            }
        }
    }

    // MARK: - Display Results

    func displayResults(_ balance: TransitBalance) {
        dateFormatter.timeZone = Self.cardTimeZone(forCurrency: balance.currencyCode)
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
            value: balance.formattedBalance,
            wrapValue: true
        )

        addInfoRow(
            icon: "info.circle",
            title: String(localized: "Raw"),
            value: balance.currencyCode == "SGD" ? String(localized: "\(String(balance.balanceRaw)) SGD cents") : "\(balance.balanceRaw) \(balance.currencyCode)",
            wrapValue: true
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
                if tx.type == .unknown, let rawType = tx.metadata["transactionType"] {
                    details.append(String(localized: "Type: 0x\(rawType)"))
                }
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
                if tx.amount != nil, let formattedAmount = Self.formatTransactionAmount(tx, currencyCode: balance.currencyCode) {
                    value = tx.balanceAfter.map {
                        "\(formattedAmount) → \(Self.formatAmount(minorUnits: $0, currencyCode: balance.currencyCode))"
                    } ?? formattedAmount
                } else {
                    value = tx.balanceAfter.map {
                        "— → \(Self.formatAmount(minorUnits: $0, currencyCode: balance.currencyCode))"
                    } ?? "—"
                }
                addInfoRow(
                    icon: tx.type == .topup ? "plus.circle" : "arrow.right.circle",
                    title: "#\(index + 1)",
                    description: details.joined(separator: " · "),
                    value: value,
                    wrapValue: true
                )
            }

            addSectionFooter(String(localized: "Transactions: \(balance.transactions.count)"))
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
}
