import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import SPIndicator
import Then
import UIKit

class RawCommunicationViewController: StackScrollController {
    private let cardInfo: CardInfo

    init(cardInfo: CardInfo) {
        self.cardInfo = cardInfo
        super.init(nibName: nil, bundle: nil)
        title = String(localized: "Raw Communication")
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError()
    }

    // MARK: - UI Elements

    private lazy var hexInputField = UITextField().then {
        $0.placeholder = "e.g. 30 04"
        $0.borderStyle = .roundedRect
        $0.font = .monospacedSystemFont(ofSize: 16, weight: .regular)
        $0.autocapitalizationType = .allCharacters
        $0.autocorrectionType = .no
        $0.spellCheckingType = .no
        $0.smartQuotesType = .no
        $0.smartDashesType = .no
        $0.smartInsertDeleteType = .no
        $0.clearButtonMode = .whileEditing
        $0.returnKeyType = .send
        $0.delegate = self
        $0.snp.makeConstraints { $0.height.greaterThanOrEqualTo(44) }
    }

    private lazy var sendButton = UIButton(configuration: {
        var config = UIButton.Configuration.filled()
        config.contentInsets = NSDirectionalEdgeInsets(top: 12, leading: 20, bottom: 12, trailing: 20)
        return config
    }()).then {
        $0.setTitle(String(localized: "Send"), for: .normal)
        $0.addTarget(self, action: #selector(sendTapped), for: .touchUpInside)
    }

    private lazy var logTextView = UITextView().then {
        $0.isEditable = false
        $0.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        $0.backgroundColor = .secondarySystemBackground
        $0.layer.cornerRadius = 8
        $0.layer.cornerCurve = .continuous
        $0.textContainerInset = UIEdgeInsets(top: 12, left: 8, bottom: 12, right: 8)
        $0.snp.makeConstraints { $0.height.greaterThanOrEqualTo(200) }
    }

    // MARK: - State

    private var logEntries: [String] = []
    private var isSending = false

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never
        enableExtendedEdge()
        setupCopyButton()
    }

    override func setupContentViews() {
        super.setupContentViews()
        buildCardInfoSection()
        buildInputSection()
        buildLogSection()
    }

    // MARK: - Navigation Bar

    private func setupCopyButton() {
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "doc.on.doc"),
            style: .plain,
            target: self,
            action: #selector(copyLog)
        )
    }

    @objc private func copyLog() {
        guard !logEntries.isEmpty else { return }
        UIPasteboard.general.string = logEntries.joined(separator: "\n")
        SPIndicator.present(
            title: String(localized: "Copied"),
            preset: .done,
            haptic: .success
        )
    }

    // MARK: - Sections

    private func buildCardInfoSection() {
        addSectionHeader(String(localized: "Target Card"))

        addInfoRow(
            icon: "rectangle.badge.checkmark",
            title: String(localized: "Card Type"),
            value: cardInfo.type.description
        )
        addInfoRow(
            icon: "number",
            title: String(localized: "UID"),
            value: cardInfo.uid.hexString
        )

        let mode = communicationMode
        addInfoRow(
            icon: "antenna.radiowaves.left.and.right",
            title: String(localized: "Mode"),
            description: mode.description,
            value: mode.title
        )

        addSectionFooter(String(localized: "Commands will only be sent after verifying the card UID matches."))
    }

    private func buildInputSection() {
        addSectionHeader(String(localized: "Command"))

        stackView.addArrangedSubviewWithMargin(hexInputField)
        stackView.setCustomSpacing(12, after: hexInputField)
        stackView.addArrangedSubviewWithMargin(sendButton)
        stackView.setCustomSpacing(12, after: sendButton)

        addSectionFooter(inputHintText)
    }

    private func buildLogSection() {
        addSectionHeader(String(localized: "Log"))
        stackView.addArrangedSubviewWithMargin(logTextView)
    }

    // MARK: - Communication Mode

    private enum CommunicationMode {
        case rawBytes // MiFare, FeliCa, ISO15693
        case apdu // ISO7816

        var title: String {
            switch self {
            case .rawBytes: String(localized: "Raw Bytes")
            case .apdu: String(localized: "APDU (ISO 7816)")
            }
        }

        var description: String {
            switch self {
            case .rawBytes: String(localized: "Sends raw byte sequence directly to the chip.")
            case .apdu: String(localized: "Parses input as ISO 7816 APDU: CLA INS P1 P2 [Data] [Le].")
            }
        }
    }

    private var communicationMode: CommunicationMode {
        switch cardInfo.type.family {
        case .type4, .passport:
            .apdu
        default:
            .rawBytes
        }
    }

    private var inputHintText: String {
        switch communicationMode {
        case .rawBytes:
            String(localized: "Enter hex bytes separated by spaces. Example: 30 04 (MiFare READ page 4)")
        case .apdu:
            String(localized: "Enter APDU hex: CLA INS P1 P2 [Lc Data...] [Le]. Example: 00 A4 04 00 07 D2760000850101 00")
        }
    }

    // MARK: - Polling Target

    private var pollingTargets: [NFCSessionManager.PollingTarget] {
        switch cardInfo.type.family {
        case .felica:
            [.iso18092]
        case .iso15693:
            [.iso15693]
        default:
            [.iso14443]
        }
    }

    // MARK: - Send

    @objc private func sendTapped() {
        guard !isSending else { return }
        guard let commandData = parseHexInput() else {
            SPIndicator.present(
                title: String(localized: "Invalid Hex"),
                preset: .error,
                haptic: .error
            )
            return
        }

        if communicationMode == .apdu, commandData.count < 4 {
            SPIndicator.present(
                title: String(localized: "APDU Too Short"),
                message: String(localized: "Need at least CLA INS P1 P2"),
                preset: .error,
                haptic: .error
            )
            return
        }

        hexInputField.resignFirstResponder()
        isSending = true
        sendButton.isEnabled = false
        sendButton.configuration?.showsActivityIndicator = true

        Task {
            await performSend(commandData)
            isSending = false
            sendButton.isEnabled = true
            sendButton.configuration?.showsActivityIndicator = false
        }
    }

    private func performSend(_ commandData: Data) async {
        let manager = NFCSessionManager()
        do {
            let (_, transport) = try await manager.scan(
                for: pollingTargets,
                message: String(localized: "Hold your iPhone near the NFC tag")
            )

            // Verify UID
            guard transport.identifier == cardInfo.uid else {
                let expected = cardInfo.uid.hexString
                let got = transport.identifier.hexString
                manager.invalidate(errorMessage: String(localized: "Wrong card detected"))
                appendLog("ERROR: UID mismatch\n  Expected: \(expected)\n  Got:      \(got)")
                return
            }

            manager.setAlertMessage(String(localized: "Sending..."))

            let response: Data
            switch communicationMode {
            case .rawBytes:
                response = try await transport.send(commandData)
            case .apdu:
                let apdu = parseAPDU(commandData)
                let apduResponse = try await transport.sendAPDU(apdu)
                // Combine data + SW1 + SW2
                var fullResponse = apduResponse.data
                fullResponse.append(apduResponse.sw1)
                fullResponse.append(apduResponse.sw2)
                response = fullResponse
            }

            manager.setAlertMessage(String(localized: "Done"))
            manager.invalidate()

            appendLog("TX: \(commandData.hexString)\nRX: \(response.hexString)")

        } catch is CancellationError {
            return
        } catch {
            manager.invalidate()
            if !presentNFCErrorAlertIfNeeded(for: error) {
                appendLog("TX: \(commandData.hexString)\nERROR: \(String(describing: error))")
            }
        }
    }

    // MARK: - APDU Parsing

    private func parseAPDU(_ data: Data) -> CommandAPDU {
        let cla = data[0]
        let ins = data[1]
        let p1 = data[2]
        let p2 = data[3]

        guard data.count > 4 else {
            return CommandAPDU(cla: cla, ins: ins, p1: p1, p2: p2)
        }

        let lc = Int(data[4])

        if lc > 0, data.count >= 5 + lc {
            let apduData = Data(data[5 ..< 5 + lc])
            let le: UInt8? = data.count > 5 + lc ? data[5 + lc] : nil
            return CommandAPDU(cla: cla, ins: ins, p1: p1, p2: p2, data: apduData, le: le)
        }

        // If only 5 bytes total (CLA INS P1 P2 Le)
        return CommandAPDU(cla: cla, ins: ins, p1: p1, p2: p2, le: data[4])
    }

    // MARK: - Hex Parsing

    private func parseHexInput() -> Data? {
        let text = hexInputField.text?.trimmingCharacters(in: .whitespaces) ?? ""
        guard !text.isEmpty else { return nil }

        // Remove all whitespace, then parse pairs
        let cleaned = text.replacingOccurrences(of: " ", with: "")
        guard cleaned.count.isMultiple(of: 2) else { return nil }

        var data = Data()
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let nextIndex = cleaned.index(index, offsetBy: 2)
            let byteString = String(cleaned[index ..< nextIndex])
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }

        return data.isEmpty ? nil : data
    }

    // MARK: - Log

    private func appendLog(_ entry: String) {
        let timestamp = DateFormatter().then {
            $0.dateFormat = "HH:mm:ss"
        }.string(from: Date())

        let formatted = "[\(timestamp)] \(entry)"
        logEntries.append(formatted)
        logTextView.text = logEntries.joined(separator: "\n\n")

        // Scroll to bottom
        let range = NSRange(location: logTextView.text.count - 1, length: 1)
        logTextView.scrollRangeToVisible(range)
    }
}

// MARK: - UITextFieldDelegate

extension RawCommunicationViewController: UITextFieldDelegate {
    func textFieldShouldReturn(_: UITextField) -> Bool {
        sendTapped()
        return true
    }
}
