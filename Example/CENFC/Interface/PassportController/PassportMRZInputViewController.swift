import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import Then
import UIKit

class PassportMRZInputViewController: StackScrollController {
    var onPassportRead: ((PassportRecord) -> Void)?

    private lazy var documentNumberField: UITextField = makeTextField(
        placeholder: String(localized: "e.g. AA0000000"),
        keyboardType: .asciiCapable
    )

    private lazy var dobPicker: UIDatePicker = makeDatePicker()
    private lazy var expiryPicker: UIDatePicker = makeDatePicker()

    private let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyMMdd"
        return f
    }()

    init() {
        super.init(nibName: nil, bundle: nil)
        title = String(localized: "Passport Info")
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError()
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never
        enableExtendedEdge()

        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "sensor.tag.radiowaves.forward"),
            style: .plain,
            target: self,
            action: #selector(scanTapped)
        )
    }

    override func setupContentViews() {
        super.setupContentViews()

        addSectionHeader(String(localized: "Document Number"))
        stackView.addArrangedSubviewWithMargin(documentNumberField) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionHeader(String(localized: "Date of Birth"))
        stackView.addArrangedSubviewWithMargin(dobPicker) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionHeader(String(localized: "Date of Expiry"))
        stackView.addArrangedSubviewWithMargin(expiryPicker) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionFooter(String(localized: "Enter the document number, date of birth, and date of expiry from the MRZ (Machine Readable Zone) on your passport. These are used for BAC (Basic Access Control) authentication with the chip."))
    }

    // MARK: - Scan

    @objc private func scanTapped() {
        guard validateInput() else { return }

        let docNumber = documentNumberField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let dobString = dateFormatter.string(from: dobPicker.date)
        let doeString = dateFormatter.string(from: expiryPicker.date)

        let mrzKey = MRZKeyGenerator.computeMRZKey(
            documentNumber: docNumber,
            dateOfBirth: dobString,
            dateOfExpiry: doeString
        )

        view.endEditing(true)
        navigationItem.rightBarButtonItem?.isEnabled = false

        Task {
            do {
                let passport = try await CoreExtendedNFC.readPassport(
                    mrzKey: mrzKey,
                    dataGroups: [.com, .dg1, .dg2, .dg7, .dg11, .dg12, .dg14, .dg15, .sod],
                    performActiveAuth: true,
                    message: String(localized: "Hold your iPhone near your passport")
                )
                let record = PassportRecord(from: passport)
                onPassportRead?(record)
            } catch is CancellationError {
                navigationItem.rightBarButtonItem?.isEnabled = true
                return
            } catch {
                navigationItem.rightBarButtonItem?.isEnabled = true
                if !presentNFCErrorAlertIfNeeded(for: error) {
                    presentErrorAlert(for: error)
                }
            }
        }
    }

    private func validateInput() -> Bool {
        let docNumber = documentNumberField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if docNumber.isEmpty {
            presentValidationAlert(String(localized: "Please enter the document number."))
            return false
        }
        return true
    }

    private func presentValidationAlert(_ message: String) {
        let alert = UIAlertController(
            title: String(localized: "Missing Information"),
            message: message,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
        present(alert, animated: true)
    }

    private func presentErrorAlert(for error: Error) {
        let alert = UIAlertController(
            title: String(localized: "Passport Read Failed"),
            message: String(describing: error),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
        present(alert, animated: true)
    }

    // MARK: - UI Helpers

    private func makeTextField(
        placeholder: String,
        keyboardType: UIKeyboardType = .default
    ) -> UITextField {
        UITextField().then {
            $0.placeholder = placeholder
            $0.borderStyle = .roundedRect
            $0.font = .monospacedSystemFont(ofSize: 16, weight: .regular)
            $0.keyboardType = keyboardType
            $0.autocapitalizationType = .allCharacters
            $0.autocorrectionType = .no
            $0.spellCheckingType = .no
            $0.smartQuotesType = .no
            $0.smartDashesType = .no
            $0.smartInsertDeleteType = .no
            $0.clearButtonMode = .whileEditing
            $0.snp.makeConstraints { $0.height.greaterThanOrEqualTo(44) }
        }
    }

    private func makeDatePicker() -> UIDatePicker {
        UIDatePicker().then {
            $0.datePickerMode = .date
            $0.preferredDatePickerStyle = .compact
        }
    }
}
