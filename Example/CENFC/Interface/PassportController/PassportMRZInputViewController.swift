import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import Then
import UIKit

class PassportMRZInputViewController: StackScrollController, PrivacySensitiveScreen, ClosingAwareScreen {
    var onPassportRead: ((PassportRecord) -> Void)?

    private lazy var documentNumberField: UITextField = makeTextField(
        placeholder: String(localized: "e.g. AA0000000"),
        keyboardType: .asciiCapable
    )

    private lazy var dobPicker: UIDatePicker = makeDatePicker()
    private lazy var expiryPicker: UIDatePicker = makeDatePicker()

    private let readTask = SingleTaskRunner()

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
        ).accessibilityLabeled(String(localized: "Read Chip"))
    }

    /// Cancels the chip read when the screen goes away for good: popped, or
    /// removed with its navigation controller from a split view's detail column.
    /// Switching tabs keeps it running.
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        if isLeavingForGood {
            screenWillClose()
        }
    }

    // MARK: - ClosingAwareScreen

    func screenWillClose() {
        readTask.cancel()
    }

    // MARK: - MRZ Fields

    /// Formats a picker date as the MRZ `YYMMDD` field.
    ///
    /// The MRZ always uses Gregorian years, whatever calendar the device is set to
    /// (a Buddhist or Japanese calendar would otherwise produce the wrong year and
    /// a wrong BAC key). The time zone matches the picker, which reports local midnight.
    nonisolated static func mrzDate(_ date: Date, timeZone: TimeZone = .current) -> String {
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = "yyMMdd"
        return formatter.string(from: date)
    }

    /// Normalises a typed document number for the MRZ key: uppercase, no spaces.
    ///
    /// ICAO 9303 check digits only assign values to `0-9`, `A-Z` and `<`, so a
    /// lowercase letter would produce a wrong check digit and BAC would fail.
    nonisolated static func mrzDocumentNumber(_ text: String) -> String {
        text.filter { !$0.isWhitespace }.uppercased()
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

        addSectionFooter(String(localized: "Enter the document number, date of birth, and date of expiry from the machine-readable zone of your passport. They are used to unlock the chip."))
    }

    // MARK: - Scan

    @objc private func scanTapped() {
        guard !readTask.isRunning, validateInput() else { return }

        let docNumber = Self.mrzDocumentNumber(documentNumberField.text ?? "")
        let dobString = Self.mrzDate(dobPicker.date)
        let doeString = Self.mrzDate(expiryPicker.date)

        let mrzKey = MRZKeyGenerator.computeMRZKey(
            documentNumber: docNumber,
            dateOfBirth: dobString,
            dateOfExpiry: doeString
        )

        view.endEditing(true)
        navigationItem.rightBarButtonItem?.isEnabled = false

        readTask.run { [weak self] in
            await self?.readPassport(mrzKey: mrzKey)
        }
    }

    private func readPassport(mrzKey: String) async {
        do {
            let passport = try await CoreExtendedNFC.readPassport(
                mrzKey: mrzKey,
                dataGroups: [.com, .dg1, .dg2, .dg7, .dg11, .dg12, .dg14, .dg15, .sod],
                performActiveAuth: true,
                message: String(localized: "Hold your iPhone near your passport")
            )
            try Task.checkCancellation()
            navigationItem.rightBarButtonItem?.isEnabled = true
            let record = PassportRecord(from: passport)
            onPassportRead?(record)
        } catch {
            navigationItem.rightBarButtonItem?.isEnabled = true
            if !presentNFCErrorAlertIfNeeded(for: error) {
                presentErrorAlert(for: error, title: String(localized: "Unable to Read Passport"))
            }
        }
    }

    private func validateInput() -> Bool {
        let docNumber = Self.mrzDocumentNumber(documentNumberField.text ?? "")
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
        presentQueued(alert)
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
