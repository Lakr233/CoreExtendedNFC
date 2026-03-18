import ConfigurableKit
import SnapKit
import Then
import UIKit

class ToolsViewController: StackScrollController {
    private struct ToolItem {
        let icon: String
        let title: String
        let subtitle: String
        let viewController: () -> UIViewController
    }

    private let tools: [ToolItem] = [
        ToolItem(
            icon: "arrow.left.arrow.right",
            title: String(localized: "Hex Converter"),
            subtitle: String(localized: "Convert between hex, decimal, binary, ASCII"),
            viewController: { HexConverterViewController() }
        ),
        ToolItem(
            icon: "checkmark.seal",
            title: String(localized: "CRC Calculator"),
            subtitle: String(localized: "Compute CRC_A and CRC_B (ISO 14443-3)"),
            viewController: { CRCCalculatorViewController() }
        ),
        ToolItem(
            icon: "magnifyingglass",
            title: String(localized: "ATQA/SAK Lookup"),
            subtitle: String(localized: "Identify card type from ATQA and SAK"),
            viewController: { ATQASAKLookupViewController() }
        ),
        ToolItem(
            icon: "lock.shield",
            title: String(localized: "Access Bits Decoder"),
            subtitle: String(localized: "Decode MIFARE Classic access permissions"),
            viewController: { AccessBitsDecoderViewController() }
        ),
        ToolItem(
            icon: "list.bullet.indent",
            title: String(localized: "BER-TLV Parser"),
            subtitle: String(localized: "Parse and display TLV tree structure"),
            viewController: { TLVParserViewController() }
        ),
    ]

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        title = String(localized: "Tools")
        enableExtendedEdge()

        let logsButton = UIBarButtonItem(
            image: UIImage(systemName: "doc.text.magnifyingglass"),
            style: .plain,
            target: self,
            action: #selector(openLogs)
        )
        logsButton.menu = UIMenu(children: [
            UIAction(
                title: String(localized: "What's New"),
                image: UIImage(systemName: "sparkles")
            ) { [weak self] _ in
                self?.presentWhatsNew()
            },
            UIMenu(options: .displayInline, children: [
                UIAction(
                    title: String(localized: "Privacy Policy"),
                    image: UIImage(systemName: "lock.shield")
                ) { [weak self] _ in
                    self?.openPrivacyPolicy()
                },
                UIAction(
                    title: String(localized: "Open Source Licenses"),
                    image: UIImage(systemName: "flag.filled.and.flag.crossed")
                ) { [weak self] _ in
                    self?.openOpenSourceLicenses()
                },
            ]),
        ])
        navigationItem.rightBarButtonItem = logsButton
    }

    @objc private func openLogs() {
        let vc = LogsViewController()
        navigationController?.pushViewController(vc, animated: true)
    }

    private func presentWhatsNew() {
        let controller = WelcomePageViewController.makePresentedController()
        present(controller, animated: true)
    }

    private func openPrivacyPolicy() {
        var text = String(localized: "Resource not found, please check your installation.")
        if let url = Bundle.main.url(forResource: "PrivacyPolicy", withExtension: "txt"),
           let content = try? String(contentsOf: url)
        { text = content }
        let vc = TextViewerController(title: String(localized: "Privacy Policy"), text: text)
        navigationController?.pushViewController(vc, animated: true)
    }

    private func openOpenSourceLicenses() {
        var text = String(localized: "Resource not found, please check your installation.")
        if let url = Bundle.main.url(forResource: "OpenSourceLicenses", withExtension: "md"),
           let content = try? String(contentsOf: url)
        { text = content }
        let vc = TextViewerController(title: String(localized: "Open Source Licenses"), text: text)
        navigationController?.pushViewController(vc, animated: true)
    }

    override func setupContentViews() {
        super.setupContentViews()
        buildDisclaimerBanner()
        buildToolsSection()
        buildBuildInfoFooter()
    }

    // MARK: - Disclaimer Banner

    private func buildDisclaimerBanner() {
        let card = UIView().then {
            $0.backgroundColor = .systemOrange.withAlphaComponent(0.12)
            $0.layer.cornerRadius = 12
            $0.layer.cornerCurve = .continuous
        }

        let iconView = UIImageView().then {
            $0.image = UIImage(systemName: "exclamationmark.triangle.fill")
            $0.tintColor = .systemOrange
            $0.contentMode = .scaleAspectFit
            $0.setContentHuggingPriority(.required, for: .horizontal)
        }

        let titleLabel = UILabel().then {
            $0.text = String(localized: "Warning")
            $0.font = .preferredFont(forTextStyle: .headline)
            $0.textColor = .label
        }

        let messageLabel = UILabel().then {
            $0.text = String(localized: "All features in this section are advanced tools that may not have been fully validated. Results are provided as-is — please verify independently before relying on them.")
            $0.font = .preferredFont(forTextStyle: .footnote)
            $0.textColor = .secondaryLabel
            $0.numberOfLines = 0
        }

        let headerStack = UIStackView(arrangedSubviews: [iconView, titleLabel]).then {
            $0.axis = .horizontal
            $0.spacing = 10
            $0.alignment = .center
        }

        let outerStack = UIStackView(arrangedSubviews: [headerStack, messageLabel]).then {
            $0.axis = .vertical
            $0.spacing = 10
        }

        card.addSubview(outerStack)
        outerStack.snp.makeConstraints {
            $0.edges.equalToSuperview().inset(20)
        }

        stackView.addArrangedSubviewWithMargin(card) { $0.top = 8; $0.bottom = 4 }
    }

    // MARK: - Tools Section

    private func buildToolsSection() {
        addSectionHeader(String(localized: "Tools"))

        for tool in tools {
            let pageView = ConfigurablePageView { tool.viewController() }
            pageView.configure(icon: UIImage(systemName: tool.icon))
            pageView.configure(title: String.LocalizationValue(stringLiteral: tool.title))
            pageView.configure(description: String.LocalizationValue(stringLiteral: tool.subtitle))
            stackView.addArrangedSubviewWithMargin(pageView)
            stackView.addArrangedSubview(SeparatorView())
        }

        addSectionFooter(String(localized: "NFC protocol analysis and debugging utilities."))
    }

    // MARK: - Build Info Footer

    private func buildBuildInfoFooter() {
        let version: String = {
            let info = Bundle.main.infoDictionary
            let marketing = info?["CFBundleShortVersionString"] as? String ?? "?"
            let build = info?["CFBundleVersion"] as? String ?? "?"
            return "Version \(marketing) (\(build))"
        }()

        let commitShort = String(BuildInfo.commitID.prefix(7))

        let lines = [
            version,
            BuildInfo.buildTime,
            commitShort,
        ]

        let label = UILabel().then {
            $0.text = lines.joined(separator: "\n")
            $0.font = .monospacedSystemFont(ofSize: UIFont.preferredFont(forTextStyle: .caption2).pointSize, weight: .regular)
            $0.textColor = .tertiaryLabel
            $0.textAlignment = .center
            $0.numberOfLines = 0
        }

        let container = UIView()
        container.addSubview(label)
        label.snp.makeConstraints {
            $0.edges.equalToSuperview().inset(UIEdgeInsets(top: 16, left: 16, bottom: 24, right: 16))
        }

        stackView.addArrangedSubview(container)
    }
}
