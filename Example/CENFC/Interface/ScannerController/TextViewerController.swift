import SnapKit
import SPIndicator
import UIKit

class TextViewerController: UIViewController {
    let textView: UITextView
    /// Whether the text is personal data (a passport data group): the copy
    /// button and the selection menu then use ``SensitivePasteboard``, and the
    /// system Share / Look Up / Translate actions are not offered
    /// (``SensitiveTextView``).
    let copiesSensitively: Bool

    init(title: String, text: String, copiesSensitively: Bool = false) {
        self.copiesSensitively = copiesSensitively
        textView = copiesSensitively ? SensitiveTextView() : UITextView()
        super.init(nibName: nil, bundle: nil)
        self.title = title
        textView.text = text
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

        textView.font = .monospacedSystemFont(ofSize: UIFont.systemFontSize, weight: .regular)
        textView.isEditable = false
        textView.isSelectable = true
        textView.isScrollEnabled = true
        textView.textColor = .label
        textView.backgroundColor = .clear
        textView.textContainerInset = .init(top: 10, left: 10, bottom: 10, right: 10)
        textView.textContainer.lineFragmentPadding = .zero
        textView.showsVerticalScrollIndicator = true

        view.addSubview(textView)
        textView.snp.makeConstraints { make in
            make.top.leading.trailing.equalToSuperview()
            make.bottom.equalTo(view.keyboardLayoutGuide.snp.top)
        }

        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "doc.on.doc"),
            primaryAction: UIAction { [weak self] _ in
                guard let self, let text = textView.text else { return }
                if copiesSensitively {
                    SensitivePasteboard.copy(text)
                } else {
                    UIPasteboard.general.string = text
                }
                SPIndicator.present(
                    title: String(localized: "Copied"),
                    preset: .done,
                    haptic: .success
                )
            }
        ).accessibilityLabeled(String(localized: "Copy"))
    }
}
