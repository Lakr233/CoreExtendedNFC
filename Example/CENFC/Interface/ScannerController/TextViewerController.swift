import SnapKit
import SPIndicator
import UIKit

class TextViewerController: UIViewController {
    private let textView = UITextView()

    init(title: String, text: String) {
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
                guard let text = self?.textView.text else { return }
                UIPasteboard.general.string = text
                SPIndicator.present(
                    title: String(localized: "Copied"),
                    preset: .done,
                    haptic: .success
                )
            }
        )
    }
}
