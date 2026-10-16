import UIKit

/// A read-only text view for personal data.
///
/// The selection menu only offers Copy, Select and Select All. Copy goes
/// through ``SensitivePasteboard`` (local only, expiring), and the system
/// actions that would hand the text to other apps or services (Share, Look Up,
/// Translate, Writing Tools) are removed. Dragging text out is disabled.
final class SensitiveTextView: UITextView {
    /// The pasteboard Copy writes to. Tests use a named pasteboard.
    var pasteboard: UIPasteboard = .general

    static let allowedActions: Set<Selector> = [
        #selector(UIResponderStandardEditActions.copy(_:)),
        #selector(UIResponderStandardEditActions.select(_:)),
        #selector(UIResponderStandardEditActions.selectAll(_:)),
    ]

    init() {
        super.init(frame: .zero, textContainer: nil)
        isEditable = false
        textDragInteraction?.isEnabled = false
        if #available(iOS 18.0, *) {
            writingToolsBehavior = .none
        }
        delegate = self
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError()
    }

    override func canPerformAction(_ action: Selector, withSender _: Any?) -> Bool {
        Self.allowedActions.contains(action)
    }

    /// The selected text, or the whole text when nothing is selected.
    var textToCopy: String {
        let content = text ?? ""
        let range = selectedRange
        guard range.length > 0,
              let swiftRange = Range(range, in: content)
        else { return content }
        return String(content[swiftRange])
    }

    override func copy(_: Any?) {
        SensitivePasteboard.copy(textToCopy, to: pasteboard)
    }
}

extension SensitiveTextView: UITextViewDelegate {
    func textView(
        _ textView: UITextView,
        editMenuForTextIn _: NSRange,
        suggestedActions _: [UIMenuElement]
    ) -> UIMenu? {
        // Replace the system menu (which carries Share, Look Up and Translate)
        // with a Copy that goes through SensitivePasteboard.
        guard let view = textView as? SensitiveTextView else { return UIMenu(children: []) }
        return UIMenu(children: [
            UIAction(
                title: String(localized: "Copy"),
                image: UIImage(systemName: "doc.on.doc")
            ) { [weak view] _ in
                view?.copy(nil)
            },
        ])
    }
}
