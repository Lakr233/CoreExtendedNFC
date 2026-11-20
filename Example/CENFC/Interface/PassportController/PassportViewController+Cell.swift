import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import UIKit

extension PassportViewController {
    class PassportRecordCell: UITableViewCell {
        static let reuseIdentifier = "PassportRecordCell"

        private let content = ConfigurablePageView { nil }

        private let dateFormatter: DateFormatter = {
            let f = DateFormatter()
            f.dateStyle = .medium
            f.timeStyle = .short
            return f
        }()

        override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
            super.init(style: style, reuseIdentifier: reuseIdentifier)
            backgroundColor = .clear
            clipsToBounds = true
            tintColor = .systemBlue
            content.isUserInteractionEnabled = false

            let wrapper = AutoLayoutMarginView(content)
            contentView.addSubview(wrapper)
            wrapper.snp.makeConstraints { $0.edges.equalToSuperview() }

            let editingBackground = UIView()
            editingBackground.backgroundColor = .systemGray5
            multipleSelectionBackgroundView = editingBackground
        }

        @available(*, unavailable)
        required init?(coder _: NSCoder) {
            fatalError()
        }

        func update(with record: PassportRecord) {
            content.configure(icon: UIImage(systemName: "person.text.rectangle"))
            content.configure(title: String.LocalizationValue(stringLiteral: record.displayName))
            let desc = "\(record.passport.mrz?.documentNumber ?? "") · \(dateFormatter.string(from: record.date))"
            content.configure(description: String.LocalizationValue(stringLiteral: desc))
        }

        override func layoutSubviews() {
            super.layoutSubviews()
            preservesSuperviewLayoutMargins = false
            // Edge to edge, but inside the side safe area: on the iPhone Duo the
            // status bar and the vertical tab bar sit there.
            separatorInset = UIEdgeInsets(top: 0, left: safeAreaInsets.left, bottom: 0, right: safeAreaInsets.right)
            layoutMargins = .zero
        }
    }
}
