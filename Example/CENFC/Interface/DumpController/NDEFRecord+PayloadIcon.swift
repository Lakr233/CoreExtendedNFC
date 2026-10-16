//
//  NDEFIcon.swift
//  CENFC
//
//  Created by Phineas Guo on 2026/3/23.
//

import Foundation

extension NDEFRecord.Payload {
    var icon: String {
        switch self {
        case .text:
            "doc.plaintext"
        case .uri:
            "link"
        case .smartPoster:
            "rectangle.and.text.magnifyingglass"
        case .mime:
            "doc.richtext"
        case .external:
            "puzzlepiece.extension"
        default:
            "questionmark"
        }
    }
}
