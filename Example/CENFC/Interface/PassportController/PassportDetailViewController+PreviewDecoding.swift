import CoreExtendedNFC
import ImageIO
import UIKit
import UniformTypeIdentifiers

extension PassportDetailViewController {
    nonisolated struct PreviewPayload: Sendable {
        let fileData: Data
        let fileExtension: String
        let sourceFormatName: String
        let imageSize: CGSize
        let hasRenderedPreview: Bool
    }

    /// Everything derived from the portrait and signature images, decoded once off the main thread.
    nonisolated struct DecodedPreviews: Sendable {
        var payloads: [DataGroupId: PreviewPayload] = [:]
        var faceImage: UIImage?
    }

    nonisolated static func decodePreviews(for passport: PassportModel) -> DecodedPreviews {
        var result = DecodedPreviews()
        for (dgId, data) in [
            (DataGroupId.dg2, passport.resolvedFaceImageData),
            (DataGroupId.dg7, passport.resolvedSignatureImageData),
        ] {
            guard let data else { continue }
            let image = decodeImage(from: data)
            if dgId == .dg2 {
                result.faceImage = image
            }
            result.payloads[dgId] = previewPayload(for: data, decodedImage: image)
        }
        return result
    }

    nonisolated private static func previewPayload(for data: Data, decodedImage: UIImage?) -> PreviewPayload? {
        let formatName = inferPreviewFormat(for: data)
        if let image = decodedImage,
           let jpegData = image.jpegData(compressionQuality: 0.95)
        {
            return PreviewPayload(
                fileData: jpegData,
                fileExtension: "jpg",
                sourceFormatName: formatName,
                imageSize: image.size,
                hasRenderedPreview: true
            )
        }

        guard let nativeExtension = nativePreviewExtension(for: data) else { return nil }
        return PreviewPayload(
            fileData: data,
            fileExtension: nativeExtension,
            sourceFormatName: formatName,
            imageSize: .zero,
            hasRenderedPreview: false
        )
    }

    nonisolated private static func decodeImage(from data: Data) -> UIImage? {
        if let image = UIImage(data: data) {
            return image
        }

        let sourceOptions = [
            kCGImageSourceShouldCache: false,
        ] as CFDictionary

        if let source = CGImageSourceCreateWithData(data as CFData, sourceOptions),
           let cgImage = CGImageSourceCreateImageAtIndex(source, 0, nil)
        {
            return UIImage(cgImage: cgImage)
        }

        let hintedTypes = [
            "public.jpeg-2000",
            UTType.jpeg.identifier,
            UTType.png.identifier,
        ]

        for hintedType in hintedTypes {
            let hintOptions = [
                kCGImageSourceShouldCache: false,
                kCGImageSourceTypeIdentifierHint: hintedType,
            ] as CFDictionary

            if let source = CGImageSourceCreateWithData(data as CFData, hintOptions),
               let cgImage = CGImageSourceCreateImageAtIndex(source, 0, nil)
            {
                return UIImage(cgImage: cgImage)
            }
        }

        return nil
    }

    nonisolated private static func inferPreviewFormat(for data: Data) -> String {
        if data.starts(with: [0xFF, 0xD8, 0xFF]) {
            return "JPEG"
        }

        if data.starts(with: [0x89, 0x50, 0x4E, 0x47]) {
            return "PNG"
        }

        if data.starts(with: [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20]) {
            return "JPEG2000"
        }

        if data.starts(with: [0xFF, 0x4F, 0xFF, 0x51]) {
            return "JPEG2000 Codestream"
        }

        return "Unknown"
    }

    nonisolated private static func nativePreviewExtension(for data: Data) -> String? {
        if data.starts(with: [0xFF, 0xD8, 0xFF]) {
            return "jpg"
        }

        if data.starts(with: [0x89, 0x50, 0x4E, 0x47]) {
            return "png"
        }

        if data.starts(with: [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20]) {
            return "jp2"
        }

        if data.starts(with: [0xFF, 0x4F, 0xFF, 0x51]) {
            return "j2c"
        }

        return nil
    }
}
