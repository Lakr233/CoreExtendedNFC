import Foundation

/// Identifies an eMRTD data group.
///
/// Each case provides the EF file identifier used for `SELECT` and the outer TLV tag.
///
/// Reference: ICAO Doc 9303 Part 10, Table 33
/// https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf
/// Cross-ref: JMRTD PassportService.java EF constants
/// https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/PassportService.java
public enum DataGroupId: String, Sendable, Hashable, CaseIterable, Codable {
    case com
    case sod
    case dg1, dg2, dg3, dg4, dg5, dg6, dg7
    case dg8, dg9, dg10, dg11, dg12, dg13, dg14, dg15, dg16

    /// The 2-byte Elementary File identifier used in SELECT commands.
    public var fileID: Data {
        switch self {
        case .com: Data([0x01, 0x1E])
        case .sod: Data([0x01, 0x1D])
        case .dg1: Data([0x01, 0x01])
        case .dg2: Data([0x01, 0x02])
        case .dg3: Data([0x01, 0x03])
        case .dg4: Data([0x01, 0x04])
        case .dg5: Data([0x01, 0x05])
        case .dg6: Data([0x01, 0x06])
        case .dg7: Data([0x01, 0x07])
        case .dg8: Data([0x01, 0x08])
        case .dg9: Data([0x01, 0x09])
        case .dg10: Data([0x01, 0x0A])
        case .dg11: Data([0x01, 0x0B])
        case .dg12: Data([0x01, 0x0C])
        case .dg13: Data([0x01, 0x0D])
        case .dg14: Data([0x01, 0x0E])
        case .dg15: Data([0x01, 0x0F])
        case .dg16: Data([0x01, 0x10])
        }
    }

    /// The outermost TLV tag wrapping this data group's contents.
    public var tlvTag: UInt {
        switch self {
        case .com: 0x60
        case .sod: 0x77
        case .dg1: 0x61
        case .dg2: 0x75
        case .dg3: 0x63
        case .dg4: 0x76
        case .dg5: 0x65
        case .dg6: 0x66
        case .dg7: 0x67
        case .dg8: 0x68
        case .dg9: 0x69
        case .dg10: 0x6A
        case .dg11: 0x6B
        case .dg12: 0x6C
        case .dg13: 0x6D
        case .dg14: 0x6E
        case .dg15: 0x6F
        case .dg16: 0x70
        }
    }

    /// Human-readable name.
    public var name: String {
        switch self {
        case .com: "COM (Common Data)"
        case .sod: "SOD (Security Object)"
        case .dg1: "DG1 (MRZ)"
        case .dg2: "DG2 (Face Image)"
        case .dg3: "DG3 (Fingerprints)"
        case .dg4: "DG4 (Iris)"
        case .dg5: "DG5 (Portrait)"
        case .dg6: "DG6 (Reserved)"
        case .dg7: "DG7 (Signature)"
        case .dg8: "DG8 (Data Features)"
        case .dg9: "DG9 (Structure Features)"
        case .dg10: "DG10 (Substance Features)"
        case .dg11: "DG11 (Additional Personal)"
        case .dg12: "DG12 (Additional Document)"
        case .dg13: "DG13 (Optional Details)"
        case .dg14: "DG14 (Security Info)"
        case .dg15: "DG15 (Active Auth Key)"
        case .dg16: "DG16 (Persons to Notify)"
        }
    }
}
