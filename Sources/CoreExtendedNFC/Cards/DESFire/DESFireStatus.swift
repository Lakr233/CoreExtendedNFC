import Foundation

/// DESFire status/error codes returned in SW2.
public enum DESFireStatus: UInt8, Sendable {
    case operationOK = 0x00
    case noChanges = 0x0C
    case outOfMemory = 0x0E
    case illegalCommand = 0x1C
    case integrityError = 0x1E
    case noSuchKey = 0x40
    case authenticationDelay = 0xAD
    case lengthError = 0x7E
    case permissionDenied = 0x9D
    case parameterError = 0x9E
    case applicationNotFound = 0xA0
    case applicationIntegrityError = 0xA1
    case authenticationError = 0xAE
    case additionalFrame = 0xAF
    case boundaryError = 0xBE
    case cardIntegrityError = 0xC1
    case commandAborted = 0xCA
    case cardDisabled = 0xCD
    case countError = 0xCE
    case duplicateError = 0xDE
    case eepromError = 0xEE
    case fileNotFound = 0xF0
    case fileIntegrityError = 0xF1

    /// Human-readable description.
    public var description: String {
        switch self {
        case .operationOK: "Operation OK"
        case .noChanges: "No changes"
        case .outOfMemory: "Out of EEPROM memory"
        case .illegalCommand: "Illegal command code"
        case .integrityError: "CRC or MAC error"
        case .noSuchKey: "No such key"
        case .authenticationDelay: "Authentication delay"
        case .lengthError: "Length error"
        case .permissionDenied: "Permission denied"
        case .parameterError: "Parameter error"
        case .applicationNotFound: "Application not found"
        case .applicationIntegrityError: "Application integrity error"
        case .authenticationError: "Authentication error"
        case .additionalFrame: "Additional frame (more data)"
        case .boundaryError: "Boundary error"
        case .cardIntegrityError: "Card integrity error"
        case .commandAborted: "Command aborted"
        case .cardDisabled: "Card disabled"
        case .countError: "Count error"
        case .duplicateError: "Duplicate error"
        case .eepromError: "EEPROM error"
        case .fileNotFound: "File not found"
        case .fileIntegrityError: "File integrity error"
        }
    }
}
