import Foundation

// MARK: - Data group read loop

extension PassportReader {
    /// Order in which requested data groups are read: COM and the SOD first (their
    /// lists decide what is selected), then DG1, then the rest as requested, with the
    /// EAC-protected DG3/DG4 last. Duplicates are dropped.
    static func readOrder(for requested: [DataGroupId]) -> [DataGroupId] {
        var seen = Set<DataGroupId>()
        let unique = requested.filter { seen.insert($0).inserted }

        func rank(_ dgId: DataGroupId) -> Int {
            switch dgId {
            case .com: 0
            case .sod: 1
            case .dg1: 2
            case .dg3, .dg4: 4
            default: 3
            }
        }

        return unique.enumerated()
            .sorted { lhs, rhs in
                (rank(lhs.element), lhs.offset) < (rank(rhs.element), rhs.offset)
            }
            .map(\.element)
    }

    /// DG3 (fingerprints) and DG4 (iris) need Extended Access Control; under BAC/PACE
    /// alone the chip refuses them, often with an unprotected 6982.
    static func isEACProtected(_ dgId: DataGroupId) -> Bool {
        dgId == .dg3 || dgId == .dg4
    }
}
