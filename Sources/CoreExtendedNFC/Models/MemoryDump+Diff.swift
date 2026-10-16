import Foundation

extension MemoryDump {
    /// Produce a stable diff summary against another dump.
    ///
    /// Entries are matched by key (page number, block number, file identifier, fact key).
    /// Repeated keys never trap: the n-th occurrence of a key is compared with the
    /// n-th occurrence in the other dump.
    public func diffSummary(against other: MemoryDump) -> DiffSummary {
        DiffSummary(
            sameCardFamily: cardInfo.type.family == other.cardInfo.type.family,
            sameUID: cardInfo.uid == other.cardInfo.uid,
            byteDelta: exportBinary().count - other.exportBinary().count,
            pageChanges: keyedDifferenceCount(
                lhs: Self.keyedByOccurrence(pages.map { (Int($0.number), $0.data) }),
                rhs: Self.keyedByOccurrence(other.pages.map { (Int($0.number), $0.data) })
            ),
            blockChanges: keyedDifferenceCount(
                lhs: Self.keyedByOccurrence(blocks.map { ($0.number, $0.data) }),
                rhs: Self.keyedByOccurrence(other.blocks.map { ($0.number, $0.data) })
            ),
            fileChanges: keyedDifferenceCount(
                lhs: Self.keyedByOccurrence(files.map { ($0.identifier, $0.data) }),
                rhs: Self.keyedByOccurrence(other.files.map { ($0.identifier, $0.data) })
            ),
            ndefChanged: ndefMessage != other.ndefMessage,
            factChanges: keyedDifferenceCount(
                lhs: Self.keyedByOccurrence(facts.map { ($0.key, $0.value) }),
                rhs: Self.keyedByOccurrence(other.facts.map { ($0.key, $0.value) })
            )
        )
    }

    private struct OccurrenceKey<Key: Hashable>: Hashable {
        let key: Key
        let occurrence: Int
    }

    private static func keyedByOccurrence<Key: Hashable, Value>(
        _ pairs: [(Key, Value)]
    ) -> [OccurrenceKey<Key>: Value] {
        var seen: [Key: Int] = [:]
        var result: [OccurrenceKey<Key>: Value] = [:]
        for (key, value) in pairs {
            let occurrence = seen[key, default: 0]
            seen[key] = occurrence + 1
            result[OccurrenceKey(key: key, occurrence: occurrence)] = value
        }
        return result
    }

    private func keyedDifferenceCount<Key: Hashable, Value: Equatable>(
        lhs: [Key: Value],
        rhs: [Key: Value]
    ) -> Int {
        let keys = Set(lhs.keys).union(rhs.keys)
        return keys.reduce(into: 0) { count, key in
            if lhs[key] != rhs[key] {
                count += 1
            }
        }
    }
}
