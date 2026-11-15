import Foundation

/// A record kept in one of the app's lists, identified by a UUID.
///
/// Lists are driven by diffable data sources keyed on `id`, so two records in
/// one store must never share an ID (UIKit raises "supplied item identifiers
/// are not unique").
nonisolated protocol StoredRecord: Codable, Sendable, Identifiable where ID == UUID {
    /// A copy with a new ID and otherwise identical content.
    func withNewID() -> Self
}
