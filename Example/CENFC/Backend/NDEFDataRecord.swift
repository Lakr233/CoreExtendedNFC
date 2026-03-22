import ConfigurableKit
import CoreExtendedNFC
import Foundation

struct NDEFDataRecord: Codable, Hashable, Identifiable {
    let id: UUID
    let date: Date
    var name: String
    let messageData: Data

    init(name: String, messageData: Data) {
        id = UUID()
        date = Date()
        self.name = name
        self.messageData = messageData
    }

    private init(id: UUID, date: Date, name: String, messageData: Data) {
        self.id = id
        self.date = date
        self.name = name
        self.messageData = messageData
    }

    var parsedMessage: NDEFMessage? {
        try? NDEFMessage(data: messageData)
    }

    var parsedRecord: NDEFRecord? {
        parsedMessage?.records.first
    }

    var displayType: String {
        parsedRecord?.displayType ?? String(localized: "Empty")
    }

    var displayValue: String {
        parsedRecord?.displayValue ?? String(localized: "No data")
    }

    func replacingID(_ newID: UUID = UUID(), date newDate: Date = Date()) -> NDEFDataRecord {
        NDEFDataRecord(id: newID, date: newDate, name: name, messageData: messageData)
    }

    func withName(_ newName: String) -> NDEFDataRecord {
        NDEFDataRecord(id: id, date: date, name: newName, messageData: messageData)
    }

    func withMessageData(_ newData: Data) -> NDEFDataRecord {
        NDEFDataRecord(id: id, date: date, name: name, messageData: newData)
    }
}

extension NDEFDataRecord: ObjectListItem {
    func matches(query: String) -> Bool {
        name.localizedCaseInsensitiveContains(query)
            || displayType.localizedCaseInsensitiveContains(query)
            || displayValue.localizedCaseInsensitiveContains(query)
    }
}
