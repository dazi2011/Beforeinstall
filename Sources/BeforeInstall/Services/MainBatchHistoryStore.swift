import Foundation

final class MainBatchHistoryStore {
    private let fileManager = FileManager.default
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()
    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    private var storageURL: URL {
        let base = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/BeforeInstall", isDirectory: true)
        return base.appendingPathComponent("analysis-batch-history.json", isDirectory: false)
    }

    func load() -> [MainBatchRunRecord] {
        guard let data = try? Data(contentsOf: storageURL),
              let records = try? decoder.decode([MainBatchRunRecord].self, from: data)
        else {
            return []
        }
        return records.sorted { $0.createdAt > $1.createdAt }
    }

    @discardableResult
    func append(_ run: MainBatchRunRecord, maxItems: Int = 80) -> [MainBatchRunRecord] {
        var records = load()
        records.removeAll { $0.id == run.id || $0.runID == run.runID }
        records.insert(run, at: 0)
        if records.count > maxItems {
            records = Array(records.prefix(maxItems))
        }
        save(records)
        return records
    }

    @discardableResult
    func delete(id: UUID) -> [MainBatchRunRecord] {
        var records = load()
        records.removeAll { $0.id == id }
        save(records)
        return records
    }

    func save(_ records: [MainBatchRunRecord]) {
        let storage = storageURL
        let parent = storage.deletingLastPathComponent()
        try? fileManager.createDirectory(at: parent, withIntermediateDirectories: true)
        guard let data = try? encoder.encode(records) else { return }
        try? data.write(to: storage, options: .atomic)
    }
}
