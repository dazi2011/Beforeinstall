import Foundation

final class RemediationHistoryStore {
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
        AppPaths.appSupportDirectory.appendingPathComponent("remediation-history.json", isDirectory: false)
    }

    func load() -> [RemediationLogEntry] {
        guard let data = try? Data(contentsOf: storageURL),
              let entries = try? decoder.decode([RemediationLogEntry].self, from: data)
        else {
            return []
        }
        return entries.sorted { $0.timestamp > $1.timestamp }
    }

    func save(_ entries: [RemediationLogEntry]) {
        guard let data = try? encoder.encode(entries) else { return }
        try? fileManager.createDirectory(at: storageURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: storageURL, options: .atomic)
    }

    @discardableResult
    func append(_ entry: RemediationLogEntry, maxItems: Int = 3000) -> [RemediationLogEntry] {
        var entries = load()
        entries.insert(entry, at: 0)
        if entries.count > maxItems {
            entries = Array(entries.prefix(maxItems))
        }
        save(entries)
        return entries
    }
}
