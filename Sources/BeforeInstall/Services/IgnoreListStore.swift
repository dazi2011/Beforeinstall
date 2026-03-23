import Foundation

final class IgnoreListStore {
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
        AppPaths.appSupportDirectory.appendingPathComponent("ignored-threat-items.json", isDirectory: false)
    }

    func load() -> [IgnoreRuleRecord] {
        guard let data = try? Data(contentsOf: storageURL),
              let records = try? decoder.decode([IgnoreRuleRecord].self, from: data)
        else {
            return []
        }
        return records.sorted { $0.createdAt > $1.createdAt }
    }

    func save(_ records: [IgnoreRuleRecord]) {
        guard let data = try? encoder.encode(records) else { return }
        try? fileManager.createDirectory(at: storageURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: storageURL, options: .atomic)
    }

    @discardableResult
    func append(_ record: IgnoreRuleRecord, maxItems: Int = 2000) -> [IgnoreRuleRecord] {
        var records = load()
        let duplicate = records.contains { existing in
            existing.path == record.path
                && existing.hash == record.hash
                && existing.bundleIdentifier == record.bundleIdentifier
                && existing.ruleID == record.ruleID
        }
        if !duplicate {
            records.insert(record, at: 0)
        }
        if records.count > maxItems {
            records = Array(records.prefix(maxItems))
        }
        save(records)
        return records
    }

    @discardableResult
    func remove(id: UUID) -> [IgnoreRuleRecord] {
        var records = load()
        records.removeAll { $0.id == id }
        save(records)
        return records
    }

    func shouldIgnore(item: ScanItem, bundleIdentifier: String?) -> Bool {
        let rules = load()
        return rules.contains { rule in
            if let path = rule.path, let hash = rule.hash {
                return path == item.path && hash == item.hash
            }
            if let path = rule.path {
                return path == item.path
            }
            if let hash = rule.hash {
                return hash == item.hash
            }
            if let bundle = rule.bundleIdentifier {
                return bundle == bundleIdentifier
            }
            return false
        }
    }
}
