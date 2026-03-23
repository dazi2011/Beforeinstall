import Foundation

enum QuarantineManagerError: LocalizedError {
    case fileMissing(String)
    case failed(String)

    var errorDescription: String? {
        switch self {
        case let .fileMissing(path):
            return "File not found: \(path)"
        case let .failed(message):
            return message
        }
    }
}

final class QuarantineManager {
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

    private var recordsURL: URL {
        AppPaths.appSupportDirectory.appendingPathComponent("quarantine-records.json", isDirectory: false)
    }

    func loadRecords() -> [QuarantineRecord] {
        guard let data = try? Data(contentsOf: recordsURL),
              let records = try? decoder.decode([QuarantineRecord].self, from: data)
        else {
            return []
        }
        return records.sorted { $0.timestamp > $1.timestamp }
    }

    func saveRecords(_ records: [QuarantineRecord]) {
        guard let data = try? encoder.encode(records) else { return }
        try? fileManager.createDirectory(at: recordsURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: recordsURL, options: .atomic)
    }

    func quarantine(
        path: String,
        reason: String,
        metadata: [String: String],
        hash: String?
    ) throws -> QuarantineRecord {
        let sourceURL = URL(fileURLWithPath: path)
        guard fileManager.fileExists(atPath: sourceURL.path) else {
            throw QuarantineManagerError.fileMissing(sourceURL.path)
        }

        let destination = AppPaths.quarantineDirectory
            .appendingPathComponent(quarantineFileName(for: sourceURL.lastPathComponent), isDirectory: false)

        do {
            try fileManager.moveItem(at: sourceURL, to: destination)
        } catch {
            throw QuarantineManagerError.failed("Move to quarantine failed: \(error.localizedDescription)")
        }

        let record = QuarantineRecord(
            quarantineID: UUID().uuidString,
            originalPath: sourceURL.path,
            quarantinePath: destination.path,
            timestamp: Date(),
            reason: reason,
            originalMetadata: metadata,
            hash: hash,
            canRestore: true
        )

        var records = loadRecords()
        records.insert(record, at: 0)
        saveRecords(records)
        return record
    }

    func restore(quarantineID: String) throws -> QuarantineRecord {
        var records = loadRecords()
        guard let index = records.firstIndex(where: { $0.quarantineID == quarantineID }) else {
            throw QuarantineManagerError.failed("Quarantine record not found.")
        }
        var record = records[index]
        let sourceURL = URL(fileURLWithPath: record.quarantinePath)
        guard fileManager.fileExists(atPath: sourceURL.path) else {
            throw QuarantineManagerError.fileMissing(sourceURL.path)
        }

        var destinationURL = URL(fileURLWithPath: record.originalPath)
        if fileManager.fileExists(atPath: destinationURL.path) {
            let fallbackName = destinationURL.lastPathComponent + ".restored-\(Int(Date().timeIntervalSince1970))"
            destinationURL = destinationURL.deletingLastPathComponent().appendingPathComponent(fallbackName, isDirectory: false)
        }

        try? fileManager.createDirectory(at: destinationURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        do {
            try fileManager.moveItem(at: sourceURL, to: destinationURL)
        } catch {
            throw QuarantineManagerError.failed("Restore failed: \(error.localizedDescription)")
        }

        record.canRestore = false
        record.originalMetadata["restoredPath"] = destinationURL.path
        records[index] = record
        saveRecords(records)
        return record
    }

    func deletePermanently(quarantineID: String) throws {
        var records = loadRecords()
        guard let index = records.firstIndex(where: { $0.quarantineID == quarantineID }) else {
            throw QuarantineManagerError.failed("Quarantine record not found.")
        }
        let record = records[index]
        let url = URL(fileURLWithPath: record.quarantinePath)
        if fileManager.fileExists(atPath: url.path) {
            do {
                try fileManager.removeItem(at: url)
            } catch {
                throw QuarantineManagerError.failed("Delete from quarantine failed: \(error.localizedDescription)")
            }
        }
        records.remove(at: index)
        saveRecords(records)
    }

    private func quarantineFileName(for baseName: String) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return "\(formatter.string(from: Date()))-\(UUID().uuidString)-\(baseName)"
    }
}
