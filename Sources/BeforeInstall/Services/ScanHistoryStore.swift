import Foundation

final class ScanHistoryStore {
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
        AppPaths.appSupportDirectory.appendingPathComponent("full-disk-scan-history.json", isDirectory: false)
    }

    func load() -> [ScanSession] {
        guard let data = try? Data(contentsOf: storageURL),
              let sessions = try? decoder.decode([ScanSession].self, from: data)
        else {
            return []
        }
        return sessions.sorted { $0.startedAt > $1.startedAt }
    }

    func save(_ sessions: [ScanSession]) {
        guard let data = try? encoder.encode(sessions) else { return }
        try? fileManager.createDirectory(at: storageURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: storageURL, options: .atomic)
    }

    @discardableResult
    func append(_ session: ScanSession, maxItems: Int = 80) -> [ScanSession] {
        var sessions = load()
        sessions.removeAll { $0.sessionID == session.sessionID }
        sessions.insert(session, at: 0)
        if sessions.count > maxItems {
            sessions = Array(sessions.prefix(maxItems))
        }
        save(sessions)
        return sessions
    }

    @discardableResult
    func update(_ session: ScanSession) -> [ScanSession] {
        var sessions = load()
        if let index = sessions.firstIndex(where: { $0.sessionID == session.sessionID }) {
            sessions[index] = session
        } else {
            sessions.insert(session, at: 0)
        }
        save(sessions)
        return sessions.sorted { $0.startedAt > $1.startedAt }
    }
}
