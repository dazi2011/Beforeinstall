import Foundation
import AppKit

enum LogLevel: String, Codable, CaseIterable, Sendable {
    case debug
    case info
    case warning
    case error

    var rank: Int {
        switch self {
        case .debug:
            return 0
        case .info:
            return 1
        case .warning:
            return 2
        case .error:
            return 3
        }
    }
}

struct DiagnosticLogEntry: Codable, Identifiable {
    var id = UUID()
    var timestamp: Date
    var level: LogLevel
    var category: String
    var message: String
}

@MainActor
final class DiagnosticsLogService: ObservableObject {
    static let shared = DiagnosticsLogService()

    @Published private(set) var entries: [DiagnosticLogEntry] = []
    @Published private(set) var minimumLevel: LogLevel = .info
    @Published private(set) var maxEntries: Int = 3000

    func log(_ level: LogLevel, category: String, _ message: String) {
        guard level.rank >= minimumLevel.rank else {
            return
        }
        entries.append(DiagnosticLogEntry(timestamp: Date(), level: level, category: category, message: message))
        if entries.count > maxEntries {
            entries.removeFirst(entries.count - maxEntries)
        }
    }

    func updateConfiguration(minLevel: LogLevel, maxEntries: Int) {
        minimumLevel = minLevel
        self.maxEntries = max(200, min(maxEntries, 20000))
        if entries.count > self.maxEntries {
            entries.removeFirst(entries.count - self.maxEntries)
        }
    }

    func clear() {
        entries.removeAll(keepingCapacity: true)
    }

    func export(includeDebug: Bool = false) throws -> URL {
        let target = entries.filter { includeDebug || $0.level != .debug }
        let formatter = ISO8601DateFormatter()
        let text = target.map {
            "[\(formatter.string(from: $0.timestamp))] [\($0.level.rawValue.uppercased())] [\($0.category)] \($0.message)"
        }.joined(separator: "\n")

        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "beforeinstall-diagnostics-\(timestamp()).log"
        guard panel.runModal() == .OK, let url = panel.url else {
            throw NSError(domain: "BeforeInstall.Log", code: 1, userInfo: [NSLocalizedDescriptionKey: "Export canceled"])
        }

        guard let data = text.data(using: .utf8) else {
            throw NSError(domain: "BeforeInstall.Log", code: 2, userInfo: [NSLocalizedDescriptionKey: "UTF-8 encoding failed"])
        }
        try data.write(to: url, options: .atomic)
        return url
    }

    private func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }
}
