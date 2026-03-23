import Foundation

final class ScanPerformanceTraceStore {
    private let fileManager = FileManager.default
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    private var tracesDirectory: URL {
        let directory = AppPaths.appSupportDirectory.appendingPathComponent("PerformanceTraces", isDirectory: true)
        if !fileManager.fileExists(atPath: directory.path) {
            try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        return directory
    }

    func write(sessionID: String, trace: ScanPerformanceTrace) -> URL? {
        let sessionDirectory = tracesDirectory.appendingPathComponent(sessionID, isDirectory: true)
        if !fileManager.fileExists(atPath: sessionDirectory.path) {
            try? fileManager.createDirectory(at: sessionDirectory, withIntermediateDirectories: true)
        }

        let fileURL = sessionDirectory.appendingPathComponent("performance_trace.json", isDirectory: false)
        guard let data = try? encoder.encode(trace) else { return nil }
        do {
            try data.write(to: fileURL, options: .atomic)
            return fileURL
        } catch {
            return nil
        }
    }
}
