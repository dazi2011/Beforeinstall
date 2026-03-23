import Foundation

enum ThreatIntelDictionaryError: LocalizedError {
    case missingBundledResource(String)
    case writeFailed(String)

    var errorDescription: String? {
        switch self {
        case let .missingBundledResource(name):
            return "Missing bundled threat profile: \(name)"
        case let .writeFailed(reason):
            return "Failed to write threat profile: \(reason)"
        }
    }
}

final class ThreatIntelDictionaryManager: @unchecked Sendable {
    static let shared = ThreatIntelDictionaryManager()

    static let bundledProfileFileName = "default-threat-profile.txt"

    private let fileManager = FileManager.default

    func ensureRuleFileReady() throws -> URL {
        let target = activeRuleFileURL()
        if fileManager.fileExists(atPath: target.path) {
            return target
        }

        let parent = target.deletingLastPathComponent()
        try fileManager.createDirectory(at: parent, withIntermediateDirectories: true)

        guard let bundled = bundledRuleFileURL() else {
            throw ThreatIntelDictionaryError.missingBundledResource(Self.bundledProfileFileName)
        }

        do {
            if fileManager.fileExists(atPath: target.path) {
                try fileManager.removeItem(at: target)
            }
            try fileManager.copyItem(at: bundled, to: target)
        } catch {
            throw ThreatIntelDictionaryError.writeFailed(error.localizedDescription)
        }

        return target
    }

    func replaceRuleFile(with sourceURL: URL) throws -> URL {
        let target = activeRuleFileURL()
        let parent = target.deletingLastPathComponent()
        try fileManager.createDirectory(at: parent, withIntermediateDirectories: true)

        do {
            if fileManager.fileExists(atPath: target.path) {
                try fileManager.removeItem(at: target)
            }
            try fileManager.copyItem(at: sourceURL, to: target)
        } catch {
            throw ThreatIntelDictionaryError.writeFailed(error.localizedDescription)
        }

        return target
    }

    func resetToBundledProfile() throws -> URL {
        guard let bundled = bundledRuleFileURL() else {
            throw ThreatIntelDictionaryError.missingBundledResource(Self.bundledProfileFileName)
        }
        return try replaceRuleFile(with: bundled)
    }

    func hasActiveRuleFile() -> Bool {
        fileManager.fileExists(atPath: activeRuleFileURL().path)
    }

    func activeRuleFileURL() -> URL {
        dictionaryDirectoryURL().appendingPathComponent(Self.bundledProfileFileName, isDirectory: false)
    }

    func bundledRuleFileURL() -> URL? {
        if let nested = Bundle.main.url(
            forResource: Self.bundledProfileFileName,
            withExtension: nil,
            subdirectory: "ThreatIntel"
        ) {
            return nested
        }
        return Bundle.main.url(forResource: Self.bundledProfileFileName, withExtension: nil)
    }

    private func dictionaryDirectoryURL() -> URL {
        let base = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/BeforeInstall", isDirectory: true)
        return base.appendingPathComponent("ThreatIntel", isDirectory: true)
    }
}
