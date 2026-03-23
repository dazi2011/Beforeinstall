import Foundation
import CryptoKit

struct FileFingerprint {
    var size: Int64
    var modifiedAt: Date?
    var isDirectory: Bool
    var isExecutable: Bool
    var detectedType: SupportedFileType
    var sha256: String?
}

struct FileSnapshotDiff {
    var createdPaths: [String]
    var modifiedPaths: [String]
    var deletedPaths: [String]
    var detailedRecords: [FileSystemChangeRecord]
    var isIncomplete: Bool
}

final class FileSystemMonitor {
    private let fileManager = FileManager.default

    func captureSnapshot(
        paths: [String],
        maxEntries: Int = 5000,
        maxHashFileSizeBytes: Int64 = 512 * 1024
    ) -> [String: FileFingerprint] {
        var snapshot: [String: FileFingerprint] = [:]

        for root in paths {
            guard fileManager.fileExists(atPath: root) else { continue }
            let rootURL = URL(fileURLWithPath: root)

            if let attrs = try? fileManager.attributesOfItem(atPath: root),
               let fingerprint = makeFingerprint(path: root, attrs: attrs, maxHashFileSizeBytes: maxHashFileSizeBytes)
            {
                snapshot[root] = fingerprint
            }

            guard let enumerator = fileManager.enumerator(
                at: rootURL,
                includingPropertiesForKeys: [.isRegularFileKey, .contentModificationDateKey, .fileSizeKey],
                options: [.skipsPackageDescendants],
                errorHandler: { _, _ in true }
            ) else {
                continue
            }

            for case let url as URL in enumerator {
                if snapshot.count >= maxEntries { break }
                if let attrs = try? fileManager.attributesOfItem(atPath: url.path),
                   let fingerprint = makeFingerprint(path: url.path, attrs: attrs, maxHashFileSizeBytes: maxHashFileSizeBytes)
                {
                    snapshot[url.path] = fingerprint
                }
            }
        }

        return snapshot
    }

    func diff(before: [String: FileFingerprint], after: [String: FileFingerprint]) -> FileSnapshotDiff {
        var created: [String] = []
        var modified: [String] = []
        var deleted: [String] = []
        var detailedRecords: [FileSystemChangeRecord] = []
        let isPotentiallyIncomplete = before.count >= 5000 || after.count >= 5000

        for (path, now) in after {
            if let prev = before[path] {
                let sizeChanged = prev.size != now.size
                let dateChanged = prev.modifiedAt != now.modifiedAt
                let hashChanged = (prev.sha256 != nil || now.sha256 != nil) && prev.sha256 != now.sha256
                let typeChanged = prev.detectedType != now.detectedType
                if sizeChanged || dateChanged || hashChanged || typeChanged {
                    modified.append(path)
                    detailedRecords.append(
                        FileSystemChangeRecord(
                            path: path,
                            changeType: .modified,
                            fileSize: now.size,
                            modifiedTime: now.modifiedAt,
                            hash: now.sha256,
                            whetherSensitivePath: isSensitivePath(path),
                            detectedType: now.detectedType
                        )
                    )
                }
            } else {
                created.append(path)
                detailedRecords.append(
                    FileSystemChangeRecord(
                        path: path,
                        changeType: .added,
                        fileSize: now.size,
                        modifiedTime: now.modifiedAt,
                        hash: now.sha256,
                        whetherSensitivePath: isSensitivePath(path),
                        detectedType: now.detectedType
                    )
                )
            }
        }

        for (path, prev) in before where after[path] == nil {
            deleted.append(path)
            detailedRecords.append(
                FileSystemChangeRecord(
                    path: path,
                    changeType: .deleted,
                    fileSize: prev.size,
                    modifiedTime: prev.modifiedAt,
                    hash: prev.sha256,
                    whetherSensitivePath: isSensitivePath(path),
                    detectedType: prev.detectedType
                )
            )
        }

        return FileSnapshotDiff(
            createdPaths: created.sorted(),
            modifiedPaths: modified.sorted(),
            deletedPaths: deleted.sorted(),
            detailedRecords: detailedRecords.sorted { lhs, rhs in
                if lhs.changeType == rhs.changeType {
                    return lhs.path < rhs.path
                }
                return lhs.changeType.rawValue < rhs.changeType.rawValue
            },
            isIncomplete: isPotentiallyIncomplete
        )
    }

    func monitoredPaths(workspaceHome: String) -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return [
            "\(workspaceHome)",
            "\(workspaceHome)/Library",
            "\(workspaceHome)/Library/Application Support",
            "\(workspaceHome)/Library/Preferences",
            "\(workspaceHome)/Library/Caches",
            "\(workspaceHome)/Library/Logs",
            "\(workspaceHome)/Library/LaunchAgents",
            "\(home)/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "\(home)/Library/Application Support",
            "\(home)/Library/Preferences",
            "\(home)/.zshrc",
            "\(home)/.bash_profile",
            "/private/tmp",
            "/tmp"
        ]
    }

    private func makeFingerprint(
        path: String,
        attrs: [FileAttributeKey: Any],
        maxHashFileSizeBytes: Int64
    ) -> FileFingerprint? {
        let size = (attrs[.size] as? NSNumber)?.int64Value ?? 0
        let modifiedAt = attrs[.modificationDate] as? Date
        let type = (attrs[.type] as? FileAttributeType) ?? .typeUnknown
        let isDirectory = type == .typeDirectory
        let posixPermissions = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0
        let isExecutable = (posixPermissions & 0o111) != 0
        let detectedType = detectType(path: path, isDirectory: isDirectory, isExecutable: isExecutable)

        let hash: String?
        if shouldHash(path: path, isDirectory: isDirectory, size: size, maxHashFileSizeBytes: maxHashFileSizeBytes) {
            hash = sha256(forPath: path)
        } else {
            hash = nil
        }

        return FileFingerprint(
            size: size,
            modifiedAt: modifiedAt,
            isDirectory: isDirectory,
            isExecutable: isExecutable,
            detectedType: detectedType,
            sha256: hash
        )
    }

    private func detectType(path: String, isDirectory: Bool, isExecutable: Bool) -> SupportedFileType {
        let url = URL(fileURLWithPath: path)
        if isDirectory, url.pathExtension.lowercased() == "app" {
            return .appBundle
        }

        let byExtension = SupportedFileType.detect(from: url)
        if byExtension != .unknown {
            return byExtension
        }

        if isExecutable {
            return .machO
        }
        return .unknown
    }

    private func shouldHash(path: String, isDirectory: Bool, size: Int64, maxHashFileSizeBytes: Int64) -> Bool {
        guard !isDirectory else { return false }
        guard size > 0 && size <= maxHashFileSizeBytes else { return false }
        let lower = path.lowercased()
        let textLikeExt = [".sh", ".zsh", ".bash", ".py", ".js", ".mjs", ".cjs", ".applescript", ".scpt", ".plist", ".txt", ".json", ".xml", ".yml", ".yaml"]
        if textLikeExt.contains(where: lower.hasSuffix) {
            return true
        }
        // Small files are hashed in best-effort mode even when extension is unknown.
        return size <= (128 * 1024)
    }

    private func sha256(forPath path: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe]) else {
            return nil
        }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func isSensitivePath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        let home = FileManager.default.homeDirectoryForCurrentUser.path.lowercased()
        let explicitSensitivePaths = [
            "\(home)/library/launchagents",
            "/library/launchagents",
            "/library/launchdaemons",
            "\(home)/library/application support",
            "\(home)/library/preferences",
            "\(home)/.zshrc",
            "\(home)/.bash_profile",
            "/tmp",
            "/private/tmp"
        ]
        return explicitSensitivePaths.contains { normalized.hasPrefix($0) || normalized == $0 }
    }
}
