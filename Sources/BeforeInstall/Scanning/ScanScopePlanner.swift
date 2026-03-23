import Foundation

final class ScanScopePlanner {
    private let fileManager = FileManager.default

    func makePlan(
        mode: FullDiskScanMode,
        customFocusPaths: [String],
        includeExternalVolumes: Bool
    ) -> ScanScopePlan {
        let home = fileManager.homeDirectoryForCurrentUser.path

        var roots = quickDefaultRoots(home: home)
        if mode == .deep {
            roots.append(contentsOf: deepAdditionalRoots(home: home))
        }

        let normalizedCustomPaths = normalizePaths(customFocusPaths)
        roots.append(contentsOf: normalizedCustomPaths)

        let pathRules = loadPathPrefixRules()
        let noticePrefixes = pathRules.filter { $0.action == .notice }.map(\.prefix)
        let ignorePrefixes = pathRules.filter { $0.action == .ignore }.map(\.prefix)
        roots.append(contentsOf: noticePrefixes)

        if includeExternalVolumes {
            roots.append(contentsOf: mountedExternalVolumes())
        }

        roots = normalizePaths(roots)

        var excludedPathPrefixes = defaultExcludedPathPrefixes(home: home)
        excludedPathPrefixes.append(contentsOf: ignorePrefixes)
        excludedPathPrefixes = normalizePaths(excludedPathPrefixes)

        let prioritizedPrefixes = normalizePaths(
            normalizedCustomPaths
                + noticePrefixes
                + quickDefaultRoots(home: home)
        )

        let commonExcludedDirectoryNames = [
            ".git",
            "node_modules",
            "Pods",
            "DerivedData",
            "build",
            "dist",
            ".venv",
            "venv",
            "__pycache__",
            "Library/Developer",
            "Library/Caches",
            "Caches",
            "benchmark",
            "BeforeInstall-Benchmark"
        ]

        let commonExcludedExtensions = [
            "jpg", "jpeg", "png", "gif", "heic", "mov", "mp4", "m4v", "mp3", "wav", "pdf", "zip"
        ]

        return ScanScopePlan(
            mode: mode,
            roots: roots,
            excludedPathPrefixes: excludedPathPrefixes,
            excludedDirectoryNames: commonExcludedDirectoryNames,
            excludedExtensions: commonExcludedExtensions,
            prioritizedPathPrefixes: prioritizedPrefixes,
            includeExternalVolumes: includeExternalVolumes,
            maxCandidates: 0, // 0 = unlimited (bounded by pruning + candidate selection)
            maxDepth: mode == .quick ? 4 : 9,
            maxFileSizeBytes: mode == .quick ? 160 * 1024 * 1024 : 2 * 1024 * 1024 * 1024,
            pathRules: pathRules
        )
    }

    private func quickDefaultRoots(home: String) -> [String] {
        [
            "/Applications",
            "\(home)/Applications",
            "\(home)/Downloads",
            "\(home)/Desktop",
            "\(home)/Documents",
            "\(home)/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "\(home)/Library/Application Support",
            "\(home)/Library/Preferences",
            "\(home)/Library/Scripts",
            "/tmp",
            "/private/tmp",
            "\(home)/Library/Caches"
        ]
    }

    private func deepAdditionalRoots(home: String) -> [String] {
        [
            home,
            "/Library",
            "/usr/local",
            "/opt/homebrew"
        ]
    }

    private func defaultExcludedPathPrefixes(home: String) -> [String] {
        [
            AppPaths.quarantineDirectory.path,
            AppPaths.appSupportDirectory.path,
            "\(home)/Library/Developer",
            "\(home)/Library/Application Support/BeforeInstall",
            "\(home)/Library/Caches/com.apple.timemachine",
            "/Volumes/com.apple.TimeMachine.localsnapshots",
            "/Volumes/Backups.backupdb"
        ]
    }

    private func mountedExternalVolumes() -> [String] {
        let root = URL(fileURLWithPath: "/Volumes", isDirectory: true)
        guard let items = try? fileManager.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey, .volumeIsInternalKey, .volumeIsBrowsableKey, .nameKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }

        return items.compactMap { url in
            let name = url.lastPathComponent.lowercased()
            if name.contains("time machine") || name.contains("backups.backupdb") || name.contains("timemachine") {
                return nil
            }
            if name.hasSuffix(".dmg") || name.contains("disk image") {
                return nil
            }

            let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .volumeIsInternalKey, .volumeIsBrowsableKey])
            let isDirectory = values?.isDirectory == true
            let isInternal = values?.volumeIsInternal ?? true
            let isBrowsable = values?.volumeIsBrowsable ?? true
            guard isDirectory, !isInternal, isBrowsable else {
                return nil
            }
            return url.path
        }
    }

    private func normalizePaths(_ rawPaths: [String]) -> [String] {
        var seen = Set<String>()
        return rawPaths.compactMap { raw in
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }
            let expanded = (trimmed as NSString).expandingTildeInPath
            let standardized = URL(fileURLWithPath: expanded).standardizedFileURL.path
            guard fileManager.fileExists(atPath: standardized) else { return nil }
            guard !seen.contains(standardized) else { return nil }
            seen.insert(standardized)
            return standardized
        }
    }

    private func loadPathPrefixRules() -> [ScanScopePathRule] {
        let parsed = ConfigProfileService.shared.loadActiveParsedProfile()
        return parsed.rules.compactMap { rule in
            guard rule.type == .rulePathPrefix else { return nil }
            let prefix = (rule.value as NSString).expandingTildeInPath
            return ScanScopePathRule(
                prefix: URL(fileURLWithPath: prefix).standardizedFileURL.path,
                action: rule.action,
                sourceLine: rule.lineNumber
            )
        }
    }
}
