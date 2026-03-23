import Foundation

struct DiscoveredCandidate: Sendable {
    var path: String
    var isDirectory: Bool
    var size: Int64
    var modifiedAt: Date?
    var isExecutable: Bool
    var sourceRoot: String
}

struct ScanEnumerationOutput: Sendable {
    var candidates: [DiscoveredCandidate]
    var inaccessiblePaths: [String]
    var visitedEntries: Int
    var pruningStats: [String: Int]
}

struct ScanEnumerationProgress: Sendable {
    var rootPath: String
    var visitedEntries: Int
    var discoveredCandidates: Int
    var currentPath: String?
}

final class ScanEnumerator {
    private let fileManager = FileManager.default

    func enumerate(
        plan: ScanScopePlan,
        shouldCancel: @escaping @Sendable () -> Bool = { false },
        progress: (@Sendable (ScanEnumerationProgress) -> Void)? = nil
    ) -> ScanEnumerationOutput {
        var candidates: [DiscoveredCandidate] = []
        var inaccessiblePaths: [String] = []
        var pruningStats: [String: Int] = [:]
        var visitedEntries = 0
        let excludedNames = Set(plan.excludedDirectoryNames.map { $0.lowercased() })
        let hasCandidateLimit = plan.maxCandidates > 0

        func markPruned(_ reason: String) {
            pruningStats[reason, default: 0] += 1
        }

        for rootPath in plan.roots {
            if shouldCancel() {
                break
            }
            if hasCandidateLimit, candidates.count >= plan.maxCandidates {
                break
            }
            let rootURL = URL(fileURLWithPath: rootPath, isDirectory: true)
            guard fileManager.fileExists(atPath: rootURL.path) else { continue }
            guard fileManager.isReadableFile(atPath: rootURL.path) else {
                inaccessiblePaths.append(rootURL.path)
                continue
            }
            let rootBudget = plan.mode == .quick
                ? quickRootVisitBudget(rootPathLower: rootURL.path.lowercased())
                : nil
            var rootVisitedEntries = 0

            progress?(
                ScanEnumerationProgress(
                    rootPath: rootURL.path,
                    visitedEntries: visitedEntries,
                    discoveredCandidates: candidates.count,
                    currentPath: rootURL.path
                )
            )

            // Include root itself when root is directly an app/pkg bundle.
            if let rootCandidate = makeCandidateIfNeeded(
                path: rootURL.path,
                isDirectory: true,
                sourceRoot: rootURL.path,
                maxFileSize: plan.maxFileSizeBytes
            ) {
                candidates.append(rootCandidate)
                progress?(
                    ScanEnumerationProgress(
                        rootPath: rootURL.path,
                        visitedEntries: visitedEntries,
                        discoveredCandidates: candidates.count,
                        currentPath: rootURL.path
                    )
                )
            }

            guard let enumerator = fileManager.enumerator(
                at: rootURL,
                includingPropertiesForKeys: [
                    .isDirectoryKey,
                    .isSymbolicLinkKey,
                    .fileSizeKey,
                    .contentModificationDateKey,
                    .isRegularFileKey
                ],
                options: [.skipsHiddenFiles],
                errorHandler: { url, _ in
                    inaccessiblePaths.append(url.path)
                    return true
                }
            ) else {
                inaccessiblePaths.append(rootURL.path)
                continue
            }

            let baseDepth = rootURL.pathComponents.count
            for case let itemURL as URL in enumerator {
                visitedEntries += 1
                rootVisitedEntries += 1
                var candidateAdded = false
                if shouldCancel() {
                    break
                }
                if let rootBudget, rootVisitedEntries > rootBudget {
                    markPruned("root_budget")
                    break
                }
                if hasCandidateLimit, candidates.count >= plan.maxCandidates {
                    break
                }

                let standardizedPath = itemURL.standardizedFileURL.path
                if let skipReason = skipReasonForPath(standardizedPath, plan: plan) {
                    markPruned(skipReason)
                    enumerator.skipDescendants()
                    continue
                }

                let depth = itemURL.pathComponents.count - baseDepth
                if depth > plan.maxDepth {
                    markPruned("depth_limit")
                    enumerator.skipDescendants()
                    continue
                }

                let values = try? itemURL.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey, .contentModificationDateKey])
                if values?.isSymbolicLink == true {
                    markPruned("symlink")
                    enumerator.skipDescendants()
                    continue
                }

                let isDirectory = values?.isDirectory == true
                let size = Int64(values?.fileSize ?? 0)
                let modifiedAt = values?.contentModificationDate

                if isDirectory {
                    let lowerPath = standardizedPath.lowercased()
                    if lowerPath.hasSuffix(".app") || lowerPath.hasSuffix(".pkg") || lowerPath.hasSuffix(".mpkg") {
                        if let candidate = makeCandidate(
                            path: standardizedPath,
                            isDirectory: true,
                            size: size,
                            modifiedAt: modifiedAt,
                            sourceRoot: rootURL.path
                        ) {
                            candidates.append(candidate)
                            candidateAdded = true
                        }
                        enumerator.skipDescendants()
                    } else if let nameReason = skipReasonForDirectoryName(path: standardizedPath, excludedNames: excludedNames) {
                        markPruned(nameReason)
                        enumerator.skipDescendants()
                    }
                    continue
                }

                let ext = itemURL.pathExtension.lowercased()
                if plan.excludedExtensions.contains(ext) {
                    markPruned("excluded_extension")
                    continue
                }

                if size > plan.maxFileSizeBytes {
                    markPruned("size_limit")
                    continue
                }

                if plan.mode == .quick,
                   !isLikelyInterestingQuickFile(path: standardizedPath, ext: ext)
                {
                    markPruned("quick_low_value_file")
                    continue
                }

                if let candidate = makeCandidate(
                    path: standardizedPath,
                    isDirectory: false,
                    size: size,
                    modifiedAt: modifiedAt,
                    sourceRoot: rootURL.path
                ) {
                    candidates.append(candidate)
                    candidateAdded = true
                }

                if candidateAdded || visitedEntries % 300 == 0 {
                    progress?(
                        ScanEnumerationProgress(
                            rootPath: rootURL.path,
                            visitedEntries: visitedEntries,
                            discoveredCandidates: candidates.count,
                            currentPath: standardizedPath
                        )
                    )
                }
            }
        }

        progress?(
            ScanEnumerationProgress(
                rootPath: plan.roots.first ?? "",
                visitedEntries: visitedEntries,
                discoveredCandidates: candidates.count,
                currentPath: nil
            )
        )

        return ScanEnumerationOutput(
            candidates: candidates.uniqueByPath(),
            inaccessiblePaths: inaccessiblePaths.uniquePreservingOrder(),
            visitedEntries: visitedEntries,
            pruningStats: pruningStats
        )
    }

    private func makeCandidateIfNeeded(
        path: String,
        isDirectory: Bool,
        sourceRoot: String,
        maxFileSize: Int64
    ) -> DiscoveredCandidate? {
        var isDirFlag: ObjCBool = false
        guard fileManager.fileExists(atPath: path, isDirectory: &isDirFlag) else { return nil }
        if isDirectory != isDirFlag.boolValue {
            return nil
        }
        let attrs = try? fileManager.attributesOfItem(atPath: path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
        guard isDirectory || size <= maxFileSize else { return nil }
        let modifiedAt = attrs?[.modificationDate] as? Date
        return makeCandidate(path: path, isDirectory: isDirectory, size: size, modifiedAt: modifiedAt, sourceRoot: sourceRoot)
    }

    private func makeCandidate(
        path: String,
        isDirectory: Bool,
        size: Int64,
        modifiedAt: Date?,
        sourceRoot: String
    ) -> DiscoveredCandidate? {
        if isDirectory {
            let lower = path.lowercased()
            let isBundleDir = lower.hasSuffix(".app") || lower.hasSuffix(".pkg") || lower.hasSuffix(".mpkg")
            guard isBundleDir else { return nil }
        }

        let isExecutable = fileManager.isExecutableFile(atPath: path)
        return DiscoveredCandidate(
            path: path,
            isDirectory: isDirectory,
            size: size,
            modifiedAt: modifiedAt,
            isExecutable: isExecutable,
            sourceRoot: sourceRoot
        )
    }

    private func skipReasonForPath(_ path: String, plan: ScanScopePlan) -> String? {
        let lower = path.lowercased()
        if plan.excludedPathPrefixes.contains(where: { lower.hasPrefix($0.lowercased()) }) {
            return "excluded_prefix"
        }
        if lower.contains("/backups.backupdb/") || lower.contains("time machine") {
            return "time_machine"
        }
        if lower.hasPrefix(AppPaths.quarantineDirectory.path.lowercased()) {
            return "quarantine_directory"
        }
        return nil
    }

    private func skipReasonForDirectoryName(path: String, excludedNames: Set<String>) -> String? {
        let lower = path.lowercased()
        for name in excludedNames {
            if name.contains("/") {
                if lower.contains(name) {
                    return "excluded_directory_name"
                }
            } else if lower.hasSuffix("/\(name)") {
                return "excluded_directory_name"
            }
        }
        return nil
    }

    private func isLikelyInterestingQuickFile(path: String, ext: String) -> Bool {
        if ext.isEmpty {
            return fileManager.isExecutableFile(atPath: path)
        }

        let quickExtensions: Set<String> = [
            "app", "pkg", "mpkg", "dmg", "iso",
            "sh", "zsh", "bash", "command",
            "py", "js", "mjs", "cjs",
            "applescript", "scpt", "scptd",
            "plist", "dylib", "so",
            "bin", "out", "exe"
        ]
        if quickExtensions.contains(ext) {
            return true
        }

        // Keep launchd configs visible even with uncommon suffixes.
        let lower = path.lowercased()
        if (lower.contains("launchagents") || lower.contains("launchdaemons")) && ext == "plist" {
            return true
        }

        return false
    }

    private func quickRootVisitBudget(rootPathLower: String) -> Int? {
        if rootPathLower.hasPrefix("/tmp")
            || rootPathLower.hasPrefix("/private/tmp")
            || rootPathLower.contains("launchagents")
            || rootPathLower.contains("launchdaemons")
            || rootPathLower.hasPrefix("/applications")
            || rootPathLower.hasSuffix("/downloads")
            || rootPathLower.hasSuffix("/desktop")
        {
            return nil
        }

        if rootPathLower.hasSuffix("/documents")
            || rootPathLower.contains("/library/caches")
        {
            return 1800
        }

        if rootPathLower.contains("/library/application support")
            || rootPathLower.contains("/library/preferences")
        {
            return 2600
        }

        return 3200
    }
}

private extension Array where Element == DiscoveredCandidate {
    func uniqueByPath() -> [DiscoveredCandidate] {
        var seen = Set<String>()
        return filter { candidate in
            if seen.contains(candidate.path) {
                return false
            }
            seen.insert(candidate.path)
            return true
        }
    }
}
