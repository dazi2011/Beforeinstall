import Foundation

final class HybridFixtureAnalyzer: StaticAnalyzer {
    let analyzerName = "HybridFixtureAnalyzer"
    let supportedTypes: Set<SupportedFileType> = [.archive]

    private let metadataService: FileMetadataService
    private let scriptAnalyzer: ScriptAnalyzer
    private let appAnalyzer: AppAnalyzer
    private let pkgAnalyzer: PkgAnalyzer
    private let fileManager = FileManager.default

    init(
        metadataService: FileMetadataService,
        scriptAnalyzer: ScriptAnalyzer,
        appAnalyzer: AppAnalyzer,
        pkgAnalyzer: PkgAnalyzer
    ) {
        self.metadataService = metadataService
        self.scriptAnalyzer = scriptAnalyzer
        self.appAnalyzer = appAnalyzer
        self.pkgAnalyzer = pkgAnalyzer
    }

    func analyze(fileURL: URL, basicInfo: FileBasicInfo) async -> AnalysisResult {
        var result = AnalysisResult.placeholder(for: basicInfo, request: .default)

        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: fileURL.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            result.warnings.append("Hybrid fixture path is not a directory.")
            return result
        }

        let scripts = collectScriptFiles(root: fileURL)
        let appBundles = collectAppBundles(root: fileURL)
        let pkgDirectories = collectPkgFixtureDirectories(root: fileURL)

        result.technicalDetails.append(
            TechnicalDetail(
                title: "Hybrid Fixture Overview",
                content: [
                    "scripts=\(scripts.count)",
                    "appBundles=\(appBundles.count)",
                    "pkgDirectories=\(pkgDirectories.count)",
                    "root=\(fileURL.path)"
                ].joined(separator: "\n")
            )
        )

        var aggregatedHits: [ScriptRuleHit] = []
        var scriptSummaries: [String] = []

        for scriptURL in scripts.prefix(24) {
            let scriptType = SupportedFileType.detect(from: scriptURL)
            let scriptInfo: FileBasicInfo
            switch metadataService.basicInfo(for: scriptURL, detectedType: scriptType) {
            case let .success(info):
                scriptInfo = info
            case .failure:
                scriptInfo = metadataService.makeFallbackInfo(for: scriptURL, detectedType: scriptType)
            }

            let scriptResult = await scriptAnalyzer.analyze(fileURL: scriptURL, basicInfo: scriptInfo)
            if let details = scriptResult.scriptDetails {
                aggregatedHits.append(contentsOf: details.ruleHits)
                scriptSummaries.append(contentsOf: details.summary)
            }
        }

        for appURL in appBundles.prefix(8) {
            let appInfo: FileBasicInfo
            switch metadataService.basicInfo(for: appURL, detectedType: .appBundle) {
            case let .success(info):
                appInfo = info
            case .failure:
                appInfo = metadataService.makeFallbackInfo(for: appURL, detectedType: .appBundle)
            }

            let appResult = await appAnalyzer.analyze(fileURL: appURL, basicInfo: appInfo)
            if let details = appResult.scriptDetails {
                aggregatedHits.append(contentsOf: details.ruleHits)
                scriptSummaries.append(contentsOf: details.summary)
            }
            result.sensitiveCapabilities.append(contentsOf: appResult.sensitiveCapabilities.map { "[app] \($0)" })
            result.persistenceIndicators.append(contentsOf: appResult.persistenceIndicators.map { "[app] \($0)" })
        }

        for pkgURL in pkgDirectories.prefix(8) {
            let pkgInfo: FileBasicInfo
            switch metadataService.basicInfo(for: pkgURL, detectedType: .pkg) {
            case let .success(info):
                pkgInfo = info
            case .failure:
                pkgInfo = metadataService.makeFallbackInfo(for: pkgURL, detectedType: .pkg)
            }

            let pkgResult = await pkgAnalyzer.analyze(fileURL: pkgURL, basicInfo: pkgInfo)
            if let details = pkgResult.scriptDetails {
                aggregatedHits.append(contentsOf: details.ruleHits)
                scriptSummaries.append(contentsOf: details.summary)
            }
            result.sensitiveCapabilities.append(contentsOf: pkgResult.sensitiveCapabilities.map { "[pkg] \($0)" })
            result.persistenceIndicators.append(contentsOf: pkgResult.persistenceIndicators.map { "[pkg] \($0)" })
        }

        if !aggregatedHits.isEmpty {
            let sorted = aggregatedHits.sorted { lhs, rhs in
                if lhs.suggestedRiskScoreDelta == rhs.suggestedRiskScoreDelta {
                    return lhs.ruleID < rhs.ruleID
                }
                return lhs.suggestedRiskScoreDelta > rhs.suggestedRiskScoreDelta
            }

            result.scriptDetails = ScriptAnalysisDetails(
                scriptType: .shellScript,
                shebang: nil,
                lineCount: 0,
                tokenCount: 0,
                commandSample: scripts.prefix(8).map { $0.lastPathComponent },
                summary: scriptSummaries.uniquePreservingOrder(),
                ruleHits: Array(sorted.prefix(120))
            )
        }

        if scripts.isEmpty && appBundles.isEmpty && pkgDirectories.isEmpty {
            result.warnings.append("Hybrid fixture has no analyzable script/app/pkg components.")
        }

        result.sensitiveCapabilities = result.sensitiveCapabilities.uniquePreservingOrder()
        result.persistenceIndicators = result.persistenceIndicators.uniquePreservingOrder()
        result.warnings = result.warnings.uniquePreservingOrder()

        result.genericDetails = GenericFileDetails(
            fileTypeByMagic: "hybrid_fixture_directory",
            mimeType: "application/x-beforeinstall-hybrid-fixture",
            sha256: nil,
            isExecutable: false,
            isPossiblyDisguised: false,
            scriptSnippet: nil,
            suspiciousKeywordHits: result.scriptDetails?.ruleHits.map(\.ruleID) ?? []
        )

        return result
    }

    private func collectScriptFiles(root: URL) -> [URL] {
        guard let enumerator = fileManager.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles],
            errorHandler: nil
        ) else {
            return []
        }

        let scriptExts = Set(["sh", "command", "py", "js", "mjs", "cjs", "applescript", "scpt"])
        var files: [URL] = []
        let baseDepth = root.pathComponents.count

        for case let url as URL in enumerator {
            let depth = url.pathComponents.count - baseDepth
            if depth > 5 {
                enumerator.skipDescendants()
                continue
            }

            var isDir: ObjCBool = false
            if fileManager.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue {
                continue
            }

            let ext = url.pathExtension.lowercased()
            if scriptExts.contains(ext) {
                files.append(url)
            }
        }

        return files.sorted { $0.path < $1.path }
    }

    private func collectAppBundles(root: URL) -> [URL] {
        collectDirectories(root: root) { url in
            url.pathExtension.lowercased() == "app"
        }
    }

    private func collectPkgFixtureDirectories(root: URL) -> [URL] {
        collectDirectories(root: root) { url in
            let scripts = url.appendingPathComponent("scripts")
            let payload = url.appendingPathComponent("payload")
            let packageInfo = url.appendingPathComponent("PackageInfo.json")
            var isScriptsDir: ObjCBool = false
            let hasScripts = fileManager.fileExists(atPath: scripts.path, isDirectory: &isScriptsDir) && isScriptsDir.boolValue
            var isPayloadDir: ObjCBool = false
            let hasPayload = fileManager.fileExists(atPath: payload.path, isDirectory: &isPayloadDir) && isPayloadDir.boolValue
            let hasPackageInfo = fileManager.fileExists(atPath: packageInfo.path)
            return hasScripts && (hasPayload || hasPackageInfo)
        }
    }

    private func collectDirectories(root: URL, predicate: (URL) -> Bool) -> [URL] {
        guard let enumerator = fileManager.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles],
            errorHandler: nil
        ) else {
            return []
        }

        var directories: [URL] = []
        let baseDepth = root.pathComponents.count

        for case let url as URL in enumerator {
            let depth = url.pathComponents.count - baseDepth
            if depth > 5 {
                enumerator.skipDescendants()
                continue
            }

            var isDir: ObjCBool = false
            guard fileManager.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue else {
                continue
            }

            if predicate(url) {
                directories.append(url)
                enumerator.skipDescendants()
            }
        }

        return directories.sorted { $0.path < $1.path }
    }
}
