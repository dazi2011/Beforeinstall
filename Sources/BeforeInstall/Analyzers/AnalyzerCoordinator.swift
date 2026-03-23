import Foundation

enum AnalysisCoordinatorError: LocalizedError, Sendable {
    case fileIssue(String)

    var errorDescription: String? {
        switch self {
        case let .fileIssue(message):
            return message
        }
    }
}

final class AnalyzerCoordinator: @unchecked Sendable {
    private let engine: AnalyzerEngine

    init(
        commandRunner: CommandRunning = ShellCommandService(),
        metadataService: FileMetadataService = FileMetadataService(),
        riskEngine: RiskEngine = RiskEngine(),
        summaryBuilder: PlainSummaryBuilder = PlainSummaryBuilder(),
        randomForestService: RandomForestModelService = .shared
    ) {
        engine = AnalyzerEngine(
            commandRunner: commandRunner,
            metadataService: metadataService,
            riskEngine: riskEngine,
            summaryBuilder: summaryBuilder,
            randomForestService: randomForestService
        )
    }

    func analyze(
        fileURL: URL,
        request: AnalysisRequest,
        stopToken: DynamicStopToken?,
        progress: @escaping @Sendable (DynamicProgressEvent) -> Void
    ) async -> Result<ScanReport, AnalysisCoordinatorError> {
        await engine.scan(fileURL: fileURL, request: request, stopToken: stopToken, progress: progress)
    }

    func cleanupDynamicWorkspaces() -> Int {
        engine.cleanupDynamicWorkspaces()
    }

    func refreshLocalizedPresentation(for result: AnalysisResult, language: AppLanguage) -> AnalysisResult {
        engine.refreshLocalizedPresentation(for: result, language: language)
    }
}

final class AnalyzerEngine: @unchecked Sendable {
    private let commandRunner: CommandRunning
    private let metadataService: FileMetadataService
    private let riskEngine: RiskEngine
    private let summaryBuilder: PlainSummaryBuilder
    private let detector: FileTypeDetector
    private let dynamicAnalyzer: DynamicAnalyzer
    private let genericAnalyzer: GenericAnalyzer
    private let hybridAnalyzer: HybridFixtureAnalyzer
    private let fixtureRouter: FixtureRouter
    private let randomForestService: RandomForestModelService
    private let fileManager = FileManager.default

    private var staticAnalyzers: [SupportedFileType: any StaticAnalyzer] = [:]

    init(
        commandRunner: CommandRunning,
        metadataService: FileMetadataService,
        riskEngine: RiskEngine,
        summaryBuilder: PlainSummaryBuilder,
        randomForestService: RandomForestModelService
    ) {
        self.commandRunner = commandRunner
        self.metadataService = metadataService
        self.riskEngine = riskEngine
        self.summaryBuilder = summaryBuilder
        self.randomForestService = randomForestService

        detector = FileTypeDetector(commandRunner: commandRunner)

        let scriptAnalyzer = ScriptAnalyzer(commandRunner: commandRunner)
        let appAnalyzer = AppAnalyzer(
            commandRunner: commandRunner,
            scriptAnalyzer: scriptAnalyzer,
            metadataService: metadataService
        )
        let pkgAnalyzer = PkgAnalyzer(
            commandRunner: commandRunner,
            scriptAnalyzer: scriptAnalyzer,
            metadataService: metadataService
        )
        genericAnalyzer = GenericAnalyzer(commandRunner: commandRunner)
        fixtureRouter = FixtureRouter()
        hybridAnalyzer = HybridFixtureAnalyzer(
            metadataService: metadataService,
            scriptAnalyzer: scriptAnalyzer,
            appAnalyzer: appAnalyzer,
            pkgAnalyzer: pkgAnalyzer
        )

        let dynamicCoordinator = DynamicAnalysisCoordinator(commandRunner: commandRunner)
        dynamicAnalyzer = dynamicCoordinator

        let dmgAnalyzer = DmgAnalyzer(
            commandRunner: commandRunner,
            metadataService: metadataService,
            appAnalyzer: appAnalyzer,
            pkgAnalyzer: pkgAnalyzer,
            riskEngine: riskEngine,
            summaryBuilder: summaryBuilder,
            detector: detector
        )

        register(staticAnalyzer: appAnalyzer)
        register(staticAnalyzer: pkgAnalyzer)
        register(staticAnalyzer: dmgAnalyzer)
        register(staticAnalyzer: scriptAnalyzer)
    }

    func register(staticAnalyzer: any StaticAnalyzer) {
        for type in staticAnalyzer.supportedTypes {
            staticAnalyzers[type] = staticAnalyzer
        }
    }

    func scan(
        fileURL: URL,
        request: AnalysisRequest,
        stopToken: DynamicStopToken?,
        progress: @escaping @Sendable (DynamicProgressEvent) -> Void
    ) async -> Result<ScanReport, AnalysisCoordinatorError> {
        let detection = detector.detect(fileURL: fileURL)

        let basicInfo: FileBasicInfo
        switch metadataService.basicInfo(for: fileURL, detectedType: detection.detectedType) {
        case let .success(info):
            basicInfo = info
        case let .failure(error):
            return .failure(.fileIssue(error.localizedDescription))
        }

        var mergedResult = AnalysisResult.placeholder(for: basicInfo, request: request)

        if request.mode == .staticOnly || request.mode == .combined {
            let staticResult = await runStaticAnalysis(
                fileURL: fileURL,
                basicInfo: basicInfo,
                request: request,
                detection: detection
            )
            mergedResult = staticResult
            mergedResult.analysisMode = request.mode
            mergedResult.analysisDepth = request.depth
        } else {
            var lightweight = AnalysisResult.placeholder(for: basicInfo, request: request)
            lightweight.analysisMode = request.mode
            lightweight.analysisDepth = request.depth
            lightweight.warnings.append("Static scoring signals are disabled in Dynamic-only mode.")
            lightweight.genericDetails = GenericFileDetails(
                fileTypeByMagic: nil,
                mimeType: nil,
                sha256: computeSHA256(fileURL: fileURL),
                isExecutable: detection.isExecutable || detection.isMachO,
                isPossiblyDisguised: false,
                scriptSnippet: nil,
                suspiciousKeywordHits: []
            )
            appendDetectionDetail(to: &lightweight, detection: detection)
            mergedResult = lightweight
        }

        if request.mode == .dynamicOnly || request.mode == .combined {
            let dynamicReport = await dynamicAnalyzer.analyze(
                fileURL: fileURL,
                basicInfo: basicInfo,
                request: request,
                stopToken: stopToken,
                progress: progress
            )
            mergedResult.dynamicReport = dynamicReport
            mergedResult.dynamicResults = dynamicReport.dynamicResults

            if !dynamicReport.warnings.isEmpty {
                mergedResult.warnings.append(contentsOf: dynamicReport.warnings)
            }
            if !dynamicReport.suspiciousIndicators.isEmpty {
                mergedResult.sensitiveCapabilities.append(contentsOf: dynamicReport.suspiciousIndicators)
            }
            if !dynamicReport.failureIssues.isEmpty {
                mergedResult.failureIssues.append(contentsOf: dynamicReport.failureIssues)
            }
        }

        if request.mode != .dynamicOnly {
            applyRandomForestPrediction(result: &mergedResult, fileURL: fileURL)
        }

        if request.mode != .dynamicOnly {
            applyThreatIntelEnrichment(
                result: &mergedResult,
                fileURL: fileURL,
                request: request,
                lightweight: request.depth == .quick
            )
        }

        mergedResult.sensitiveCapabilities = mergedResult.sensitiveCapabilities.uniquePreservingOrder()
        mergedResult.persistenceIndicators = mergedResult.persistenceIndicators.uniquePreservingOrder()
        mergedResult.warnings = mergedResult.warnings.uniquePreservingOrder()
        mergedResult.failureIssues.append(contentsOf: FailureIssueClassifier.classify(warnings: mergedResult.warnings))
        mergedResult.failureIssues = mergedResult.failureIssues.uniqueByCodeAndMessage()
        mergedResult.analyzedAt = Date()

        let sha256: String?
        if request.depth == .quick {
            sha256 = mergedResult.genericDetails?.sha256
        } else {
            sha256 = mergedResult.genericDetails?.sha256 ?? computeSHA256(fileURL: fileURL)
        }
        let findings = collectFindings(from: mergedResult)
        var report = ScanReport(
            analyzedAt: mergedResult.analyzedAt,
            filePath: mergedResult.basicInfo.fullPath,
            detectedType: mergedResult.basicInfo.fileType,
            fileSizeBytes: mergedResult.basicInfo.fileSizeBytes,
            sha256: sha256,
            signingInfo: mergedResult.signatureInfo,
            findings: findings,
            riskScore: 0,
            finalVerdict: .unknown,
            reasoningSummary: "",
            topFindings: [],
            riskEvaluation: nil,
            filesystemDiff: mergedResult.dynamicReport?.fileSystemDiff,
            networkSummary: mergedResult.dynamicReport?.networkSummary,
            dynamicResults: mergedResult.dynamicResults,
            analysisResult: mergedResult,
            detection: detection
        )

        let evaluation = riskEngine.evaluate(report: report)
        mergedResult.riskEvaluation = evaluation
        mergedResult.riskAssessment = riskEngine.toLegacyAssessment(evaluation, language: request.language)
        mergedResult.plainSummary = summaryBuilder.build(for: mergedResult, language: request.language)

        report.riskScore = evaluation.totalScore
        report.finalVerdict = evaluation.verdict
        report.reasoningSummary = evaluation.reasoningSummary(language: request.language)
        report.topFindings = evaluation.topFindings
        report.riskEvaluation = evaluation
        report.analysisResult = mergedResult

        return .success(report)
    }

    func cleanupDynamicWorkspaces() -> Int {
        if let dynamic = dynamicAnalyzer as? DynamicAnalysisCoordinator {
            return dynamic.cleanupTemporaryWorkspaces()
        }
        return 0
    }

    func refreshLocalizedPresentation(for result: AnalysisResult, language: AppLanguage) -> AnalysisResult {
        var updated = result
        let evaluation = riskEngine.evaluate(result: updated)
        updated.riskEvaluation = evaluation
        updated.riskAssessment = riskEngine.toLegacyAssessment(evaluation, language: language)
        updated.plainSummary = summaryBuilder.build(for: updated, language: language)
        return updated
    }

    private func runStaticAnalysis(
        fileURL: URL,
        basicInfo: FileBasicInfo,
        request: AnalysisRequest,
        detection: FileTypeDetection
    ) async -> AnalysisResult {
        let route = fixtureRouter.route(fileURL: fileURL, detectedType: basicInfo.fileType)
        var routedBasicInfo = basicInfo
        if let overrideType = route.overrideType {
            routedBasicInfo.fileType = overrideType
        }

        let analyzer: any StaticAnalyzer
        switch route {
        case .appBundle:
            analyzer = staticAnalyzers[.appBundle] ?? genericAnalyzer
        case .pkgFixture:
            analyzer = staticAnalyzers[.pkg] ?? genericAnalyzer
        case .hybridFixture:
            analyzer = hybridAnalyzer
        case .manifestFixture, .descriptorFixture:
            analyzer = genericAnalyzer
        case .none:
            analyzer = staticAnalyzers[routedBasicInfo.fileType] ?? genericAnalyzer
        }

        let quickMode = request.depth == .quick
        var result: AnalysisResult
        if quickMode, routedBasicInfo.fileType == .dmg {
            result = quickDmgProbe(fileURL: fileURL, basicInfo: routedBasicInfo)
        } else if quickMode, let appAnalyzer = analyzer as? AppAnalyzer {
            result = await appAnalyzer.analyzeLightweight(fileURL: fileURL, basicInfo: routedBasicInfo)
        } else if quickMode, let pkgAnalyzer = analyzer as? PkgAnalyzer {
            result = await pkgAnalyzer.analyzeLightweight(fileURL: fileURL, basicInfo: routedBasicInfo)
        } else {
            result = await analyzer.analyze(fileURL: fileURL, basicInfo: routedBasicInfo)
        }
        result.analysisMode = request.mode
        result.analysisDepth = request.depth

        if request.depth == .deep {
            let enrichment = await genericAnalyzer.analyze(fileURL: fileURL, basicInfo: routedBasicInfo)
            mergeDeepStaticEnrichment(base: &result, enrichment: enrichment)
        } else {
            reduceQuickStaticOutput(result: &result)
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "Quick Static Short-Circuit",
                    content: "Quick mode skipped deep bundle expansion/pkg payload recursion/full static enrichment."
                )
            )
        }

        appendDetectionDetail(to: &result, detection: detection)

        if route != .none {
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "Fixture Routing",
                    content: "route=\(route.rawValue), analyzer=\(analyzer.analyzerName), fileType=\(routedBasicInfo.fileType.rawValue)"
                )
            )
        }

        if route == .manifestFixture || route == .descriptorFixture {
            result.warnings.append("Manifest/descriptor fixture uses lightweight parsing and does not represent full app/pkg execution coverage.")
        } else if analyzer.analyzerName == genericAnalyzer.analyzerName {
            result.warnings.append("No dedicated analyzer for \(basicInfo.fileType.rawValue). Fallback to generic analyzer.")
        }

        return result
    }

    private func mergeDeepStaticEnrichment(base: inout AnalysisResult, enrichment: AnalysisResult) {
        if base.genericDetails == nil {
            base.genericDetails = enrichment.genericDetails
        } else if let enrichmentDetails = enrichment.genericDetails {
            var merged = base.genericDetails!
            merged.suspiciousKeywordHits = (merged.suspiciousKeywordHits + enrichmentDetails.suspiciousKeywordHits)
                .uniquePreservingOrder()
            if merged.scriptSnippet == nil {
                merged.scriptSnippet = enrichmentDetails.scriptSnippet
            }
            if merged.fileTypeByMagic == nil {
                merged.fileTypeByMagic = enrichmentDetails.fileTypeByMagic
            }
            if merged.mimeType == nil {
                merged.mimeType = enrichmentDetails.mimeType
            }
            if merged.sha256 == nil {
                merged.sha256 = enrichmentDetails.sha256
            }
            base.genericDetails = merged
        }

        if !enrichment.technicalDetails.isEmpty {
            let details = enrichment.technicalDetails.map { detail in
                TechnicalDetail(
                    title: "Deep Static Enrichment · \(detail.title)",
                    content: detail.content
                )
            }
            base.technicalDetails.append(contentsOf: details)
        }

        if !enrichment.sensitiveCapabilities.isEmpty {
            base.sensitiveCapabilities.append(contentsOf: enrichment.sensitiveCapabilities)
            base.sensitiveCapabilities = base.sensitiveCapabilities.uniquePreservingOrder()
        }

        if !enrichment.warnings.isEmpty {
            base.warnings.append(contentsOf: enrichment.warnings)
            base.warnings = base.warnings.uniquePreservingOrder()
        }
    }

    private func reduceQuickStaticOutput(result: inout AnalysisResult) {
        if result.technicalDetails.count > 24 {
            result.technicalDetails = Array(result.technicalDetails.prefix(24))
            result.warnings.append("Quick depth trimmed extended technical details. Use Deep for full context.")
        }

        if var scriptDetails = result.scriptDetails, scriptDetails.ruleHits.count > 40 {
            scriptDetails.ruleHits = Array(scriptDetails.ruleHits.prefix(40))
            result.scriptDetails = scriptDetails
            result.warnings.append("Quick depth kept top 40 script rule hits. Use Deep for exhaustive script hit list.")
        }
    }

    private func quickDmgProbe(fileURL: URL, basicInfo: FileBasicInfo) -> AnalysisResult {
        var result = AnalysisResult.placeholder(for: basicInfo)
        switch commandRunner.run(executable: "/usr/bin/hdiutil", arguments: ["imageinfo", fileURL.path]) {
        case let .success(command):
            let lines = command.combinedOutput
                .split(whereSeparator: \.isNewline)
                .map(String.init)
            let preview = lines.prefix(40).joined(separator: "\n")
            result.technicalDetails.append(TechnicalDetail(title: "Quick DMG Probe", content: preview))
            if lines.contains(where: { $0.lowercased().contains("udif") || $0.lowercased().contains("apple disk image") }) {
                result.sensitiveCapabilities.append("Disk image metadata identified")
            }
        case let .failure(error):
            result.warnings.append("Quick DMG probe failed: \(error.localizedDescription)")
        }
        result.warnings.append("Quick probe skipped DMG mount and nested payload analysis. Use Deep for full traversal.")
        return result
    }

    private func applyThreatIntelEnrichment(
        result: inout AnalysisResult,
        fileURL: URL,
        request: AnalysisRequest,
        lightweight: Bool
    ) {
        let scanner = ThreatIntelScanner.shared
        let resolvedHash: String?
        if lightweight {
            resolvedHash = result.genericDetails?.sha256
        } else {
            resolvedHash = resolvePrimaryHash(for: fileURL, result: &result)
        }
        var intelHits: [ThreatIntelHit] = scanner.matchHash(resolvedHash)
        let textCandidate = readThreatIntelTextCandidate(
            fileURL: fileURL,
            type: result.basicInfo.fileType,
            maxBytes: lightweight ? 128 * 1024 : 512 * 1024
        )

        if let text = textCandidate {
            intelHits.append(contentsOf: scanner.scanTextContent(text, sha256: resolvedHash, maxMatches: lightweight ? 24 : 80))
        }

        if !lightweight, result.basicInfo.fileType == .appBundle, request.depth == .deep {
            let signatureHits = scanner.scanAppBundleBinarySignatures(appURL: fileURL, maxBinaries: 32, maxMatches: 18)
            intelHits.append(contentsOf: signatureHits)
            if !signatureHits.isEmpty {
                result.sensitiveCapabilities.append("App binary signature-byte pattern matched known malicious fragment")
            }
        }

        let profileEvaluation = ProfileRuleEngine.shared.evaluate(
            fileURL: fileURL,
            textContent: textCandidate,
            sha256: resolvedHash,
            existingHits: intelHits,
            enableAppSignatureRules: !lightweight && result.basicInfo.fileType == .appBundle && request.depth == .deep
        )
        intelHits = profileEvaluation.hits

        if profileEvaluation.ignoredCount > 0 {
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "Config Rule Overrides",
                    content: "Ignored \(profileEvaluation.ignoredCount) threat-intel hit(s) by active profile rules."
                )
            )
        }

        guard !intelHits.isEmpty else { return }
        intelHits = dedupeThreatIntelHits(intelHits)

        let hitLines = intelHits.prefix(48).map { hit in
            "[\(hit.category.rawValue)] +\(hit.scoreDelta) \(hit.matchedValue)"
        }
        result.technicalDetails.append(
            TechnicalDetail(
                title: "Threat Intel Unified Profile",
                content: hitLines.joined(separator: "\n")
            )
        )

        let addedRuleHits = intelHits.map { hit in
            ScriptRuleHit(
                ruleID: hit.ruleID,
                title: "Threat Intel \(hit.category.rawValue)",
                severity: threatIntelSeverity(for: hit.scoreDelta),
                matchedContent: hit.matchedValue,
                lineStart: 0,
                lineEnd: 0,
                explanation: "Matched unified threat profile section [\(hit.category.rawValue)].",
                suggestedRiskScoreDelta: hit.scoreDelta
            )
        }

        if var existing = result.scriptDetails {
            existing.ruleHits.append(contentsOf: addedRuleHits)
            existing.ruleHits = dedupeScriptRuleHits(existing.ruleHits)
            existing.summary.append("Threat intel profile matched \(intelHits.count) rules")
            existing.summary = existing.summary.uniquePreservingOrder()
            result.scriptDetails = existing
        } else {
            result.scriptDetails = ScriptAnalysisDetails(
                scriptType: result.basicInfo.fileType,
                shebang: nil,
                lineCount: 0,
                tokenCount: 0,
                commandSample: [],
                summary: ["Threat intel profile matched \(intelHits.count) rules"],
                ruleHits: addedRuleHits
            )
        }

        result.sensitiveCapabilities.append(contentsOf: intelHits.prefix(20).map { hit in
            "Threat intel [\(hit.category.rawValue)] hit: \(hit.matchedValue)"
        })
    }

    private func resolvePrimaryHash(for fileURL: URL, result: inout AnalysisResult) -> String? {
        if let known = result.genericDetails?.sha256, !known.isEmpty {
            return known
        }

        if let direct = computeSHA256(fileURL: fileURL) {
            if var generic = result.genericDetails {
                generic.sha256 = generic.sha256 ?? direct
                result.genericDetails = generic
            } else {
                result.genericDetails = GenericFileDetails(
                    fileTypeByMagic: nil,
                    mimeType: nil,
                    sha256: direct,
                    isExecutable: result.basicInfo.fileType.isExecutableLike,
                    isPossiblyDisguised: false,
                    scriptSnippet: nil,
                    suspiciousKeywordHits: []
                )
            }
            return direct
        }

        guard result.basicInfo.fileType == .appBundle else { return nil }
        guard let mainExecutable = appMainExecutableURL(appURL: fileURL) else { return nil }
        let hash = computeSHA256(fileURL: mainExecutable)
        if let hash {
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "App Main Executable SHA256",
                    content: "\(mainExecutable.path)\n\(hash)"
                )
            )
        }
        return hash
    }

    private func appMainExecutableURL(appURL: URL) -> URL? {
        let infoURL = appURL.appendingPathComponent("Contents/Info.plist")
        if let data = try? Data(contentsOf: infoURL),
           let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
           let executableName = plist["CFBundleExecutable"] as? String,
           !executableName.isEmpty
        {
            let executableURL = appURL.appendingPathComponent("Contents/MacOS/\(executableName)")
            if fileManager.fileExists(atPath: executableURL.path) {
                return executableURL
            }
        }

        let macOSDir = appURL.appendingPathComponent("Contents/MacOS", isDirectory: true)
        guard let candidates = try? fileManager.contentsOfDirectory(at: macOSDir, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
            return nil
        }
        return candidates.first(where: { fileManager.isExecutableFile(atPath: $0.path) }) ?? candidates.first
    }

    private func readThreatIntelTextCandidate(fileURL: URL, type: SupportedFileType, maxBytes: Int) -> String? {
        guard type.isScriptType || type == .plist || type == .unknown else {
            return nil
        }
        guard let handle = try? FileHandle(forReadingFrom: fileURL) else { return nil }
        defer { try? handle.close() }

        guard let data = try? handle.read(upToCount: maxBytes), !data.isEmpty else { return nil }
        let nullCount = data.reduce(into: 0) { partial, byte in
            if byte == 0 { partial += 1 }
        }
        if nullCount > 32 {
            return nil
        }
        return String(decoding: data, as: UTF8.self)
    }

    private func dedupeThreatIntelHits(_ hits: [ThreatIntelHit]) -> [ThreatIntelHit] {
        var seen = Set<String>()
        return hits.filter { hit in
            let key = "\(hit.category.rawValue)|\(hit.ruleID)|\(hit.matchedValue)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }

    private func dedupeScriptRuleHits(_ hits: [ScriptRuleHit]) -> [ScriptRuleHit] {
        var seen = Set<String>()
        return hits.filter { hit in
            let key = "\(hit.ruleID)|\(hit.lineStart)|\(hit.lineEnd)|\(hit.matchedContent)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }

    private func threatIntelSeverity(for score: Int) -> ScriptFindingSeverity {
        switch score {
        case 28...:
            return .critical
        case 18...:
            return .high
        case 10...:
            return .medium
        default:
            return .low
        }
    }

    private func computeSHA256(fileURL: URL) -> String? {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: fileURL.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
            return nil
        }

        switch commandRunner.run(executable: "/usr/bin/shasum", arguments: ["-a", "256", fileURL.path]) {
        case let .success(result):
            return result.stdout.split(separator: " ").first.map(String.init)
        case .failure:
            return nil
        }
    }

    private func collectFindings(from result: AnalysisResult) -> [String] {
        var findings: [String] = []
        if let script = result.scriptDetails {
            findings.append(contentsOf: script.summary)
            findings.append(contentsOf: script.ruleHits.map { hit in
                "[\(hit.ruleID)] \(hit.title) [\(hit.severity.rawValue)] L\(hit.lineStart)-\(hit.lineEnd) Δ\(hit.suggestedRiskScoreDelta): \(hit.matchedContent)"
            })
        }
        findings.append(contentsOf: result.sensitiveCapabilities)
        findings.append(contentsOf: result.persistenceIndicators)
        if let dynamic = result.dynamicResults {
            findings.append("Dynamic structured events: \(dynamic.events.count)")
            findings.append(contentsOf: dynamic.highRiskEvents.prefix(8).map { event in
                "[dynamic:\(event.category.rawValue)] Δ\(event.riskScoreDelta) \(event.action) -> \(event.target)"
            })
        }
        if let fileDiff = result.dynamicReport?.fileSystemDiff {
            findings.append("Filesystem diff: +\(fileDiff.added.count) ~\(fileDiff.modified.count) -\(fileDiff.deleted.count)")
            let sensitiveHits = fileDiff.records.filter(\.whetherSensitivePath).count
            if sensitiveHits > 0 {
                findings.append("Filesystem sensitive-path changes: \(sensitiveHits)")
            }
        }
        if let net = result.dynamicReport?.networkSummary {
            findings.append("Network summary: total=\(net.totalConnections), remote=\(net.remoteConnections), unique=\(net.uniqueDestinations.count)")
            findings.append(contentsOf: net.highlights.prefix(5))
        }
        if let chains = result.dynamicReport?.highRiskChains, !chains.isEmpty {
            findings.append(contentsOf: chains.prefix(5).map { "High-risk chain: \($0)" })
        }
        findings.append(contentsOf: result.warnings)
        findings.append(contentsOf: result.failureIssues.map { "\($0.code): \($0.rawMessage)" })
        return findings.uniquePreservingOrder()
    }

    private func shouldUseRandomForestPrediction() -> Bool {
        UserDefaults.standard.bool(forKey: "beforeinstall.useRandomForestPrediction")
    }

    private func applyRandomForestPrediction(result: inout AnalysisResult, fileURL: URL) {
        guard shouldUseRandomForestPrediction() else { return }

        if shouldSkipRandomForestPrediction(fileURL: fileURL, detectedType: result.basicInfo.fileType) {
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "RandomForest Model Prediction",
                    content: "skipped: container/archive-like target is excluded from RandomForest scoring"
                )
            )
            return
        }

        do {
            let prediction = try randomForestService.predict(targetURL: fileURL, commandRunner: commandRunner)
            result.randomForestPrediction = prediction

            if let error = prediction.error, !error.isEmpty {
                result.warnings.append("RandomForest prediction returned error: \(error)")
                return
            }

            guard prediction.hasUsablePrediction else {
                result.warnings.append("RandomForest prediction output is incomplete; skipped model fusion.")
                return
            }

            let probText = String(format: "%.3f", prediction.safeProbMalicious)
            var detailLines = [
                "path=\(prediction.path)",
                "verdict=\(prediction.normalizedVerdictLabel)",
                "prob_malicious=\(probText)",
                prediction.riskBucket.map { "risk_bucket=\($0)" },
                prediction.analysisScope.map { "analysis_scope=\($0)" },
                prediction.modelPath.map { "model_path=\($0)" }
            ].compactMap { $0 }

            if !prediction.heuristicReasons.isEmpty {
                detailLines.append("heuristics=\(prediction.heuristicReasons.prefix(5).joined(separator: " | "))")
            }
            if !prediction.modelActiveTopFeatures.isEmpty {
                detailLines.append("top_features=\(prediction.modelActiveTopFeatures.prefix(5).joined(separator: " | "))")
            }

            result.technicalDetails.append(
                TechnicalDetail(
                    title: "RandomForest Model Prediction",
                    content: detailLines.joined(separator: "\n")
                )
            )

            if !prediction.modelWarnings.isEmpty {
                result.warnings.append("RandomForest model warning: \(prediction.modelWarnings.prefix(2).joined(separator: " | "))")
            }

            if prediction.normalizedVerdictLabel == "malicious" || prediction.safeProbMalicious >= 0.7 {
                result.sensitiveCapabilities.append("RandomForest model flagged sample as high risk (\(prediction.normalizedVerdictLabel), p=\(probText)).")
            }
        } catch {
            result.warnings.append("RandomForest prediction failed: \(error.localizedDescription)")
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "RandomForest Model Prediction",
                    content: "failed: \(error.localizedDescription)"
                )
            )
        }
    }

    private func shouldSkipRandomForestPrediction(fileURL: URL, detectedType: SupportedFileType) -> Bool {
        switch detectedType {
        case .dmg, .pkg, .archive, .shellScript, .pythonScript, .javaScript, .appleScript, .plist:
            return true
        case .unknown:
            if !fileManager.isExecutableFile(atPath: fileURL.path) {
                return true
            }
        default:
            break
        }

        let ext = fileURL.pathExtension.lowercased()
        let excludedExtensions: Set<String> = [
            "dmg", "pkg", "mpkg", "iso",
            "zip", "tar", "gz", "tgz", "xz", "txz", "bz2", "tbz", "tbz2", "7z", "rar",
            "sh", "zsh", "bash", "command", "py", "js", "mjs", "cjs", "applescript", "scpt", "scptd",
            "plist", "json", "yaml", "yml", "toml", "xml", "txt", "md", "markdown", "html", "htm", "svg"
        ]
        return excludedExtensions.contains(ext)
    }

    private func appendDetectionDetail(to result: inout AnalysisResult, detection: FileTypeDetection) {
        result.technicalDetails.append(
            TechnicalDetail(
                title: "Type Detection",
                content: [
                    "Detected type: \(detection.detectedType.rawValue)",
                    "Source: \(detection.source.rawValue)",
                    "Detail: \(detection.detail)",
                    detection.shebang.map { "Shebang: \($0)" },
                    detection.headerDescription.map { "Header: \($0)" },
                    "Executable bit: \(detection.isExecutable)",
                    "Is Mach-O: \(detection.isMachO)"
                ]
                .compactMap { $0 }
                .joined(separator: "\n")
            )
        )
    }
}

private extension Array where Element == FailureIssue {
    func uniqueByCodeAndMessage() -> [FailureIssue] {
        var seen = Set<String>()
        return filter { issue in
            let key = "\(issue.code)|\(issue.rawMessage)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }
}
