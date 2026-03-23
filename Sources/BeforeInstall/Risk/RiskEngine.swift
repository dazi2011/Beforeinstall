import Foundation

struct RiskRule {
    let id: String
    let titleZH: String
    let titleEN: String
    let scoreDelta: Int
    let evaluate: (RiskRuleContext) -> RiskRuleMatch?
}

protocol RiskSignalProvider {
    var providerID: String { get }
    // Reserved extension hook for future cloud intel / YARA / VM / deeper system telemetry.
    func evaluate(context: RiskRuleContext) -> [RiskRuleResult]
}

struct RiskRuleMatch {
    let shortSummaryZH: String
    let shortSummaryEN: String
    let technicalDetails: String
}

struct RiskRuleContext {
    let report: ScanReport

    var result: AnalysisResult {
        report.analysisResult
    }

    var dynamicReport: DynamicAnalysisReport? {
        report.analysisResult.dynamicReport
    }

    var dynamicEvents: [AnalysisEvent] {
        report.dynamicResults?.events ?? dynamicReport?.dynamicResults?.events ?? []
    }

    var scriptHits: [ScriptRuleHit] {
        result.scriptDetails?.ruleHits ?? []
    }

    var fileDiffRecords: [FileSystemChangeRecord] {
        report.filesystemDiff?.records ?? dynamicReport?.fileSystemDiff?.records ?? []
    }

    var networkSummary: NetworkSummary? {
        report.networkSummary ?? dynamicReport?.networkSummary
    }

    var networkRecords: [NetworkConnectionRecord] {
        dynamicReport?.networkRecords ?? []
    }

    var staticFindings: [String] {
        report.findings
    }
}

struct RiskScoreWeights {
    var suspiciousDownloadExecChain = 35
    var launchAgentWrite = 30
    var shellProfilePersistence = 20
    var sampleSpawnsShell = 15
    var remoteNetworkConnect = 10
    var obfuscationOrBase64Exec = 15
    var sensitivePathModification = 20
    var signatureAnomaly = 10
    var disguisedTypeOrExtension = 10
}

final class RiskEngine {
    private let weights: RiskScoreWeights
    private let rules: [RiskRule]
    private let signalProviders: [any RiskSignalProvider]
    private let staticRiskEngine: StaticRiskEngine

    init(
        weights: RiskScoreWeights = RiskScoreWeights(),
        signalProviders: [any RiskSignalProvider] = []
    ) {
        self.weights = weights
        var providers = signalProviders
        if !providers.contains(where: { $0.providerID == "risk_finding_normalizer.v1" }) {
            providers.append(RiskFindingNormalizer())
        }
        self.signalProviders = providers
        self.rules = Self.buildRules(weights: weights)
        self.staticRiskEngine = StaticRiskEngine()
    }

    func evaluate(report: ScanReport) -> RiskEvaluation {
        let mode = report.analysisResult.analysisMode
        let profile = scoringProfileConfig()

        switch mode {
        case .staticOnly:
            let staticEvaluation = staticRiskEngine.evaluate(
                report: report,
                profileOffset: profile.scoreOffset
            )
            return applyRandomForestSignal(evaluation: staticEvaluation, report: report)
        case .combined:
            let staticEvaluation = staticRiskEngine.evaluate(
                report: report,
                profileOffset: 0
            )
            let dynamicPortion = evaluateLegacy(report: report, includeStaticSignals: false)
            let merged = mergeStaticAndDynamic(
                staticEvaluation: staticEvaluation,
                dynamicEvaluation: dynamicPortion,
                profile: profile
            )
            return applyRandomForestSignal(evaluation: merged, report: report)
        case .dynamicOnly:
            return evaluateLegacy(report: report, includeStaticSignals: true)
        }
    }

    private func evaluateLegacy(report: ScanReport, includeStaticSignals: Bool) -> RiskEvaluation {
        let context = RiskRuleContext(report: report)
        var allFindings: [RiskRuleResult] = []
        var totalScore = 0

        for rule in rules {
            if !includeStaticSignals && !isDynamicRule(rule.id) {
                continue
            }
            guard let match = rule.evaluate(context) else { continue }
            let finding = RiskRuleResult(
                id: rule.id,
                titleZH: rule.titleZH,
                titleEN: rule.titleEN,
                shortSummaryZH: match.shortSummaryZH,
                shortSummaryEN: match.shortSummaryEN,
                technicalDetails: match.technicalDetails,
                scoreDelta: rule.scoreDelta,
                severity: severityLabel(for: rule.scoreDelta),
                category: categoryForRuleID(rule.id),
                explanation: match.shortSummaryEN
            )
            allFindings.append(finding)
            totalScore += max(0, rule.scoreDelta)
        }

        for provider in signalProviders {
            if !includeStaticSignals && provider.providerID == "risk_finding_normalizer.v1" {
                continue
            }
            let providerFindings = provider.evaluate(context: context)
            if !providerFindings.isEmpty {
                allFindings.append(contentsOf: providerFindings)
                totalScore += providerFindings.reduce(0) { partialResult, finding in
                    partialResult + max(0, finding.scoreDelta)
                }
            }
        }

        let profileConfig = scoringProfileConfig()
        totalScore = max(0, min(100, totalScore + profileConfig.scoreOffset))

        let insufficient = isEvidenceInsufficient(context: context, findings: allFindings)
        let verdict: ScanVerdict
        if insufficient {
            verdict = .unknown
        } else if totalScore >= profileConfig.maliciousThreshold {
            verdict = .malicious
        } else if totalScore >= profileConfig.suspiciousThreshold {
            verdict = .suspicious
        } else {
            verdict = .clean
        }

        let topFindings = allFindings
            .sorted { lhs, rhs in
                if lhs.scoreDelta == rhs.scoreDelta {
                    return lhs.id < rhs.id
                }
                return lhs.scoreDelta > rhs.scoreDelta
            }
            .prefix(8)
            .map { $0 }

        let reasoning = buildReasoningSummary(
            verdict: verdict,
            score: totalScore,
            topFindings: topFindings,
            insufficient: insufficient
        )

        return RiskEvaluation(
            totalScore: totalScore,
            verdict: verdict,
            reasoningSummaryZH: reasoning.zh,
            reasoningSummaryEN: reasoning.en,
            topFindings: topFindings,
            allFindings: allFindings,
            isEvidenceInsufficient: insufficient,
            staticScoringTrace: nil,
            findingsTrace: nil,
            scoreCapTrace: nil,
            contextTrace: nil
        )
    }

    private func mergeStaticAndDynamic(
        staticEvaluation: RiskEvaluation,
        dynamicEvaluation: RiskEvaluation,
        profile: (scoreOffset: Int, suspiciousThreshold: Int, maliciousThreshold: Int)
    ) -> RiskEvaluation {
        let mergedFindings = (staticEvaluation.allFindings + dynamicEvaluation.allFindings)
            .uniqueByIDAndDetails()
            .sorted { lhs, rhs in
                if lhs.scoreDelta == rhs.scoreDelta {
                    return lhs.id < rhs.id
                }
                return lhs.scoreDelta > rhs.scoreDelta
            }

        var totalScore = staticEvaluation.totalScore + dynamicEvaluation.totalScore + profile.scoreOffset
        totalScore = max(0, min(100, totalScore))

        let verdict: ScanVerdict
        if totalScore >= profile.maliciousThreshold {
            // Combined mode keeps malicious classification strict: need strong static score or strong dynamic evidence.
            if staticEvaluation.totalScore >= 82 || dynamicEvaluation.totalScore >= 45 {
                verdict = .malicious
            } else {
                verdict = .suspicious
            }
        } else if totalScore >= profile.suspiciousThreshold {
            verdict = .suspicious
        } else {
            verdict = .clean
        }

        let topFindings = Array(mergedFindings.prefix(8))
        let reasoning = (
            zh: "组合模式已合并静态与动态证据。静态分 \(staticEvaluation.totalScore) + 动态分 \(dynamicEvaluation.totalScore) = 总分 \(totalScore)。",
            en: "Combined mode merged static and dynamic evidence. Static \(staticEvaluation.totalScore) + dynamic \(dynamicEvaluation.totalScore) = total \(totalScore)."
        )

        return RiskEvaluation(
            totalScore: totalScore,
            verdict: verdict,
            reasoningSummaryZH: reasoning.zh,
            reasoningSummaryEN: reasoning.en,
            topFindings: topFindings,
            allFindings: mergedFindings,
            isEvidenceInsufficient: staticEvaluation.isEvidenceInsufficient && dynamicEvaluation.isEvidenceInsufficient,
            staticScoringTrace: staticEvaluation.staticScoringTrace,
            findingsTrace: staticEvaluation.findingsTrace,
            scoreCapTrace: staticEvaluation.scoreCapTrace,
            contextTrace: staticEvaluation.contextTrace
        )
    }

    private func applyRandomForestSignal(
        evaluation: RiskEvaluation,
        report: ScanReport
    ) -> RiskEvaluation {
        if isRandomForestExcludedTarget(report) {
            return evaluation
        }
        guard let prediction = report.analysisResult.randomForestPrediction,
              prediction.hasUsablePrediction
        else {
            return evaluation
        }

        let delta = randomForestScoreDelta(for: prediction)
        let aiFinding = randomForestFinding(prediction: prediction, scoreDelta: delta)

        var mergedFindings = evaluation.allFindings + [aiFinding]
        mergedFindings = mergedFindings
            .uniqueByIDAndDetails()
            .sorted { lhs, rhs in
                if lhs.scoreDelta == rhs.scoreDelta {
                    return lhs.id < rhs.id
                }
                return lhs.scoreDelta > rhs.scoreDelta
            }

        var mergedScore = max(0, min(100, evaluation.totalScore + delta))
        var appliedFloor: Int?
        if isHighRiskRandomForest(prediction), shouldApplyRandomForestFloor(for: report.detectedType) {
            let floor = minimumScoreForHighRiskRandomForest(currentProfile: currentScoringProfile())
            if mergedScore < floor {
                mergedScore = floor
                appliedFloor = floor
            }
        }
        let mergedVerdict = adjustVerdictWithRandomForest(
            current: evaluation.verdict,
            score: mergedScore,
            prediction: prediction
        )
        let topFindings = Array(mergedFindings.prefix(8))

        let rfSummary = randomForestReasoningLine(prediction: prediction, delta: delta)
        let summaryZH = [evaluation.reasoningSummaryZH, rfSummary.zh]
            .filter { !$0.isEmpty }
            .joined(separator: " ")
        let summaryEN = [evaluation.reasoningSummaryEN, rfSummary.en]
            .filter { !$0.isEmpty }
            .joined(separator: " ")

        var trace = evaluation.staticScoringTrace
        if var currentTrace = trace {
            currentTrace.notes.append("random_forest.label=\(prediction.normalizedVerdictLabel)")
            currentTrace.notes.append(String(format: "random_forest.prob=%.6f", prediction.safeProbMalicious))
            currentTrace.notes.append("random_forest.delta=\(delta)")
            if let appliedFloor {
                currentTrace.notes.append("random_forest.profile_floor=\(appliedFloor)")
            }
            currentTrace.notes = currentTrace.notes.uniquePreservingOrder()
            currentTrace.finalScore = mergedScore
            currentTrace.verdict = mergedVerdict.rawValue
            trace = currentTrace
        }

        return RiskEvaluation(
            totalScore: mergedScore,
            verdict: mergedVerdict,
            reasoningSummaryZH: summaryZH,
            reasoningSummaryEN: summaryEN,
            topFindings: topFindings,
            allFindings: mergedFindings,
            isEvidenceInsufficient: false,
            staticScoringTrace: trace,
            findingsTrace: evaluation.findingsTrace,
            scoreCapTrace: evaluation.scoreCapTrace,
            contextTrace: evaluation.contextTrace
        )
    }

    private func randomForestFinding(
        prediction: RandomForestPredictionResult,
        scoreDelta: Int
    ) -> RiskRuleResult {
        let probText = String(format: "%.3f", prediction.safeProbMalicious)
        let verdict = prediction.normalizedVerdictLabel
        let summaryZH = "随机森林预测 \(verdict)（恶意概率 \(probText)）。"
        let summaryEN = "Random-Forest predicted \(verdict) (malicious probability \(probText))."
        let topFeature = prediction.modelActiveTopFeatures.first ?? "-"
        let riskBucket = prediction.riskBucket ?? "-"

        let severity: String
        if scoreDelta >= 35 {
            severity = "critical"
        } else if scoreDelta >= 20 {
            severity = "high"
        } else if scoreDelta >= 8 {
            severity = "medium"
        } else if scoreDelta < 0 {
            severity = "info"
        } else {
            severity = "low"
        }

        return RiskRuleResult(
            id: "ai.random_forest_prediction",
            titleZH: "随机森林模型预测",
            titleEN: "Random-Forest Model Prediction",
            shortSummaryZH: summaryZH,
            shortSummaryEN: summaryEN,
            technicalDetails: "label=\(verdict), prob=\(probText), risk_bucket=\(riskBucket), top_feature=\(topFeature)",
            scoreDelta: scoreDelta,
            severity: severity,
            category: "ai",
            explanation: summaryEN,
            confidence: prediction.safeProbMalicious >= 0.8 || prediction.safeProbMalicious <= 0.2 ? "high" : "medium",
            evidenceStrength: prediction.safeProbMalicious >= 0.75 || prediction.safeProbMalicious <= 0.15 ? "strong" : "moderate",
            executionSemantics: "model_prediction",
            scoreDeltaBase: scoreDelta,
            sourceLocation: prediction.path,
            tags: ["ai", "random_forest", "python_bridge"],
            typeScorer: "RandomForestModel"
        )
    }

    private func randomForestScoreDelta(for prediction: RandomForestPredictionResult) -> Int {
        let prob = prediction.safeProbMalicious
        let label = prediction.normalizedVerdictLabel

        switch label {
        case "malicious":
            if prob >= 0.95 { return 30 }
            if prob >= 0.90 { return 26 }
            if prob >= 0.80 { return 22 }
            if prob >= 0.70 { return 18 }
            return 12
        case "container_suspicious":
            if prob >= 0.75 { return 16 }
            if prob >= 0.60 { return 12 }
            return 8
        case "container_needs_deeper_inspection":
            if prob >= 0.65 { return 12 }
            if prob >= 0.50 { return 8 }
            return 5
        case "container_low_risk":
            if prob <= 0.20 { return -6 }
            return -2
        case "benign":
            if prob <= 0.08 { return -14 }
            if prob <= 0.15 { return -10 }
            if prob <= 0.25 { return -6 }
            return -4
        default:
            if prob >= 0.85 { return 18 }
            if prob >= 0.65 { return 12 }
            if prob >= 0.45 { return 8 }
            if prob <= 0.15 { return -6 }
            return 3
        }
    }

    private func adjustVerdictWithRandomForest(
        current: ScanVerdict,
        score: Int,
        prediction: RandomForestPredictionResult
    ) -> ScanVerdict {
        let label = prediction.normalizedVerdictLabel
        let prob = prediction.safeProbMalicious
        var updated = current

        if label == "malicious" {
            if prob >= 0.90 || score >= 78 {
                updated = .malicious
            } else if prob >= 0.70 {
                updated = maxVerdict(updated, .suspicious)
            }
        } else if label == "container_suspicious" || label == "container_needs_deeper_inspection" {
            if prob >= 0.58 {
                updated = maxVerdict(updated, .suspicious)
            }
        } else if (label == "benign" || label == "container_low_risk")
            && prob <= 0.12
            && score < 35
            && current != .malicious
        {
            updated = .clean
        }

        return updated
    }

    private func maxVerdict(_ lhs: ScanVerdict, _ rhs: ScanVerdict) -> ScanVerdict {
        verdictRank(lhs) >= verdictRank(rhs) ? lhs : rhs
    }

    private func verdictRank(_ verdict: ScanVerdict) -> Int {
        switch verdict {
        case .unknown:
            return 0
        case .clean:
            return 1
        case .suspicious:
            return 2
        case .malicious:
            return 3
        }
    }

    private func randomForestReasoningLine(
        prediction: RandomForestPredictionResult,
        delta: Int
    ) -> (zh: String, en: String) {
        let probText = String(format: "%.3f", prediction.safeProbMalicious)
        let label = prediction.normalizedVerdictLabel
        let bucket = prediction.riskBucket ?? "-"
        let direction = delta >= 0 ? "+" : ""

        return (
            zh: "AI 模型结果：\(label)，恶意概率 \(probText)，风险桶 \(bucket)，评分调整 \(direction)\(delta)。",
            en: "AI model output: \(label), malicious probability \(probText), bucket \(bucket), score adjustment \(direction)\(delta)."
        )
    }

    private func isRandomForestExcludedType(_ type: SupportedFileType) -> Bool {
        switch type {
        case .dmg, .pkg, .archive, .shellScript, .pythonScript, .javaScript, .appleScript, .plist:
            return true
        default:
            return false
        }
    }

    private func isRandomForestExcludedTarget(_ report: ScanReport) -> Bool {
        if isRandomForestExcludedType(report.detectedType) {
            return true
        }

        let ext = URL(fileURLWithPath: report.filePath).pathExtension.lowercased()
        return randomForestExcludedExtensions.contains(ext)
    }

    private var randomForestExcludedExtensions: Set<String> {
        [
            "dmg", "pkg", "mpkg", "iso",
            "zip", "tar", "gz", "tgz", "xz", "txz", "bz2", "tbz", "tbz2", "7z", "rar",
            "sh", "zsh", "bash", "command", "py", "js", "mjs", "cjs", "applescript", "scpt", "scptd",
            "plist", "json", "yaml", "yml", "toml", "xml", "txt", "md", "markdown", "html", "htm", "svg"
        ]
    }

    private func isHighRiskRandomForest(_ prediction: RandomForestPredictionResult) -> Bool {
        prediction.normalizedVerdictLabel == "malicious" && prediction.safeProbMalicious >= 0.70
    }

    private func shouldApplyRandomForestFloor(for type: SupportedFileType) -> Bool {
        switch type {
        case .appBundle, .machO, .dylib:
            return true
        default:
            return false
        }
    }

    private func currentScoringProfile() -> ScoringProfile {
        let raw = UserDefaults.standard.string(forKey: "beforeinstall.scoringProfile") ?? ""
        return ScoringProfile(rawValue: raw) ?? .balanced
    }

    private func minimumScoreForHighRiskRandomForest(currentProfile: ScoringProfile) -> Int {
        switch currentProfile {
        case .optimistic:
            return 60
        case .balanced:
            return 70
        case .aggressive:
            return 80
        }
    }

    private func scoringProfileConfig() -> (scoreOffset: Int, suspiciousThreshold: Int, maliciousThreshold: Int) {
        let raw = UserDefaults.standard.string(forKey: "beforeinstall.scoringProfile") ?? ""
        switch ScoringProfile(rawValue: raw) ?? .balanced {
        case .optimistic:
            return (scoreOffset: -8, suspiciousThreshold: 38, maliciousThreshold: 72)
        case .balanced:
            return (scoreOffset: 0, suspiciousThreshold: 30, maliciousThreshold: 60)
        case .aggressive:
            return (scoreOffset: 8, suspiciousThreshold: 24, maliciousThreshold: 50)
        }
    }

    func evaluate(result: AnalysisResult) -> RiskEvaluation {
        evaluate(report: buildSyntheticReport(from: result))
    }

    func toLegacyAssessment(_ evaluation: RiskEvaluation, language: AppLanguage) -> RiskAssessment {
        let level: RiskLevel
        switch evaluation.verdict {
        case .clean:
            level = .low
        case .suspicious:
            level = .medium
        case .malicious:
            level = .high
        case .unknown:
            level = .medium
        }

        let breakdown = evaluation.allFindings.map { finding in
            RiskReason(
                id: finding.id,
                titleZH: finding.titleZH,
                titleEN: finding.titleEN,
                delta: finding.scoreDelta,
                evidence: finding.technicalDetails
            )
        }

        var reasons = evaluation.topFindings.map { $0.shortSummary(language: language) }
        if evaluation.isEvidenceInsufficient {
            reasons.append(language == .zhHans ? "证据不足，结论保守。" : "Evidence is insufficient; conclusion is conservative.")
        }

        return RiskAssessment(
            level: level,
            score: evaluation.totalScore,
            reasons: reasons.uniquePreservingOrder(),
            breakdown: breakdown
        )
    }

    func assess(_ result: AnalysisResult, language: AppLanguage) -> RiskAssessment {
        let evaluation = evaluate(result: result)
        return toLegacyAssessment(evaluation, language: language)
    }

    private func buildSyntheticReport(from result: AnalysisResult) -> ScanReport {
        ScanReport(
            analyzedAt: result.analyzedAt,
            filePath: result.basicInfo.fullPath,
            detectedType: result.basicInfo.fileType,
            fileSizeBytes: result.basicInfo.fileSizeBytes,
            sha256: result.genericDetails?.sha256,
            signingInfo: result.signatureInfo,
            findings: collectSyntheticFindings(from: result),
            riskScore: result.riskAssessment.score,
            finalVerdict: .unknown,
            reasoningSummary: "",
            topFindings: [],
            riskEvaluation: result.riskEvaluation,
            filesystemDiff: result.dynamicReport?.fileSystemDiff,
            networkSummary: result.dynamicReport?.networkSummary,
            dynamicResults: result.dynamicResults ?? result.dynamicReport?.dynamicResults,
            analysisResult: result,
            detection: FileTypeDetection(
                detectedType: result.basicInfo.fileType,
                source: .unknown,
                detail: "synthetic",
                shebang: nil,
                magicDescription: nil,
                headerDescription: nil,
                isExecutable: result.basicInfo.fileType.isExecutableLike,
                isMachO: result.basicInfo.fileType == .machO || result.basicInfo.fileType == .dylib
            )
        )
    }

    private func collectSyntheticFindings(from result: AnalysisResult) -> [String] {
        var findings: [String] = []
        findings.append(contentsOf: result.sensitiveCapabilities)
        findings.append(contentsOf: result.persistenceIndicators)
        if let model = result.randomForestPrediction, model.hasUsablePrediction {
            findings.append("random_forest.label=\(model.normalizedVerdictLabel)")
            findings.append(String(format: "random_forest.prob=%.6f", model.safeProbMalicious))
            if let bucket = model.riskBucket {
                findings.append("random_forest.bucket=\(bucket)")
            }
            findings.append(contentsOf: model.heuristicReasons.prefix(4).map { "random_forest.reason=\($0)" })
        }
        if let script = result.scriptDetails {
            findings.append(contentsOf: script.summary)
            findings.append(contentsOf: script.ruleHits.map(\.ruleID))
        }
        if let dynamic = result.dynamicResults {
            findings.append("dynamic.events=\(dynamic.events.count)")
            findings.append(contentsOf: dynamic.events.map { "\($0.category.rawValue):\($0.action)" })
        }
        if let diff = result.dynamicReport?.fileSystemDiff {
            findings.append("fs.added=\(diff.added.count)")
            findings.append("fs.modified=\(diff.modified.count)")
            findings.append("fs.deleted=\(diff.deleted.count)")
        }
        if let network = result.dynamicReport?.networkSummary {
            findings.append("network.remote=\(network.remoteConnections)")
            findings.append(contentsOf: network.highlights)
        }
        return findings.uniquePreservingOrder()
    }

    private static func buildRules(weights: RiskScoreWeights) -> [RiskRule] {
        var rules: [RiskRule] = []

        rules.append(
            RiskRule(
                id: "script.download_execute_chain",
                titleZH: "可疑脚本下载执行链",
                titleEN: "Suspicious Script Download-and-Execute Chain",
                scoreDelta: weights.suspiciousDownloadExecChain,
                evaluate: { ctx in
                    let staticDownloadHint = ctx.staticFindings.first(where: { finding in
                        let lower = finding.lowercased()
                        return (lower.contains("curl") || lower.contains("wget") || lower.contains("download"))
                            && (lower.contains("| sh") || lower.contains("execute") || lower.contains("exec"))
                    })

                    let hit = ctx.scriptHits.first(where: { hit in
                        [
                            "shell.curl_pipe_sh",
                            "shell.wget_pipe_sh",
                            "shell.mktemp_download_exec",
                            "applescript.download_execute",
                            "javascript.network_download_exec"
                        ].contains(hit.ruleID)
                    }) ?? ctx.dynamicEvents.first(where: { event in
                        event.category == .scriptExecuted
                            && (event.action.contains("download") || event.action == "mktemp_download_chain")
                    }).map { event in
                        ScriptRuleHit(
                            ruleID: event.action,
                            title: event.action,
                            severity: .high,
                            matchedContent: event.target,
                            lineStart: 0,
                            lineEnd: 0,
                            explanation: event.action,
                            suggestedRiskScoreDelta: event.riskScoreDelta
                        )
                    } ?? staticDownloadHint.map { finding in
                        ScriptRuleHit(
                            ruleID: "static.download_exec_hint",
                            title: "static download-exec hint",
                            severity: .medium,
                            matchedContent: finding,
                            lineStart: 0,
                            lineEnd: 0,
                            explanation: "static finding",
                            suggestedRiskScoreDelta: weights.suspiciousDownloadExecChain
                        )
                    }

                    guard let hit else { return nil }
                    return RiskRuleMatch(
                        shortSummaryZH: "出现了“下载后立即执行”行为，常用于投递二阶段载荷。",
                        shortSummaryEN: "A download-then-execute pattern was observed, commonly used for staged payload delivery.",
                        technicalDetails: "\(hit.ruleID): \(hit.matchedContent)"
                    )
                }
            )
        )

        rules.append(
            RiskRule(
                id: "persistence.launch_agent_write",
                titleZH: "写入 LaunchAgent / LaunchDaemon",
                titleEN: "LaunchAgent / LaunchDaemon Write",
                scoreDelta: weights.launchAgentWrite,
                evaluate: { ctx in
                    let hit = ctx.fileDiffRecords.first { record in
                        let lower = record.path.lowercased()
                        return lower.contains("launchagents") || lower.contains("launchdaemons")
                    } ?? ctx.scriptHits.first(where: { hit in
                        let id = hit.ruleID.lowercased()
                        if id == "shell.write_launchagent" || id == "shell.launchctl.persistence" {
                            return true
                        }
                        let content = hit.matchedContent.lowercased()
                        return content.contains("launchagents")
                            || content.contains("launchdaemons")
                            || content.contains("launchctl")
                    }).map { hit in
                        FileSystemChangeRecord(
                            path: hit.matchedContent,
                            changeType: .modified,
                            fileSize: nil,
                            modifiedTime: nil,
                            hash: nil,
                            whetherSensitivePath: true,
                            detectedType: .plist
                        )
                    } ?? ctx.dynamicEvents.first(where: { event in
                        event.category == .persistenceAttempt
                            && (event.target.lowercased().contains("launchagents") || event.target.lowercased().contains("launchdaemons"))
                    }).map { event in
                        FileSystemChangeRecord(
                            path: event.target,
                            changeType: .added,
                            fileSize: nil,
                            modifiedTime: nil,
                            hash: nil,
                            whetherSensitivePath: true,
                            detectedType: .plist
                        )
                    }

                    guard let hit else { return nil }
                    return RiskRuleMatch(
                        shortSummaryZH: "样本写入了启动项目录，存在开机/登录持久化风险。",
                        shortSummaryEN: "The sample wrote into startup item paths, indicating persistence risk.",
                        technicalDetails: hit.path
                    )
                }
            )
        )

        rules.append(
            RiskRule(
                id: "persistence.shell_profile",
                titleZH: "Shell Profile 持久化",
                titleEN: "Shell Profile Persistence",
                scoreDelta: weights.shellProfilePersistence,
                evaluate: { ctx in
                    let hit = ctx.fileDiffRecords.first { record in
                        let lower = record.path.lowercased()
                        return lower.hasSuffix("/.zshrc")
                            || lower.hasSuffix("/.bash_profile")
                            || lower.hasSuffix("/.bashrc")
                    } ?? ctx.scriptHits.first(where: { $0.ruleID == "shell.profile_persistence" }).map { hit in
                        FileSystemChangeRecord(
                            path: hit.matchedContent,
                            changeType: .modified,
                            fileSize: nil,
                            modifiedTime: nil,
                            hash: nil,
                            whetherSensitivePath: true,
                            detectedType: .shellScript
                        )
                    }

                    guard let hit else { return nil }
                    return RiskRuleMatch(
                        shortSummaryZH: "样本修改了 shell 启动配置，可能用于长期驻留。",
                        shortSummaryEN: "The sample modified shell startup profiles, which may indicate persistence.",
                        technicalDetails: hit.path
                    )
                }
            )
        )

        rules.append(
            RiskRule(
                id: "process.spawn_shell",
                titleZH: "样本拉起 Shell 子进程",
                titleEN: "Sample Spawned Shell Child Process",
                scoreDelta: weights.sampleSpawnsShell,
                evaluate: { ctx in
                    let hit = ctx.dynamicEvents.first(where: { event in
                        event.category == .scriptExecuted && event.action == "child_shell_spawned"
                    }) ?? ctx.dynamicEvents.first(where: { event in
                        guard event.category == .processCreated else { return false }
                        let lower = (event.processName ?? event.target).lowercased()
                        return lower.contains("bash") || lower.contains("zsh") || lower.contains("/bin/sh") || lower == "sh"
                    })

                    guard let hit else { return nil }
                    return RiskRuleMatch(
                        shortSummaryZH: "样本运行期间派生出 shell 进程，执行链可控性较高。",
                        shortSummaryEN: "A shell process was spawned during execution, increasing command-execution risk.",
                        technicalDetails: hit.target
                    )
                }
            )
        )

        rules.append(
            RiskRule(
                id: "network.remote_connect",
                titleZH: "运行期远程网络连接",
                titleEN: "Remote Network Connection During Execution",
                scoreDelta: weights.remoteNetworkConnect,
                evaluate: { ctx in
                    if let record = ctx.networkRecords.first(where: { $0.whetherRemote }) {
                        return RiskRuleMatch(
                            shortSummaryZH: "样本在运行期间主动连接了远程主机。",
                            shortSummaryEN: "The sample made outbound connections to remote hosts at runtime.",
                            technicalDetails: "\(record.processName)(\(record.processID)) -> \(record.destination):\(record.port)"
                        )
                    }
                    if let summary = ctx.networkSummary, summary.remoteConnections > 0, let first = summary.uniqueDestinations.first {
                        return RiskRuleMatch(
                            shortSummaryZH: "样本存在远程外连行为。",
                            shortSummaryEN: "Remote outbound network behavior was observed.",
                            technicalDetails: "remote=\(summary.remoteConnections), first=\(first)"
                        )
                    }
                    return nil
                }
            )
        )

        rules.append(
            RiskRule(
                id: "script.obfuscation_base64_exec",
                titleZH: "混淆 / Base64 解码执行",
                titleEN: "Obfuscation / Base64 Decode-and-Execute",
                scoreDelta: weights.obfuscationOrBase64Exec,
                evaluate: { ctx in
                    let hasExecutionHint = ctx.scriptHits.contains(where: { hit in
                        let id = hit.ruleID.lowercased()
                        return id.contains("exec")
                            || id.contains("system")
                            || id.contains("subprocess")
                            || id.contains("child_process")
                            || id.contains("do_shell_script")
                            || id.contains("osascript_shell")
                    }) || ctx.staticFindings.contains(where: { finding in
                        let lower = finding.lowercased()
                        return lower.contains("| sh")
                            || lower.contains("would execute")
                            || lower.contains("execute")
                            || lower.contains("exec(")
                    })

                    let staticObfuscationHint = ctx.staticFindings.first(where: { finding in
                        let lower = finding.lowercased()
                        return lower.contains("base64")
                            || lower.contains("obfus")
                            || lower.contains("eval(")
                            || lower.contains("exec(")
                    })

                    let hit = ctx.scriptHits.first(where: { hit in
                        hit.ruleID == "shell.base64_exec"
                            || hit.ruleID == "javascript.eval"
                            || hit.ruleID == "python.eval_exec"
                            || (hasExecutionHint && (hit.ruleID == "python.obfuscation" || hit.ruleID == "javascript.base64_obfuscation"))
                    }) ?? ctx.dynamicEvents.first(where: { event in
                        event.category == .scriptExecuted && event.action == "base64_decode_execute_chain"
                    }).map { event in
                        ScriptRuleHit(
                            ruleID: event.action,
                            title: event.action,
                            severity: .high,
                            matchedContent: event.target,
                            lineStart: 0,
                            lineEnd: 0,
                            explanation: event.action,
                            suggestedRiskScoreDelta: event.riskScoreDelta
                        )
                    } ?? (hasExecutionHint ? staticObfuscationHint : nil).map { finding in
                        ScriptRuleHit(
                            ruleID: "static.obfuscation_hint",
                            title: "static obfuscation hint",
                            severity: .medium,
                            matchedContent: finding,
                            lineStart: 0,
                            lineEnd: 0,
                            explanation: "static finding",
                            suggestedRiskScoreDelta: weights.obfuscationOrBase64Exec
                        )
                    }

                    guard let hit else { return nil }
                    return RiskRuleMatch(
                        shortSummaryZH: "检测到编码/混淆后执行行为，存在规避审计迹象。",
                        shortSummaryEN: "Encoded/obfuscated execution behavior was detected, suggesting evasion intent.",
                        technicalDetails: "\(hit.ruleID): \(hit.matchedContent)"
                    )
                }
            )
        )

        rules.append(
            RiskRule(
                id: "filesystem.sensitive_path_change",
                titleZH: "修改敏感路径",
                titleEN: "Sensitive Path Modification",
                scoreDelta: weights.sensitivePathModification,
                evaluate: { ctx in
                    guard let hit = ctx.fileDiffRecords.first(where: { $0.whetherSensitivePath }) else {
                        return nil
                    }
                    return RiskRuleMatch(
                        shortSummaryZH: "样本修改了系统/用户敏感目录，潜在影响范围较大。",
                        shortSummaryEN: "The sample modified sensitive system/user paths with potentially broad impact.",
                        technicalDetails: "\(hit.changeType.rawValue): \(hit.path)"
                    )
                }
            )
        )

        rules.append(
            RiskRule(
                id: "signature.anomaly",
                titleZH: "签名异常或可执行无签名",
                titleEN: "Signature Anomaly or Unsigned Executable",
                scoreDelta: weights.signatureAnomaly,
                evaluate: { ctx in
                    guard Self.shouldApplySignatureRule(result: ctx.result) else { return nil }
                    guard let signature = ctx.result.signatureInfo else {
                        let staticUnsignedHint = ctx.staticFindings.contains { finding in
                            finding.lowercased().contains("unsigned") || finding.lowercased().contains("no valid signature")
                        }
                        guard staticUnsignedHint || ctx.result.genericDetails?.isExecutable == true else { return nil }
                        return RiskRuleMatch(
                            shortSummaryZH: "未获取到可执行样本签名信息。",
                            shortSummaryEN: "No signature metadata was available for an executable-like sample.",
                            technicalDetails: "signatureInfo=nil"
                        )
                    }
                    guard !signature.isSigned else { return nil }
                    return RiskRuleMatch(
                        shortSummaryZH: "样本可执行但未签名，来源可信度不足。",
                        shortSummaryEN: "The sample is executable-like but unsigned.",
                        technicalDetails: "isSigned=false"
                    )
                }
            )
        )

        rules.append(
            RiskRule(
                id: "type.masquerading",
                titleZH: "伪装类型 / 可疑扩展",
                titleEN: "Masquerading Type / Suspicious Extension",
                scoreDelta: weights.disguisedTypeOrExtension,
                evaluate: { ctx in
                    if ctx.result.genericDetails?.isPossiblyDisguised == true {
                        return RiskRuleMatch(
                            shortSummaryZH: "文件扩展名与内容类型不一致，存在伪装风险。",
                            shortSummaryEN: "The file extension does not match content type (possible masquerading).",
                            technicalDetails: "genericDetails.isPossiblyDisguised=true"
                        )
                    }

                    let detection = ctx.report.detection
                    if detection.source == .fileExtension && detection.detectedType == .unknown && ctx.result.basicInfo.fileType.isExecutableLike {
                        return RiskRuleMatch(
                            shortSummaryZH: "主要依赖扩展名识别，真实类型存在不确定性。",
                            shortSummaryEN: "Type identification relied on extension with uncertain executable semantics.",
                            technicalDetails: "detection=\(detection.source.rawValue), type=\(detection.detectedType.rawValue)"
                        )
                    }
                    if let suspiciousFinding = ctx.staticFindings.first(where: { finding in
                        let lower = finding.lowercased()
                        return lower.contains("masquerad")
                            || lower.contains("disguised")
                            || lower.contains("extension does not match")
                    }) {
                        return RiskRuleMatch(
                            shortSummaryZH: "静态分析发现扩展名与实际内容不一致的迹象。",
                            shortSummaryEN: "Static analysis found hints that extension and content do not match.",
                            technicalDetails: suspiciousFinding
                        )
                    }
                    return nil
                }
            )
        )

        return rules
    }

    private func severityLabel(for scoreDelta: Int) -> String {
        switch scoreDelta {
        case 35...:
            return "critical"
        case 20...:
            return "high"
        case 10...:
            return "medium"
        default:
            return "low"
        }
    }

    private func categoryForRuleID(_ ruleID: String) -> String {
        let lower = ruleID.lowercased()
        if lower.contains("random_forest") || lower.hasPrefix("ai.") {
            return "ai"
        }
        if lower.contains("signature") {
            return "signature"
        }
        if lower.contains("type") || lower.contains("masquerading") {
            return "type"
        }
        if lower.contains("network") || lower.contains("download") {
            return "network"
        }
        if lower.contains("persist") || lower.contains("launch") || lower.contains("profile") {
            return "persistence"
        }
        if lower.contains("obfuscation") || lower.contains("base64") || lower.contains("eval") {
            return "obfuscation"
        }
        if lower.contains("process") || lower.contains("shell") || lower.contains("execute") {
            return "execution"
        }
        if lower.contains("filesystem") {
            return "filesystem"
        }
        return "generic"
    }

    private func isDynamicRule(_ ruleID: String) -> Bool {
        let lower = ruleID.lowercased()
        return lower.contains("process.")
            || lower.contains("network.")
            || lower.contains("filesystem.")
            || lower.contains("launch_agent_write")
            || lower.contains("shell_profile")
    }

    private static func shouldApplySignatureRule(result: AnalysisResult) -> Bool {
        switch result.basicInfo.fileType {
        case .machO, .dylib, .appBundle:
            return true
        default:
            break
        }

        if result.dynamicReport != nil, result.basicInfo.fileType == .unknown {
            return result.genericDetails?.isExecutable == true
        }

        let header = result.genericDetails?.fileTypeByMagic?.lowercased() ?? ""
        if header.contains("mach-o") || header.contains("dynamically linked shared library") {
            return true
        }

        return false
    }

    private func isEvidenceInsufficient(context: RiskRuleContext, findings: [RiskRuleResult]) -> Bool {
        if !findings.isEmpty {
            return false
        }

        if let modelPrediction = context.result.randomForestPrediction, modelPrediction.hasUsablePrediction {
            return false
        }

        let result = context.result
        let dynamicRequested = result.analysisMode == .dynamicOnly || result.analysisMode == .combined
        let dynamicMissingOrFailed: Bool = {
            guard dynamicRequested else { return false }
            guard let dynamic = result.dynamicReport else { return true }
            switch dynamic.overview.status {
            case .failed, .skipped, .partial:
                return true
            default:
                return false
            }
        }()

        let noStaticDepth = result.signatureInfo == nil
            && result.scriptDetails == nil
            && result.genericDetails == nil
            && result.technicalDetails.isEmpty

        return dynamicMissingOrFailed || noStaticDepth
    }

    private func buildReasoningSummary(
        verdict: ScanVerdict,
        score: Int,
        topFindings: [RiskRuleResult],
        insufficient: Bool
    ) -> (zh: String, en: String) {
        if insufficient || verdict == .unknown {
            return (
                zh: "当前证据不足，无法给出稳定结论。建议补充权限后重跑动态分析，重点关注文件改动与网络连接。",
                en: "Evidence is insufficient for a stable conclusion. Re-run dynamic analysis with better permissions and focus on file/network behaviors."
            )
        }

        if topFindings.isEmpty {
            return (
                zh: "未发现明显高风险行为，当前评分 \(score)/100，判定 \(verdict.displayName(language: .zhHans))。",
                en: "No obvious high-risk behavior was observed. Current score is \(score)/100, verdict: \(verdict.displayName(language: .en))."
            )
        }

        let zhCore = topFindings.prefix(3).map { $0.shortSummaryZH }.joined(separator: "；")
        let enCore = topFindings.prefix(3).map { $0.shortSummaryEN }.joined(separator: "; ")
        return (
            zh: "该样本\(zhCore)。综合评分 \(score)/100，判定 \(verdict.displayName(language: .zhHans))。",
            en: "The sample showed: \(enCore). Final score \(score)/100, verdict: \(verdict.displayName(language: .en))."
        )
    }
}

final class PlainSummaryBuilder {
    func build(for result: AnalysisResult, language: AppLanguage) -> [String] {
        language == .zhHans ? buildChinese(for: result) : buildEnglish(for: result)
    }

    private func buildChinese(for result: AnalysisResult) -> [String] {
        var lines: [String] = []

        if let signature = result.signatureInfo {
            if signature.isSigned {
                lines.append("该文件已签名。")
                if let signer = signature.signerName {
                    lines.append("签名主体：\(signer)。")
                }
                if signature.isLikelyNotarized == true {
                    lines.append("检测到 notarization 信号，分发链路相对规范。")
                }
            } else {
                lines.append("未检测到有效签名，来源可信度较难判断。")
            }
        } else {
            lines.append("未获得完整签名信息。")
        }

        if let script = result.scriptDetails {
            lines.append("脚本分析命中 \(script.ruleHits.count) 条规则。")
            lines.append(contentsOf: script.summary.map { "脚本结论：\($0)。" })
        }

        if let dynamic = result.dynamicReport {
            switch dynamic.overview.status {
            case .completed:
                lines.append("动态分析已完成，运行时长约 \(Int(dynamic.overview.actualDuration)) 秒。")
            case .interrupted:
                lines.append("动态分析被用户中断，结论仅覆盖已观察片段。")
            case .failed:
                lines.append("动态分析启动失败或中途失败，动态结论不足。")
            case .noObservableActivity:
                lines.append("动态分析已执行，未观察到明显高风险行为。")
            default:
                lines.append("动态分析未完整执行，当前结论偏保守。")
            }

            if dynamic.overview.hasPersistenceAttempt {
                lines.append("运行期间观察到持久化目录写入，风险上升。")
            }

            if dynamic.overview.hasNetworkActivity {
                lines.append("运行期间观察到网络连接行为。")
            }

            if !dynamic.suspiciousIndicators.isEmpty {
                lines.append("检测到可疑行为指标，建议人工复核技术详情。")
            }

            if let session = result.dynamicResults ?? dynamic.dynamicResults {
                lines.append("结构化动态事件 \(session.events.count) 条，高风险事件 \(session.highRiskEvents.count) 条。")
            }
        } else if result.analysisMode == .dynamicOnly || result.analysisMode == .combined {
            lines.append("未获得有效动态结果，建议导出日志后重试。")
        }

        if let generic = result.genericDetails, generic.isPossiblyDisguised {
            lines.append("扩展名与真实文件类型不匹配，存在伪装风险。")
        }

        if let model = result.randomForestPrediction, model.hasUsablePrediction {
            lines.append(
                String(
                    format: "随机森林模型预测：%@（恶意概率 %.3f）。",
                    model.normalizedVerdictLabel,
                    model.safeProbMalicious
                )
            )
            if let bucket = model.riskBucket, !bucket.isEmpty {
                lines.append("模型风险桶：\(bucket)。")
            }
        }

        if !result.failureIssues.isEmpty {
            lines.append("部分模块执行失败，已给出可操作建议。")
        }

        lines.append("综合风险等级：\(result.riskAssessment.level.displayName(language: .zhHans))（\(result.riskAssessment.score)/100）。")
        return lines.uniquePreservingOrder()
    }

    private func buildEnglish(for result: AnalysisResult) -> [String] {
        var lines: [String] = []

        if let signature = result.signatureInfo {
            if signature.isSigned {
                lines.append("The file is signed.")
                if let signer = signature.signerName {
                    lines.append("Signer: \(signer).")
                }
                if signature.isLikelyNotarized == true {
                    lines.append("A notarization signal was detected.")
                }
            } else {
                lines.append("No valid signature was detected.")
            }
        } else {
            lines.append("Signature details are incomplete.")
        }

        if let script = result.scriptDetails {
            lines.append("Script analyzer matched \(script.ruleHits.count) rules.")
            lines.append(contentsOf: script.summary.map { "Script summary: \($0)." })
        }

        if let dynamic = result.dynamicReport {
            switch dynamic.overview.status {
            case .completed:
                lines.append("Dynamic analysis completed for about \(Int(dynamic.overview.actualDuration)) seconds.")
            case .interrupted:
                lines.append("Dynamic analysis was interrupted by user and is partial.")
            case .failed:
                lines.append("Dynamic analysis failed to start or finish, so dynamic evidence is insufficient.")
            case .noObservableActivity:
                lines.append("Dynamic analysis ran, but no obvious high-risk behavior was observed.")
            default:
                lines.append("Dynamic analysis was limited, so conclusions are conservative.")
            }

            if dynamic.overview.hasPersistenceAttempt {
                lines.append("Writes to persistence-related paths were observed.")
            }

            if dynamic.overview.hasNetworkActivity {
                lines.append("Network activity was observed during runtime.")
            }

            if !dynamic.suspiciousIndicators.isEmpty {
                lines.append("Suspicious behavior indicators were detected and need manual review.")
            }

            if let session = result.dynamicResults ?? dynamic.dynamicResults {
                lines.append("Structured dynamic stream captured \(session.events.count) events, with \(session.highRiskEvents.count) high-risk events.")
            }
        } else if result.analysisMode == .dynamicOnly || result.analysisMode == .combined {
            lines.append("No reliable dynamic result was produced; consider exporting diagnostics and retrying.")
        }

        if let generic = result.genericDetails, generic.isPossiblyDisguised {
            lines.append("The extension does not match detected content type (possible masquerading).")
        }

        if let model = result.randomForestPrediction, model.hasUsablePrediction {
            lines.append(
                String(
                    format: "Random-Forest model predicted %@ (malicious probability %.3f).",
                    model.normalizedVerdictLabel,
                    model.safeProbMalicious
                )
            )
            if let bucket = model.riskBucket, !bucket.isEmpty {
                lines.append("Model risk bucket: \(bucket).")
            }
        }

        if !result.failureIssues.isEmpty {
            lines.append("Some modules failed and actionable suggestions are provided.")
        }

        lines.append("Overall risk level: \(result.riskAssessment.level.displayName(language: .en)) (\(result.riskAssessment.score)/100).")
        return lines.uniquePreservingOrder()
    }
}

private extension Array where Element == RiskRuleResult {
    func uniqueByIDAndDetails() -> [RiskRuleResult] {
        var seen = Set<String>()
        return filter { item in
            let key = "\(item.id)|\(item.technicalDetails)|\(item.scoreDelta)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }
}
