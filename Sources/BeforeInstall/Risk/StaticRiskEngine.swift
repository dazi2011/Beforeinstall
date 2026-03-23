import Foundation

struct StaticRiskContext {
    let report: ScanReport

    var result: AnalysisResult {
        report.analysisResult
    }

    var pathLower: String {
        result.basicInfo.fullPath.lowercased()
    }

    var detectedType: SupportedFileType {
        result.basicInfo.fileType
    }

    var isSensitiveLocation: Bool {
        pathLower.contains("/downloads/")
            || pathLower.contains("/desktop/")
            || pathLower.hasPrefix("/tmp/")
            || pathLower.hasPrefix("/private/tmp/")
            || pathLower.contains("/launchagents/")
            || pathLower.contains("/launchdaemons/")
            || pathLower.contains("/library/application support/")
            || pathLower.contains("/library/preferences/")
    }

    var isConservativeLocation: Bool {
        pathLower.contains("/node_modules/")
            || pathLower.contains("/.git/")
            || pathLower.contains("/deriveddata/")
            || pathLower.contains("/build/")
            || pathLower.contains("/dist/")
            || pathLower.contains("/venv/")
            || pathLower.contains("/.venv/")
            || pathLower.hasPrefix("/usr/local/")
            || pathLower.hasPrefix("/opt/homebrew/")
            || pathLower.contains("/library/developer/")
    }

    var isLaunchdPath: Bool {
        pathLower.contains("launchagents") || pathLower.contains("launchdaemons")
    }
}

private protocol TypeRiskScorer {
    var scorerID: String { get }
    func supports(type: SupportedFileType) -> Bool
    func score(for finding: StaticFinding, context: StaticRiskContext) -> Int
}

private struct ScriptRiskScorer: TypeRiskScorer {
    let scorerID = "ScriptRiskScorer"

    func supports(type: SupportedFileType) -> Bool {
        type == .shellScript || type == .pythonScript || type == .javaScript || type == .appleScript
    }

    func score(for finding: StaticFinding, context: StaticRiskContext) -> Int {
        var score = finding.scoreDeltaBase

        switch finding.executionSemantics {
        case .downloadExecuteLike:
            score += 8
        case .actualExecutionLike:
            score += 6
        case .persistenceLike:
            score += 7
        case .printedOnly, .echoedOnly:
            score = min(score, 4)
        case .commentOnly, .documentationOnly:
            score = min(score, 2)
        case .simulationOnly, .dryRunOnly:
            score = min(score, 5)
        case .configOnly:
            score = min(score + 1, 10)
        case .unknown:
            break
        }

        if finding.category == "obfuscation" && (finding.executionSemantics == .actualExecutionLike || finding.executionSemantics == .downloadExecuteLike) {
            score += 5
        }

        if context.isConservativeLocation && finding.evidenceStrength != .strong {
            score -= 3
        }

        return max(0, min(score, 42))
    }
}

private struct AppBundleRiskScorer: TypeRiskScorer {
    let scorerID = "AppBundleRiskScorer"

    func supports(type: SupportedFileType) -> Bool {
        type == .appBundle
    }

    func score(for finding: StaticFinding, context: StaticRiskContext) -> Int {
        var score = finding.scoreDeltaBase
        if finding.executionSemantics == .persistenceLike {
            score += 6
        }
        if finding.tags.contains("embedded_script") {
            score += 5
        }
        if context.pathLower.hasPrefix("/applications/") && finding.evidenceStrength != .strong {
            score -= 3
        }
        return max(0, min(score, 38))
    }
}

private struct PKGRiskScorer: TypeRiskScorer {
    let scorerID = "PKGRiskScorer"

    func supports(type: SupportedFileType) -> Bool {
        type == .pkg
    }

    func score(for finding: StaticFinding, context: StaticRiskContext) -> Int {
        var score = finding.scoreDeltaBase
        if finding.tags.contains("postinstall") || finding.tags.contains("preinstall") {
            score += 4
        }
        if finding.executionSemantics == .persistenceLike {
            score += 6
        }
        if finding.executionSemantics == .simulationOnly || finding.executionSemantics == .dryRunOnly {
            score = min(score, 7)
        }
        if context.isConservativeLocation && finding.evidenceStrength != .strong {
            score -= 2
        }
        return max(0, min(score, 40))
    }
}

private struct PlistPersistenceScorer: TypeRiskScorer {
    let scorerID = "PlistPersistenceScorer"

    func supports(type: SupportedFileType) -> Bool {
        type == .plist
    }

    func score(for finding: StaticFinding, context: StaticRiskContext) -> Int {
        var score = finding.scoreDeltaBase
        if context.isLaunchdPath {
            score += 8
        }
        if finding.executionSemantics == .persistenceLike {
            score += 5
        }
        if finding.executionSemantics == .configOnly && finding.evidenceStrength == .weak {
            score = min(score, 6)
        }
        return max(0, min(score, 36))
    }
}

private struct BinaryRiskScorer: TypeRiskScorer {
    let scorerID = "BinaryRiskScorer"

    func supports(type: SupportedFileType) -> Bool {
        type == .machO || type == .dylib
    }

    func score(for finding: StaticFinding, context: StaticRiskContext) -> Int {
        var score = finding.scoreDeltaBase
        if finding.tags.contains("unsigned") {
            score += 5
        }
        if context.isSensitiveLocation {
            score += 4
        }
        return max(0, min(score, 36))
    }
}

private struct HybridFixtureRiskScorer: TypeRiskScorer {
    let scorerID = "HybridFixtureRiskScorer"

    func supports(type: SupportedFileType) -> Bool {
        type == .dmg || type == .archive
    }

    func score(for finding: StaticFinding, context: StaticRiskContext) -> Int {
        var score = finding.scoreDeltaBase
        if finding.tags.contains("hybrid") {
            score += 4
        }
        if finding.executionSemantics == .downloadExecuteLike || finding.executionSemantics == .persistenceLike {
            score += 4
        }
        if context.isConservativeLocation {
            score -= 2
        }
        return max(0, min(score, 34))
    }
}

private struct DefaultRiskScorer: TypeRiskScorer {
    let scorerID = "DefaultRiskScorer"

    func supports(type: SupportedFileType) -> Bool {
        _ = type
        return true
    }

    func score(for finding: StaticFinding, context: StaticRiskContext) -> Int {
        var score = finding.scoreDeltaBase
        if context.isConservativeLocation && finding.evidenceStrength == .weak {
            score -= 3
        }
        return max(0, min(score, 30))
    }
}

private final class StaticFindingNormalizer {
    func normalize(context: StaticRiskContext) -> [StaticFinding] {
        var findings: [StaticFinding] = []
        let result = context.result
        let path = result.basicInfo.fullPath

        if let script = result.scriptDetails {
            for hit in script.ruleHits {
                let semantics = inferSemantics(ruleID: hit.ruleID, content: hit.matchedContent)
                let evidence = inferEvidenceStrength(semantics: semantics, severity: hit.severity)
                let confidence = inferConfidence(semantics: semantics, evidence: evidence, severity: hit.severity)

                let finding = StaticFinding(
                    id: "script|\(hit.ruleID)|\(hit.lineStart)|\(hit.lineEnd)|\(hit.matchedContent.hashValue)",
                    ruleID: hit.ruleID,
                    title: hit.title,
                    category: categoryForRuleID(hit.ruleID),
                    severity: mapSeverity(hit.severity),
                    confidence: confidence,
                    evidenceStrength: evidence,
                    scoreDeltaBase: max(1, min(42, hit.suggestedRiskScoreDelta)),
                    explanation: hit.explanation,
                    evidenceSnippet: hit.matchedContent,
                    sourceLocation: StaticFindingSourceLocation(
                        filePath: path,
                        lineStart: hit.lineStart > 0 ? hit.lineStart : nil,
                        lineEnd: hit.lineEnd > 0 ? hit.lineEnd : nil,
                        keyPath: nil
                    ),
                    executionSemantics: semantics,
                    tags: ["script", result.basicInfo.fileType.rawValue],
                    detectedType: result.basicInfo.fileType
                )
                findings.append(finding)
            }
        }

        if let app = result.appDetails {
            if !app.launchItems.isEmpty || !app.loginItems.isEmpty {
                findings.append(
                    StaticFinding(
                        id: "app.bundle.persistence|\(path.hashValue)",
                        ruleID: "app.bundle.persistence_components",
                        title: "App bundle contains startup-linked components",
                        category: "persistence",
                        severity: .medium,
                        confidence: .medium,
                        evidenceStrength: .moderate,
                        scoreDeltaBase: 14,
                        explanation: "LoginItems/LaunchItems were found in bundle structure.",
                        evidenceSnippet: (app.launchItems + app.loginItems).prefix(6).joined(separator: ", "),
                        sourceLocation: StaticFindingSourceLocation(filePath: path, lineStart: nil, lineEnd: nil, keyPath: "Contents/Library"),
                        executionSemantics: .persistenceLike,
                        tags: ["bundle", "persistence"],
                        detectedType: .appBundle
                    )
                )
            }

            if !app.helperItems.isEmpty {
                findings.append(
                    StaticFinding(
                        id: "app.bundle.embedded_helpers|\(path.hashValue)",
                        ruleID: "app.bundle.embedded_helpers",
                        title: "App bundle embeds helper executables",
                        category: "execution",
                        severity: .medium,
                        confidence: .medium,
                        evidenceStrength: .moderate,
                        scoreDeltaBase: 10,
                        explanation: "Helper or XPC components can extend runtime execution surface.",
                        evidenceSnippet: app.helperItems.prefix(6).joined(separator: ", "),
                        sourceLocation: StaticFindingSourceLocation(filePath: path, lineStart: nil, lineEnd: nil, keyPath: "Contents/Library"),
                        executionSemantics: .actualExecutionLike,
                        tags: ["bundle", "embedded_script"],
                        detectedType: .appBundle
                    )
                )
            }
        }

        if let pkg = result.pkgDetails {
            for script in pkg.scripts {
                let semantics = inferSemantics(ruleID: script.scriptType, content: script.snippet ?? script.scriptPath)
                let finding = StaticFinding(
                    id: "pkg.script|\(script.scriptPath.hashValue)",
                    ruleID: "pkg.install.script",
                    title: "Installer script discovered",
                    category: "installer",
                    severity: .medium,
                    confidence: .medium,
                    evidenceStrength: semantics == .simulationOnly || semantics == .dryRunOnly ? .weak : .moderate,
                    scoreDeltaBase: 11,
                    explanation: "Package pre/post install scripts can execute with installer privileges.",
                    evidenceSnippet: script.snippet ?? script.scriptPath,
                    sourceLocation: StaticFindingSourceLocation(filePath: path, lineStart: nil, lineEnd: nil, keyPath: script.scriptPath),
                    executionSemantics: semantics == .unknown ? .actualExecutionLike : semantics,
                    tags: ["pkg", script.scriptType.lowercased()],
                    detectedType: .pkg
                )
                findings.append(finding)
            }
        }

        for indicator in result.persistenceIndicators {
            let lower = indicator.lowercased()
            let semantics: ExecutionSemantics = lower.contains("launch") || lower.contains("profile") ? .persistenceLike : .configOnly
            findings.append(
                StaticFinding(
                    id: "persistence|\(indicator.hashValue)",
                    ruleID: "static.persistence.indicator",
                    title: "Persistence indicator",
                    category: "persistence",
                    severity: .medium,
                    confidence: .medium,
                    evidenceStrength: semantics == .persistenceLike ? .moderate : .weak,
                    scoreDeltaBase: semantics == .persistenceLike ? 10 : 6,
                    explanation: "Static analyzer surfaced persistence-related indicator.",
                    evidenceSnippet: indicator,
                    sourceLocation: StaticFindingSourceLocation(filePath: path, lineStart: nil, lineEnd: nil, keyPath: nil),
                    executionSemantics: semantics,
                    tags: ["persistence"],
                    detectedType: result.basicInfo.fileType
                )
            )
        }

        if let generic = result.genericDetails {
            if generic.isExecutable, result.signatureInfo?.isSigned == false {
                findings.append(
                    StaticFinding(
                        id: "binary.unsigned|\(path.hashValue)",
                        ruleID: "binary.unsigned",
                        title: "Unsigned executable-like object",
                        category: "signature",
                        severity: .high,
                        confidence: .medium,
                        evidenceStrength: .moderate,
                        scoreDeltaBase: 16,
                        explanation: "Executable-like sample appears unsigned.",
                        evidenceSnippet: result.signatureInfo?.signerName ?? "isSigned=false",
                        sourceLocation: StaticFindingSourceLocation(filePath: path, lineStart: nil, lineEnd: nil, keyPath: nil),
                        executionSemantics: .actualExecutionLike,
                        tags: ["unsigned", "binary"],
                        detectedType: result.basicInfo.fileType
                    )
                )
            }

            for keyword in generic.suspiciousKeywordHits.prefix(20) {
                let semantics = inferSemantics(ruleID: "generic.keyword", content: keyword)
                findings.append(
                    StaticFinding(
                        id: "keyword|\(keyword.hashValue)",
                        ruleID: "generic.keyword.hit",
                        title: "Suspicious static keyword",
                        category: "keyword",
                        severity: semantics == .actualExecutionLike || semantics == .downloadExecuteLike ? .medium : .low,
                        confidence: semantics == .unknown ? .low : .medium,
                        evidenceStrength: (semantics == .commentOnly || semantics == .documentationOnly || semantics == .printedOnly || semantics == .echoedOnly || semantics == .simulationOnly || semantics == .dryRunOnly) ? .weak : .moderate,
                        scoreDeltaBase: 6,
                        explanation: "Keyword-level static signal; requires context to determine impact.",
                        evidenceSnippet: keyword,
                        sourceLocation: StaticFindingSourceLocation(filePath: path, lineStart: nil, lineEnd: nil, keyPath: nil),
                        executionSemantics: semantics,
                        tags: ["keyword"],
                        detectedType: result.basicInfo.fileType
                    )
                )
            }
        }

        return dedupe(findings)
    }

    private func mapSeverity(_ severity: ScriptFindingSeverity) -> FindingSeverity {
        switch severity {
        case .critical: return .critical
        case .high: return .high
        case .medium: return .medium
        case .low: return .low
        }
    }

    private func inferEvidenceStrength(semantics: ExecutionSemantics, severity: ScriptFindingSeverity) -> EvidenceStrength {
        switch semantics {
        case .actualExecutionLike, .persistenceLike, .downloadExecuteLike:
            return severity == .critical || severity == .high ? .strong : .moderate
        case .configOnly:
            return .moderate
        case .printedOnly, .echoedOnly, .commentOnly, .documentationOnly, .simulationOnly, .dryRunOnly:
            return .weak
        case .unknown:
            return .moderate
        }
    }

    private func inferConfidence(
        semantics: ExecutionSemantics,
        evidence: EvidenceStrength,
        severity: ScriptFindingSeverity
    ) -> FindingConfidence {
        if evidence == .weak {
            return .low
        }
        if evidence == .strong && (severity == .critical || severity == .high) {
            return .high
        }
        switch semantics {
        case .actualExecutionLike, .persistenceLike, .downloadExecuteLike:
            return .high
        case .configOnly:
            return .medium
        default:
            return .medium
        }
    }

    private func inferSemantics(ruleID: String, content: String) -> ExecutionSemantics {
        let lowerRule = ruleID.lowercased()
        let lower = content.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        if lower.hasPrefix("#") || lower.hasPrefix("//") || lower.hasPrefix("/*") {
            return .commentOnly
        }
        if lower.contains("readme") || lower.contains("documentation") || lower.contains("for demo") {
            return .documentationOnly
        }
        if lower.contains("simulate") || lower.contains("simulation") || lower.contains("would execute") {
            return .simulationOnly
        }
        if lower.contains("dry-run") || lower.contains("--dry-run") {
            return .dryRunOnly
        }
        if lower.contains("echo ") && !lower.contains("| sh") && !lower.contains("bash -c") {
            return .echoedOnly
        }
        if lower.contains("print(") || lower.contains("console.log") {
            return .printedOnly
        }

        if lowerRule.contains("launch") || lowerRule.contains("persist") || lowerRule.contains("profile") {
            return .persistenceLike
        }
        if (lowerRule.contains("download") || lowerRule.contains("curl") || lowerRule.contains("wget"))
            && (lowerRule.contains("exec") || lower.contains("| sh") || lower.contains("bash -c") || lower.contains("exec("))
        {
            return .downloadExecuteLike
        }
        if lowerRule.contains("exec")
            || lowerRule.contains("system")
            || lowerRule.contains("subprocess")
            || lowerRule.contains("child_process")
            || lowerRule.contains("do_shell_script")
            || lowerRule.contains("osascript_shell")
            || lower.contains("| sh")
            || lower.contains("bash -c")
            || lower.contains("zsh -c")
        {
            return .actualExecutionLike
        }
        if lowerRule.contains("plist") || lowerRule.contains("config") {
            return .configOnly
        }
        return .unknown
    }

    private func categoryForRuleID(_ ruleID: String) -> String {
        let lower = ruleID.lowercased()
        if lower.contains("launch") || lower.contains("persist") || lower.contains("profile") { return "persistence" }
        if lower.contains("download") || lower.contains("curl") || lower.contains("wget") { return "network" }
        if lower.contains("exec") || lower.contains("system") || lower.contains("subprocess") || lower.contains("child_process") { return "execution" }
        if lower.contains("obfus") || lower.contains("base64") || lower.contains("eval") { return "obfuscation" }
        if lower.contains("pkg") || lower.contains("install") { return "installer" }
        if lower.contains("signature") || lower.contains("unsigned") { return "signature" }
        return "generic"
    }

    private func dedupe(_ findings: [StaticFinding]) -> [StaticFinding] {
        var seen = Set<String>()
        return findings.filter { finding in
            let key = "\(finding.ruleID)|\(finding.evidenceSnippet)|\(finding.sourceLocation.filePath ?? "")|\(finding.sourceLocation.lineStart ?? -1)|\(finding.sourceLocation.lineEnd ?? -1)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }
}

private final class ContextWeightingEngine {
    func adjustments(findings: [StaticFinding], context: StaticRiskContext) -> [ScoreAdjustmentTrace] {
        guard !findings.isEmpty else { return [] }
        var output: [ScoreAdjustmentTrace] = []

        let strongCount = findings.filter { $0.evidenceStrength == .strong }.count
        let weakCount = findings.filter { $0.evidenceStrength == .weak }.count
        let hasPersistence = findings.contains { $0.executionSemantics == .persistenceLike }
        let hasActual = findings.contains { $0.executionSemantics == .actualExecutionLike || $0.executionSemantics == .downloadExecuteLike }

        if context.isSensitiveLocation {
            let delta = (hasActual || hasPersistence) ? 10 : 4
            output.append(ScoreAdjustmentTrace(name: "sensitive_path", delta: delta, reason: "Sample is in Downloads/tmp/launchd-sensitive location."))
        }

        if context.isConservativeLocation {
            let delta = strongCount > 0 ? -4 : -8
            output.append(ScoreAdjustmentTrace(name: "conservative_path", delta: delta, reason: "Developer/Homebrew/build path requires conservative static scoring."))
        }

        if context.detectedType == .plist {
            let delta = context.isLaunchdPath ? 8 : -3
            output.append(ScoreAdjustmentTrace(name: "plist_context", delta: delta, reason: context.isLaunchdPath ? "Launchd plist context is sensitive." : "Generic plist context is conservative."))
        }

        if context.detectedType.isExecutableLike {
            output.append(ScoreAdjustmentTrace(name: "executable_context", delta: 3, reason: "Executable-like object raises exploitability potential."))
        }

        if weakCount > 0 && weakCount == findings.count {
            output.append(ScoreAdjustmentTrace(name: "weak_evidence_bias", delta: -8, reason: "All findings are weak evidence semantics."))
        }

        return output
    }
}

private final class ChainBonusEngine {
    func bonuses(findings: [StaticFinding], context: StaticRiskContext) -> [ScoreAdjustmentTrace] {
        guard !findings.isEmpty else { return [] }

        let strongCount = findings.filter { $0.evidenceStrength == .strong }.count
        let moderateCount = findings.filter { $0.evidenceStrength == .moderate }.count
        let weakOnly = strongCount == 0 && moderateCount == 0

        let hasDownload = findings.contains { $0.executionSemantics == .downloadExecuteLike || $0.category == "network" }
        let hasExec = findings.contains { $0.executionSemantics == .actualExecutionLike || $0.executionSemantics == .downloadExecuteLike }
        let hasPersistence = findings.contains { $0.executionSemantics == .persistenceLike }
        let hasObfuscation = findings.contains { $0.category == "obfuscation" }
        let hasInstaller = findings.contains { $0.category == "installer" || $0.detectedType == .pkg }

        let highGate = (strongCount >= 2)
            || (strongCount >= 1 && moderateCount >= 1)
            || (strongCount >= 1 && context.isSensitiveLocation)
            || (moderateCount >= 2 && hasPersistence)

        let moderateGate = (moderateCount >= 2 && hasPersistence) || (moderateCount >= 3)

        var bonuses: [ScoreAdjustmentTrace] = []

        if weakOnly {
            return bonuses
        }

        if hasDownload && hasExec {
            let delta = highGate ? 16 : (moderateGate ? 6 : 0)
            if delta > 0 {
                bonuses.append(ScoreAdjustmentTrace(name: "chain_download_execute", delta: delta, reason: "Download + execution chain formed in same static context."))
            }
        }

        if hasPersistence && hasExec {
            let delta = highGate ? 14 : (moderateGate ? 5 : 0)
            if delta > 0 {
                bonuses.append(ScoreAdjustmentTrace(name: "chain_persistence_execution", delta: delta, reason: "Persistence + execution chain formed."))
            }
        }

        if hasInstaller && (hasExec || hasPersistence) {
            let delta = highGate ? 12 : (moderateGate ? 4 : 0)
            if delta > 0 {
                bonuses.append(ScoreAdjustmentTrace(name: "chain_installer_execution", delta: delta, reason: "Installer script chain suggests post-install execution."))
            }
        }

        if hasObfuscation && hasExec {
            let delta = highGate ? 10 : (moderateGate ? 4 : 0)
            if delta > 0 {
                bonuses.append(ScoreAdjustmentTrace(name: "chain_obfuscation_execution", delta: delta, reason: "Obfuscation + execution chain formed."))
            }
        }

        return bonuses
    }
}

private final class ScoreCapPolicy {
    func apply(score: Int, findings: [StaticFinding], chainBonuses: [ScoreAdjustmentTrace]) -> (finalScore: Int, traces: [ScoreCapTrace]) {
        guard !findings.isEmpty else {
            return (max(0, min(100, score)), [])
        }

        var traces: [ScoreCapTrace] = []
        let semantics = findings.map(\.executionSemantics)
        let strongCount = findings.filter { $0.evidenceStrength == .strong }.count
        let moderateCount = findings.filter { $0.evidenceStrength == .moderate }.count

        let allDocLike = semantics.allSatisfy { $0 == .documentationOnly || $0 == .commentOnly }
        let allPrintLike = semantics.allSatisfy {
            $0 == .printedOnly || $0 == .echoedOnly || $0 == .dryRunOnly || $0 == .simulationOnly || $0 == .documentationOnly || $0 == .commentOnly
        }
        let hasChainBonus = !chainBonuses.isEmpty
        let hasActualExecution = semantics.contains(.actualExecutionLike) || semantics.contains(.downloadExecuteLike) || semantics.contains(.persistenceLike)

        var final = score

        if allDocLike {
            let capped = min(final, 45)
            traces.append(
                ScoreCapTrace(
                    cap: 45,
                    reason: "Documentation/comment-only sample is capped.",
                    applied: capped != final,
                    beforeScore: final,
                    afterScore: capped
                )
            )
            final = capped
        } else if allPrintLike {
            let capped = min(final, 58)
            traces.append(
                ScoreCapTrace(
                    cap: 58,
                    reason: "Printed/echoed/simulation-only evidence is capped.",
                    applied: capped != final,
                    beforeScore: final,
                    afterScore: capped
                )
            )
            final = capped
        } else if !hasActualExecution && strongCount == 0 && moderateCount > 0 && hasChainBonus {
            let capped = min(final, 65)
            traces.append(
                ScoreCapTrace(
                    cap: 65,
                    reason: "Moderate chain without execution semantics is capped.",
                    applied: capped != final,
                    beforeScore: final,
                    afterScore: capped
                )
            )
            final = capped
        }

        return (max(0, min(100, final)), traces)
    }
}

private final class VerdictMapper {
    func map(score: Int, findings: [StaticFinding], capApplied: Bool, chainBonuses: [ScoreAdjustmentTrace]) -> ScanVerdict {
        guard !findings.isEmpty else {
            return .clean
        }

        let strongCount = findings.filter { $0.evidenceStrength == .strong }.count
        let weakCount = findings.filter { $0.evidenceStrength == .weak }.count
        let weakDominant = weakCount >= max(1, findings.count * 2 / 3)
        let hasStrongChain = !chainBonuses.isEmpty

        if score >= 85 && strongCount >= 2 && hasStrongChain {
            return .malicious
        }

        if score >= 72 && strongCount >= 1 && !weakDominant {
            return .suspicious
        }

        if capApplied && weakDominant {
            return score >= 45 ? .suspicious : .clean
        }

        if score >= 42 {
            return .suspicious
        }

        return .clean
    }
}

private final class StaticSummaryBuilder {
    func buildReasoning(
        language: AppLanguage,
        verdict: ScanVerdict,
        score: Int,
        topFindings: [RiskRuleResult],
        capTrace: [ScoreCapTrace]
    ) -> String {
        let core = topFindings.prefix(3).map { $0.shortSummary(language: language) }.joined(separator: language == .zhHans ? "；" : "; ")
        let capNote = capTrace.contains(where: { $0.applied })
            ? (language == .zhHans ? "（已触发静态封顶策略）" : " (score-cap policy applied)")
            : ""

        if core.isEmpty {
            return language == .zhHans
                ? "静态证据不足，当前判定 \(verdict.displayName(language: language))，得分 \(score)/100\(capNote)。"
                : "Static evidence is limited. Verdict: \(verdict.displayName(language: language)), score \(score)/100\(capNote)."
        }

        return language == .zhHans
            ? "静态证据链：\(core)。最终 \(verdict.displayName(language: language))，得分 \(score)/100\(capNote)。"
            : "Static evidence chain: \(core). Final verdict \(verdict.displayName(language: language)), score \(score)/100\(capNote)."
    }
}

final class StaticRiskEngine {
    private let normalizer = StaticFindingNormalizer()
    private let contextWeighting = ContextWeightingEngine()
    private let chainBonus = ChainBonusEngine()
    private let scoreCapPolicy = ScoreCapPolicy()
    private let verdictMapper = VerdictMapper()
    private let summaryBuilder = StaticSummaryBuilder()

    private let scorers: [TypeRiskScorer] = [
        ScriptRiskScorer(),
        AppBundleRiskScorer(),
        PKGRiskScorer(),
        PlistPersistenceScorer(),
        BinaryRiskScorer(),
        HybridFixtureRiskScorer(),
        DefaultRiskScorer()
    ]

    func evaluate(
        report: ScanReport,
        profileOffset: Int
    ) -> RiskEvaluation {
        let context = StaticRiskContext(report: report)
        let staticFindings = normalizer.normalize(context: context)

        var allFindings: [RiskRuleResult] = []
        var baseScore = 0
        var scorerTotals: [String: Int] = [:]

        for finding in staticFindings {
            let scorer = scorerFor(type: finding.detectedType)
            let scoredDelta = scorer.score(for: finding, context: context)
            guard scoredDelta > 0 else { continue }

            baseScore += scoredDelta
            scorerTotals[scorer.scorerID, default: 0] += scoredDelta

            allFindings.append(
                RiskRuleResult(
                    id: finding.ruleID,
                    titleZH: finding.title,
                    titleEN: finding.title,
                    shortSummaryZH: finding.explanation,
                    shortSummaryEN: finding.explanation,
                    technicalDetails: finding.evidenceSnippet,
                    scoreDelta: scoredDelta,
                    severity: finding.severity.rawValue,
                    category: finding.category,
                    explanation: finding.explanation,
                    confidence: finding.confidence.rawValue,
                    evidenceStrength: finding.evidenceStrength.rawValue,
                    executionSemantics: finding.executionSemantics.rawValue,
                    scoreDeltaBase: finding.scoreDeltaBase,
                    sourceLocation: sourceLocationString(finding.sourceLocation),
                    tags: finding.tags,
                    typeScorer: scorer.scorerID
                )
            )
        }

        let contextAdjustments = contextWeighting.adjustments(findings: staticFindings, context: context)
        let chainBonuses = chainBonus.bonuses(findings: staticFindings, context: context)

        var totalScore = baseScore
            + contextAdjustments.reduce(0, { $0 + $1.delta })
            + chainBonuses.reduce(0, { $0 + $1.delta })
            + profileOffset

        let capped = scoreCapPolicy.apply(score: totalScore, findings: staticFindings, chainBonuses: chainBonuses)
        totalScore = capped.finalScore

        let capApplied = capped.traces.contains(where: { $0.applied })
        let verdict = verdictMapper.map(score: totalScore, findings: staticFindings, capApplied: capApplied, chainBonuses: chainBonuses)

        let sortedFindings = allFindings.sorted { lhs, rhs in
            if lhs.scoreDelta == rhs.scoreDelta {
                return lhs.id < rhs.id
            }
            return lhs.scoreDelta > rhs.scoreDelta
        }
        let topFindings = Array(sortedFindings.prefix(8))

        let typeScorer = scorerTotals.max(by: { $0.value < $1.value })?.key ?? "DefaultRiskScorer"
        let reasoningZH = summaryBuilder.buildReasoning(
            language: .zhHans,
            verdict: verdict,
            score: totalScore,
            topFindings: topFindings,
            capTrace: capped.traces
        )
        let reasoningEN = summaryBuilder.buildReasoning(
            language: .en,
            verdict: verdict,
            score: totalScore,
            topFindings: topFindings,
            capTrace: capped.traces
        )

        let trace = StaticScoringTrace(
            sampleID: report.filePath,
            detectedType: report.detectedType.rawValue,
            typeScorerUsed: typeScorer,
            baseScore: baseScore,
            contextAdjustments: contextAdjustments,
            chainBonuses: chainBonuses,
            scoreCapsApplied: capped.traces,
            finalScore: totalScore,
            verdict: verdict.rawValue,
            topFindings: topFindings.map { "\($0.id):\($0.scoreDelta)" },
            notes: [
                "finding_count=\(staticFindings.count)",
                "profile_offset=\(profileOffset)"
            ]
        )

        return RiskEvaluation(
            totalScore: totalScore,
            verdict: verdict,
            reasoningSummaryZH: reasoningZH,
            reasoningSummaryEN: reasoningEN,
            topFindings: topFindings,
            allFindings: sortedFindings,
            isEvidenceInsufficient: staticFindings.isEmpty,
            staticScoringTrace: trace,
            findingsTrace: staticFindings,
            scoreCapTrace: capped.traces,
            contextTrace: contextAdjustments
        )
    }

    private func scorerFor(type: SupportedFileType) -> TypeRiskScorer {
        scorers.first(where: { $0.supports(type: type) }) ?? DefaultRiskScorer()
    }

    private func sourceLocationString(_ location: StaticFindingSourceLocation) -> String {
        var parts: [String] = []
        if let filePath = location.filePath {
            parts.append(filePath)
        }
        if let lineStart = location.lineStart {
            if let lineEnd = location.lineEnd, lineEnd != lineStart {
                parts.append("L\(lineStart)-L\(lineEnd)")
            } else {
                parts.append("L\(lineStart)")
            }
        }
        if let keyPath = location.keyPath {
            parts.append("key=\(keyPath)")
        }
        return parts.joined(separator: " | ")
    }
}
