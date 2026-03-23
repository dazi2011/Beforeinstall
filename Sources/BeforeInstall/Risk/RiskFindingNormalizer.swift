import Foundation

final class RiskFindingNormalizer: RiskSignalProvider {
    let providerID = "risk_finding_normalizer.v1"

    private let maxProviderScore = 45

    func evaluate(context: RiskRuleContext) -> [RiskRuleResult] {
        let hits = dedupe(context.scriptHits)
        guard !hits.isEmpty else {
            return []
        }

        let flags = buildFlags(context: context, hits: hits)
        var findings: [RiskRuleResult] = []
        let coreCoveredRuleIDs: Set<String> = [
            "shell.curl_pipe_sh",
            "shell.wget_pipe_sh",
            "shell.mktemp_download_exec",
            "applescript.download_execute",
            "shell.base64_exec",
            "python.eval_exec",
            "javascript.eval",
            "shell.profile_persistence",
            "shell.write_launchagent",
            "shell.launchctl.persistence"
        ]

        for hit in hits {
            if coreCoveredRuleIDs.contains(hit.ruleID) {
                continue
            }
            let category = categorize(hit.ruleID)
            let normalizedDelta = normalizedDelta(for: hit, category: category, flags: flags)
            guard normalizedDelta > 0 else {
                continue
            }

            findings.append(
                RiskRuleResult(
                    id: "normalized.\(hit.ruleID)",
                    titleZH: "脚本命中：\(hit.title)",
                    titleEN: "Script finding: \(hit.title)",
                    shortSummaryZH: "规则 \(hit.ruleID) 命中，按上下文归一化后计入风险。",
                    shortSummaryEN: "Rule \(hit.ruleID) matched and was normalized into risk scoring based on context.",
                    technicalDetails: hit.matchedContent,
                    scoreDelta: normalizedDelta,
                    severity: hit.severity.rawValue,
                    category: category,
                    explanation: hit.explanation
                )
            )
        }

        findings.append(contentsOf: buildChainFindings(flags: flags))

        return cap(findings)
    }

    private func buildFlags(context: RiskRuleContext, hits: [ScriptRuleHit]) -> ScriptRiskFlags {
        let ruleIDs = hits.map(\.ruleID)
        let contents = hits.map(\.matchedContent).joined(separator: "\n").lowercased()
        let dynamicActions = context.dynamicEvents.map(\.action).map { $0.lowercased() }

        let hasDownloadPrimitive = ruleIDs.contains(where: {
            $0.contains("download") || $0.contains("curl") || $0.contains("wget") || $0.contains("network_loader")
        }) || contents.contains("curl ") || contents.contains("wget ") || contents.contains("https://") || contents.contains("http://")

        let hasExecPrimitive = ruleIDs.contains(where: {
            $0.contains("exec") || $0.contains("system") || $0.contains("subprocess") || $0.contains("child_process") || $0.contains("do_shell_script")
        }) || contents.contains("| sh") || contents.contains("bash -c") || contents.contains("zsh -c")
            || dynamicActions.contains(where: { $0.contains("execute") || $0.contains("shell") })

        let hasPersistencePrimitive = ruleIDs.contains(where: {
            $0.contains("launch") || $0.contains("profile") || $0.contains("persistence")
        }) || contents.contains("launchagents") || contents.contains("launchdaemons") || contents.contains("launchctl")

        let hasObfuscationPrimitive = ruleIDs.contains(where: {
            $0.contains("base64") || $0.contains("obfuscation") || $0.contains("eval")
        }) || contents.contains("base64") || contents.contains("eval(") || contents.contains("function(")

        let hasNetworkPrimitive = hasDownloadPrimitive
            || context.dynamicEvents.contains(where: { $0.category == .networkConnect })

        return ScriptRiskFlags(
            hasDownloadPrimitive: hasDownloadPrimitive,
            hasExecPrimitive: hasExecPrimitive,
            hasPersistencePrimitive: hasPersistencePrimitive,
            hasObfuscationPrimitive: hasObfuscationPrimitive,
            hasNetworkPrimitive: hasNetworkPrimitive
        )
    }

    private func normalizedDelta(for hit: ScriptRuleHit, category: String, flags: ScriptRiskFlags) -> Int {
        var delta = baseDelta(for: hit)
        let lowerContent = hit.matchedContent.lowercased()
        let ruleID = hit.ruleID.lowercased()

        if isIsolatedSafeCommandExecution(ruleID: ruleID, content: lowerContent, flags: flags) {
            delta = min(delta, 2)
        }

        if isMathOnlyEval(ruleID: ruleID, content: lowerContent, flags: flags) {
            delta = 0
        }

        if isBenignBase64(ruleID: ruleID, content: lowerContent, flags: flags) {
            delta = min(delta, 2)
        }

        if isDownloadWithoutExecution(ruleID: ruleID, flags: flags) {
            delta = min(delta, 4)
        }

        if category == "automation" && !flags.hasDownloadPrimitive && !flags.hasPersistencePrimitive {
            delta = min(delta, 2)
        }

        if hit.severity == .low && !flags.hasPersistencePrimitive && !flags.hasDownloadPrimitive {
            delta = min(delta, 1)
        }

        return max(0, delta)
    }

    private func baseDelta(for hit: ScriptRuleHit) -> Int {
        switch hit.severity {
        case .critical:
            return max(14, min(24, hit.suggestedRiskScoreDelta / 2))
        case .high:
            return max(10, min(18, hit.suggestedRiskScoreDelta / 2))
        case .medium:
            return max(5, min(10, hit.suggestedRiskScoreDelta / 2))
        case .low:
            return max(2, min(5, hit.suggestedRiskScoreDelta / 2))
        }
    }

    private func buildChainFindings(flags: ScriptRiskFlags) -> [RiskRuleResult] {
        var findings: [RiskRuleResult] = []

        if flags.hasDownloadPrimitive && flags.hasExecPrimitive {
            findings.append(
                RiskRuleResult(
                    id: "chain.download_then_execute",
                    titleZH: "组合链：下载后执行",
                    titleEN: "Chained pattern: download then execute",
                    shortSummaryZH: "检测到下载与执行组合链条。",
                    shortSummaryEN: "A chained download-and-execute pattern was detected.",
                    technicalDetails: "download + execute",
                    scoreDelta: 18,
                    severity: "high",
                    category: "chain",
                    explanation: "Composed from normalized primitive findings."
                )
            )
        }

        if flags.hasPersistencePrimitive && flags.hasExecPrimitive {
            findings.append(
                RiskRuleResult(
                    id: "chain.persistence_with_execution",
                    titleZH: "组合链：持久化 + 执行",
                    titleEN: "Chained pattern: persistence + execution",
                    shortSummaryZH: "检测到持久化原语与执行原语组合。",
                    shortSummaryEN: "Persistence primitives were combined with execution primitives.",
                    technicalDetails: "persistence + execute",
                    scoreDelta: 16,
                    severity: "high",
                    category: "chain",
                    explanation: "Composed from normalized primitive findings."
                )
            )
        }

        if flags.hasObfuscationPrimitive && flags.hasExecPrimitive {
            findings.append(
                RiskRuleResult(
                    id: "chain.obfuscation_with_execution",
                    titleZH: "组合链：混淆 + 执行",
                    titleEN: "Chained pattern: obfuscation + execution",
                    shortSummaryZH: "检测到混淆与执行组合链。",
                    shortSummaryEN: "Obfuscation and execution primitives were observed together.",
                    technicalDetails: "obfuscation + execute",
                    scoreDelta: 12,
                    severity: "medium",
                    category: "chain",
                    explanation: "Composed from normalized primitive findings."
                )
            )
        }

        return findings
    }

    private func cap(_ findings: [RiskRuleResult]) -> [RiskRuleResult] {
        let sorted = findings.sorted { lhs, rhs in
            if lhs.scoreDelta == rhs.scoreDelta {
                return lhs.id < rhs.id
            }
            return lhs.scoreDelta > rhs.scoreDelta
        }

        var accumulated = 0
        var capped: [RiskRuleResult] = []
        for item in sorted {
            let room = max(0, maxProviderScore - accumulated)
            guard room > 0 else { break }
            let applied = min(room, item.scoreDelta)
            guard applied > 0 else { continue }
            accumulated += applied

            var adjusted = item
            adjusted.scoreDelta = applied
            capped.append(adjusted)
        }
        return capped
    }

    private func dedupe(_ hits: [ScriptRuleHit]) -> [ScriptRuleHit] {
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

    private func categorize(_ ruleID: String) -> String {
        let lower = ruleID.lowercased()
        if lower.contains("launch") || lower.contains("profile") || lower.contains("persist") {
            return "persistence"
        }
        if lower.contains("download") || lower.contains("network") || lower.contains("curl") || lower.contains("wget") {
            return "network"
        }
        if lower.contains("exec") || lower.contains("system") || lower.contains("child_process") || lower.contains("subprocess") {
            return "execution"
        }
        if lower.contains("base64") || lower.contains("obfuscation") || lower.contains("eval") {
            return "obfuscation"
        }
        if lower.contains("finder") || lower.contains("terminal") || lower.contains("applescript") {
            return "automation"
        }
        return "script"
    }

    private func isIsolatedSafeCommandExecution(ruleID: String, content: String, flags: ScriptRiskFlags) -> Bool {
        guard ruleID.contains("subprocess")
            || ruleID.contains("child_process")
            || ruleID.contains("os_system")
            || ruleID.contains("do_shell_script")
            || ruleID.contains("osascript_shell")
            || ruleID.contains("terminal_control")
        else {
            return false
        }

        if flags.hasDownloadPrimitive || flags.hasPersistencePrimitive {
            return false
        }

        if containsSuspiciousKeyword(content) {
            return false
        }

        return ["echo", "pwd", "ls", "whoami", "date", "printf"].contains(where: { content.contains($0) })
    }

    private func isMathOnlyEval(ruleID: String, content: String, flags: ScriptRiskFlags) -> Bool {
        guard ruleID.contains("eval") else {
            return false
        }

        if flags.hasDownloadPrimitive || flags.hasPersistencePrimitive {
            return false
        }

        let allowed = CharacterSet(charactersIn: "0123456789+-*/() .\"'=resultconstletvar")
        return content.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    private func isBenignBase64(ruleID: String, content: String, flags: ScriptRiskFlags) -> Bool {
        guard ruleID.contains("base64") || content.contains("base64") else {
            return false
        }

        if flags.hasExecPrimitive && (content.contains("| sh") || content.contains("eval") || content.contains("exec")) {
            return false
        }

        return !flags.hasPersistencePrimitive
    }

    private func isDownloadWithoutExecution(ruleID: String, flags: ScriptRiskFlags) -> Bool {
        guard ruleID.contains("download") || ruleID.contains("network") else {
            return false
        }
        return !flags.hasExecPrimitive
    }

    private func containsSuspiciousKeyword(_ content: String) -> Bool {
        [
            "curl", "wget", "http://", "https://", "launchctl", "launchagents", "launchdaemons",
            "| sh", "bash -c", "zsh -c", "osascript", "base64", "eval", "exec("
        ].contains(where: { content.contains($0) })
    }
}

private struct ScriptRiskFlags {
    var hasDownloadPrimitive: Bool
    var hasExecPrimitive: Bool
    var hasPersistencePrimitive: Bool
    var hasObfuscationPrimitive: Bool
    var hasNetworkPrimitive: Bool
}
