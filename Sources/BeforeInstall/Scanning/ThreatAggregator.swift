import Foundation

struct RiskLevelPolicy {
    var criticalThreshold: Int = 85
    var highThreshold: Int = 65
    var mediumThreshold: Int = 40
    var lowThreshold: Int = 20

    func map(score: Int, verdict: ScanVerdict) -> RiskLevel {
        if score >= criticalThreshold {
            return .critical
        }
        if verdict == .malicious, score >= highThreshold - 5 {
            return .high
        }
        if score >= highThreshold {
            return .high
        }
        if verdict == .suspicious, score >= mediumThreshold - 5 {
            return .medium
        }
        if score >= mediumThreshold {
            return .medium
        }
        if score >= lowThreshold {
            return .low
        }
        return .info
    }
}

final class ThreatAggregator {
    private let fileManager = FileManager.default
    private let riskPolicy: RiskLevelPolicy

    init(riskPolicy: RiskLevelPolicy = RiskLevelPolicy()) {
        self.riskPolicy = riskPolicy
    }

    func makeThreatRecord(item: ScanItem, report: ScanReport, now: Date = Date()) -> ThreatRecord? {
        let verdict = report.finalVerdict
        let score = report.riskScore
        let riskLevel = riskPolicy.map(score: score, verdict: verdict)
        let findings = normalizeFindings(report: report)
        let persistenceIndicators = inferPersistenceIndicators(item: item, report: report, findings: findings)

        let shouldInclude = verdict != .clean
            || riskLevel == .critical
            || riskLevel == .high
            || (!findings.isEmpty && riskLevel != .info)
            || !persistenceIndicators.isEmpty
        guard shouldInclude else {
            return nil
        }

        let networkIndicators = report.networkSummary?.highlights ?? []
        let isSystemSensitive = isSystemSensitivePath(item.path)
        let canDisablePersistence = !persistenceIndicators.isEmpty
        let canDelete = !isSystemSensitive
        let canQuarantine = !isSystemSensitive || riskLevel == .critical || riskLevel == .high
        let canIgnore = true

        return ThreatRecord(
            threatID: UUID().uuidString,
            itemID: item.itemID,
            path: item.path,
            displayName: item.displayName,
            detectedType: item.detectedType,
            score: score,
            verdict: verdict,
            riskLevel: riskLevel,
            summary: report.reasoningSummary,
            findings: findings,
            persistenceIndicators: persistenceIndicators,
            networkIndicators: networkIndicators,
            cleanupRecommendations: cleanupRecommendations(
                riskLevel: riskLevel,
                persistenceIndicators: persistenceIndicators,
                canDelete: canDelete
            ),
            canQuarantine: canQuarantine,
            canDelete: canDelete,
            canIgnore: canIgnore,
            canDisablePersistence: canDisablePersistence,
            isSystemSensitive: isSystemSensitive,
            requiresExtraConfirmation: isSystemSensitive || riskLevel == .critical,
            status: .active,
            lastUpdatedAt: now,
            firstSeenAt: now
        )
    }

    func buildSummary(threats: [ThreatRecord]) -> ScanSummary {
        let activeThreats = threats.filter { $0.status == .active || $0.status == .failed }
        return ScanSummary(
            threatCount: activeThreats.count,
            criticalCount: activeThreats.filter { $0.riskLevel == .critical }.count,
            highCount: activeThreats.filter { $0.riskLevel == .high }.count,
            mediumCount: activeThreats.filter { $0.riskLevel == .medium }.count,
            lowCount: activeThreats.filter { $0.riskLevel == .low }.count,
            infoCount: activeThreats.filter { $0.riskLevel == .info }.count,
            persistenceCount: activeThreats.filter { !$0.persistenceIndicators.isEmpty }.count,
            quarantinedCount: threats.filter { $0.status == .quarantined }.count,
            ignoredCount: threats.filter { $0.status == .ignored }.count
        )
    }

    private func normalizeFindings(report: ScanReport) -> [ThreatFinding] {
        let findings = report.riskEvaluation?.allFindings ?? report.topFindings
        return findings.map { finding in
            ThreatFinding(
                ruleID: finding.id,
                title: finding.titleEN,
                severity: finding.severity ?? "medium",
                scoreDelta: finding.scoreDelta,
                category: finding.category ?? "generic",
                explanation: finding.explanation ?? finding.shortSummaryEN,
                evidenceSnippet: finding.shortSummaryEN,
                technicalDetails: finding.technicalDetails
            )
        }
    }

    private func inferPersistenceIndicators(item: ScanItem, report: ScanReport, findings: [ThreatFinding]) -> [String] {
        var indicators = report.analysisResult.persistenceIndicators
        let pathLower = item.path.lowercased()
        if pathLower.contains("launchagents") || pathLower.contains("launchdaemons") {
            indicators.append("launchd_persistence_path")
        }
        if pathLower.hasSuffix("/.zshrc") || pathLower.hasSuffix("/.bash_profile") || pathLower.hasSuffix("/.bashrc") {
            indicators.append("shell_profile_persistence")
        }
        if findings.contains(where: { $0.category == "persistence" }) {
            indicators.append("persistence_rule_hit")
        }
        return indicators.uniquePreservingOrder()
    }

    private func cleanupRecommendations(riskLevel: RiskLevel, persistenceIndicators: [String], canDelete: Bool) -> [String] {
        var notes: [String] = []
        notes.append("Prefer quarantine as the default remediation.")
        if !persistenceIndicators.isEmpty {
            notes.append("Disable persistence entry before or during quarantine.")
        }
        notes.append("Move to Trash is safer than permanent delete for user review.")
        if canDelete && (riskLevel == .critical || riskLevel == .high) {
            notes.append("Permanent delete is available only after explicit confirmation.")
        }
        if !canDelete {
            notes.append("System-sensitive path: avoid permanent delete.")
        }
        return notes
    }

    private func isSystemSensitivePath(_ path: String) -> Bool {
        let lower = path.lowercased()
        let home = fileManager.homeDirectoryForCurrentUser.path.lowercased()

        let blockedPrefixes = [
            "/system/",
            "/usr/lib/",
            "/bin/",
            "/sbin/",
            "/library/apple/",
            "\(home)/library/application support/beforeinstall",
            AppPaths.appSupportDirectory.path.lowercased(),
            AppPaths.quarantineDirectory.path.lowercased()
        ]
        return blockedPrefixes.contains(where: { lower.hasPrefix($0) })
    }
}
