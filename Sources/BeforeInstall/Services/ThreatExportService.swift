import Foundation
import AppKit

enum ThreatExportFormat: String, CaseIterable, Identifiable {
    case json
    case csv
    case markdown

    var id: String { rawValue }

    var fileExtension: String {
        switch self {
        case .json: return "json"
        case .csv: return "csv"
        case .markdown: return "md"
        }
    }
}

@MainActor
enum ThreatExportService {
    static func export(
        session: ScanSession,
        remediationLogs: [RemediationLogEntry],
        format: ThreatExportFormat
    ) throws -> URL {
        let content: String
        switch format {
        case .json:
            content = try buildJSON(session: session, remediationLogs: remediationLogs)
        case .csv:
            content = buildCSV(session: session)
        case .markdown:
            content = buildMarkdown(session: session, remediationLogs: remediationLogs)
        }

        let filename = "fullscan-\(session.sessionID).\(format.fileExtension)"
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = filename
        guard panel.runModal() == .OK, let url = panel.url else {
            throw NSError(domain: "BeforeInstall.ThreatExport", code: 1, userInfo: [NSLocalizedDescriptionKey: "Export cancelled"])
        }
        guard let data = content.data(using: .utf8) else {
            throw NSError(domain: "BeforeInstall.ThreatExport", code: 2, userInfo: [NSLocalizedDescriptionKey: "UTF-8 encoding failed"])
        }
        try data.write(to: url, options: .atomic)
        return url
    }

    private static func buildJSON(session: ScanSession, remediationLogs: [RemediationLogEntry]) throws -> String {
        struct Payload: Codable {
            var schemaVersion: String
            var exportedAt: Date
            var session: ScanSession
            var remediationLogs: [RemediationLogEntry]
        }

        let payload = Payload(
            schemaVersion: "1.0",
            exportedAt: Date(),
            session: session,
            remediationLogs: remediationLogs
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(payload)
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    private static func buildCSV(session: ScanSession) -> String {
        var lines: [String] = []
        lines.append("session_id,mode,started_at,completed_at,total_candidates,analyzed,skipped,failed,path,detected_type,score,verdict,risk_level,status,summary,findings")
        let iso = ISO8601DateFormatter()
        for threat in session.threats {
            let findings = threat.findings.map { "\($0.ruleID):\($0.title)" }.joined(separator: " | ")
            lines.append([
                csv(session.sessionID),
                csv(session.mode.rawValue),
                csv(iso.string(from: session.startedAt)),
                csv(session.completedAt.map(iso.string(from:)) ?? ""),
                String(session.totalCandidates),
                String(session.analyzedCount),
                String(session.skippedCount),
                String(session.failedCount),
                csv(threat.path),
                csv(threat.detectedType.rawValue),
                String(threat.score),
                csv(threat.verdict.rawValue),
                csv(threat.riskLevel.rawValue),
                csv(threat.status.rawValue),
                csv(threat.summary),
                csv(findings)
            ].joined(separator: ","))
        }
        return lines.joined(separator: "\n")
    }

    private static func buildMarkdown(session: ScanSession, remediationLogs: [RemediationLogEntry]) -> String {
        let iso = ISO8601DateFormatter()
        var lines: [String] = []
        lines.append("# Full Disk Scan Report")
        lines.append("")
        lines.append("- Session: `\(session.sessionID)`")
        lines.append("- Mode: `\(session.mode.rawValue)`")
        lines.append("- Started: \(iso.string(from: session.startedAt))")
        lines.append("- Completed: \(session.completedAt.map(iso.string(from:)) ?? "-")")
        lines.append("- Scopes: \(session.rootScopes.joined(separator: ", "))")
        lines.append("- Total candidates: \(session.totalCandidates)")
        lines.append("- Analyzed / Skipped / Failed: \(session.analyzedCount) / \(session.skippedCount) / \(session.failedCount)")
        lines.append("- Risk items: \(session.summary.threatCount)")
        lines.append("- Critical / High / Medium / Low / Info: \(session.summary.criticalCount) / \(session.summary.highCount) / \(session.summary.mediumCount) / \(session.summary.lowCount) / \(session.summary.infoCount)")
        lines.append("- Persistence suspicious: \(session.summary.persistenceCount)")
        lines.append("- Quarantined: \(session.summary.quarantinedCount)")
        lines.append("- Ignored: \(session.summary.ignoredCount)")
        if let perf = session.performanceTrace {
            lines.append("- Performance: enumerated \(perf.totalEnumerated), candidates \(perf.totalCandidates), escalated \(perf.totalEscalated), analyzed \(perf.totalAnalyzed), elapsed \(perf.elapsedTimeMs)ms")
            if let tracePath = perf.exportedTracePath {
                lines.append("- Performance trace: `\(tracePath)`")
            }
        }
        lines.append("")
        lines.append("## Threats")
        if session.threats.isEmpty {
            lines.append("- None")
        } else {
            for threat in session.threats {
                lines.append("- `[\(threat.riskLevel.rawValue.uppercased())]` \(threat.displayName) (`\(threat.verdict.rawValue)`) ")
                lines.append("  - path: `\(threat.path)`")
                lines.append("  - type: `\(threat.detectedType.rawValue)`")
                lines.append("  - status: `\(threat.status.rawValue)`")
                lines.append("  - summary: \(threat.summary)")
                if !threat.findings.isEmpty {
                    lines.append("  - findings:")
                    for finding in threat.findings.prefix(5) {
                        lines.append("    - [\(finding.ruleID)] \(finding.title) (\(finding.severity), +\(finding.scoreDelta))")
                    }
                }
            }
        }
        lines.append("")
        lines.append("## Remediation History")
        if remediationLogs.isEmpty {
            lines.append("- None")
        } else {
            for log in remediationLogs.prefix(120) {
                lines.append("- \(iso.string(from: log.timestamp)) `\(log.actionType.rawValue)` `\(log.status.rawValue)` `\(log.path)` - \(log.message)")
            }
        }
        return lines.joined(separator: "\n")
    }

    private static func csv(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "\"", with: "\"\"")
        return "\"\(escaped)\""
    }
}
