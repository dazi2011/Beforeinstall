import Foundation
import AppKit

enum ReportExportFormat: String, CaseIterable, Identifiable {
    case markdown
    case json
    case text

    var id: String { rawValue }

    func fileExtension() -> String {
        switch self {
        case .markdown: return "md"
        case .json: return "json"
        case .text: return "txt"
        }
    }
}

@MainActor
enum ClipboardService {
    static func copy(_ text: String) {
        let board = NSPasteboard.general
        board.clearContents()
        board.setString(text, forType: .string)
    }
}

@MainActor
enum ReportExportService {
    static func export(
        result: AnalysisResult,
        language: AppLanguage,
        format: ReportExportFormat
    ) throws -> URL {
        let content: String
        switch format {
        case .markdown:
            content = buildMarkdown(result: result, language: language)
        case .json:
            content = try buildJSON(result: result, language: language)
        case .text:
            content = buildPlainText(result: result, language: language)
        }

        let filename = "\(result.basicInfo.fileName)-\(timestampString()).\(format.fileExtension())"
        return try save(content: content, suggestedFileName: filename)
    }

    static func copySummary(_ result: AnalysisResult) {
        ClipboardService.copy(result.plainSummary.joined(separator: "\n"))
    }

    static func copyTechnicalDetails(_ result: AnalysisResult) {
        let text = result.technicalDetails
            .map { "[\($0.title)]\n\($0.content)" }
            .joined(separator: "\n\n")
        ClipboardService.copy(text)
    }

    static func copySignature(_ result: AnalysisResult) {
        guard let signature = result.signatureInfo else {
            ClipboardService.copy("N/A")
            return
        }
        let lines = [
            "Signed: \(signature.isSigned)",
            "Signer: \(signature.signerName ?? "-")",
            "TeamIdentifier: \(signature.teamIdentifier ?? "-")",
            "SigningIdentifier: \(signature.signingIdentifier ?? "-")",
            "Notarization: \(signature.notarizationStatus ?? "-")",
            "Authorities: \(signature.authorities.joined(separator: ", "))"
        ]
        ClipboardService.copy(lines.joined(separator: "\n"))
    }

    static func copySHA256(_ result: AnalysisResult) {
        if let hash = result.genericDetails?.sha256 {
            ClipboardService.copy(hash)
            return
        }
        let hash = result.technicalDetails.first(where: { $0.title == "SHA256" })?.content ?? "N/A"
        ClipboardService.copy(hash)
    }

    static func copyNetworkSummary(_ result: AnalysisResult) {
        guard let report = result.dynamicReport else {
            ClipboardService.copy("N/A")
            return
        }
        if let summary = report.networkSummary {
            let text = [
                "Total: \(summary.totalConnections)",
                "Remote: \(summary.remoteConnections)",
                "Unique Destinations: \(summary.uniqueDestinations.count)",
                summary.highlights.isEmpty ? nil : "Highlights: \(summary.highlights.joined(separator: " | "))"
            ]
            .compactMap { $0 }
            .joined(separator: "\n")
            ClipboardService.copy(text)
            return
        }
        let text = report.networkObservations.map { "\($0.proto) \($0.endpoint):\($0.port) x\($0.count)" }.joined(separator: "\n")
        ClipboardService.copy(text.isEmpty ? "N/A" : text)
    }

    static func copyTimeline(_ result: AnalysisResult) {
        guard let report = result.dynamicReport else {
            ClipboardService.copy("N/A")
            return
        }
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        let lines: [String]
        if let events = report.dynamicResults?.events, !events.isEmpty {
            lines = events
                .sorted { $0.timestamp < $1.timestamp }
                .map {
                    let process = $0.processName.map { " \($0)" } ?? ""
                    return "\(formatter.string(from: $0.timestamp)) [\($0.category.rawValue)] \($0.action) -> \($0.target)\(process)"
                }
        } else {
            lines = report.behaviorTimeline
                .sorted { $0.timestamp < $1.timestamp }
                .map { "\(formatter.string(from: $0.timestamp)) [\($0.type.rawValue)] \($0.summary)" }
        }
        ClipboardService.copy(lines.joined(separator: "\n"))
    }

    private static func buildJSON(result: AnalysisResult, language: AppLanguage) throws -> String {
        let evaluation = resolvedRiskEvaluation(for: result)
        let exported = ExportedReport(
            schemaVersion: "1.0",
            generatedAt: Date(),
            mode: result.analysisMode,
            depth: result.analysisDepth,
            riskLevel: riskLevel(for: evaluation.verdict),
            riskScore: evaluation.totalScore,
            verdict: evaluation.verdict,
            reasoningSummary: evaluation.reasoningSummary(language: language),
            topFindings: evaluation.topFindings,
            allFindings: evaluation.allFindings,
            riskReasons: result.riskAssessment.breakdown,
            result: result,
            summary: result.plainSummary,
            filesystemDiff: result.dynamicReport?.fileSystemDiff,
            networkSummary: result.dynamicReport?.networkSummary,
            dynamicStatus: result.dynamicReport?.overview.status,
            dynamicFailureReasons: result.dynamicReport?.failureIssues ?? []
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(exported)
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    private static func buildMarkdown(result: AnalysisResult, language: AppLanguage) -> String {
        let evaluation = resolvedRiskEvaluation(for: result)
        var lines: [String] = []
        lines.append("# BeforeInstall Report")
        lines.append("")
        lines.append("- Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("- Mode: \(result.analysisMode.rawValue)")
        lines.append("- Depth: \(result.analysisDepth.rawValue)")
        lines.append("- Risk: \(result.riskAssessment.level.displayName(language: language)) (\(evaluation.totalScore)/100)")
        lines.append("- Verdict: \(evaluation.verdict.displayName(language: language))")
        lines.append("")
        lines.append("## Reasoning Summary")
        lines.append("- \(evaluation.reasoningSummary(language: language))")
        lines.append("")
        lines.append("## Top Findings")
        if evaluation.topFindings.isEmpty {
            lines.append("- N/A")
        } else {
            for finding in evaluation.topFindings {
                lines.append("- [\(finding.id)] \(finding.title(language: language)) (+\(finding.scoreDelta))")
                lines.append("  - \(finding.shortSummary(language: language))")
                lines.append("  - technical: `\(finding.technicalDetails)`")
            }
        }
        lines.append("")
        lines.append("## Basic Info")
        lines.append("- File: \(result.basicInfo.fileName)")
        lines.append("- Path: \(result.basicInfo.fullPath)")
        lines.append("- Type: \(result.basicInfo.fileType.displayName(language: language))")
        lines.append("- Size (bytes): \(result.basicInfo.fileSizeBytes)")
        if let sha = result.genericDetails?.sha256 {
            lines.append("- SHA256: \(sha)")
        }
        lines.append("")
        lines.append("## Risk Reasons")
        if evaluation.allFindings.isEmpty {
            lines.append("- N/A")
        } else {
            for item in evaluation.allFindings {
                lines.append("- \(item.title(language: language)): +\(item.scoreDelta) (`\(item.technicalDetails)`)")
            }
        }
        lines.append("")
        lines.append("## Static Signals")
        if let signature = result.signatureInfo {
            lines.append("- Signed: \(signature.isSigned)")
            lines.append("- Signer: \(signature.signerName ?? "-")")
            lines.append("- Team Identifier: \(signature.teamIdentifier ?? "-")")
            lines.append("- Signing Identifier: \(signature.signingIdentifier ?? "-")")
            lines.append("- Notarization: \(signature.notarizationStatus ?? "-")")
        } else {
            lines.append("- Signature: N/A")
        }
        if let app = result.appDetails {
            lines.append("- Bundle ID: \(app.bundleIdentifier ?? "-")")
            lines.append("- Version: \([app.shortVersion, app.buildVersion].compactMap { $0 }.joined(separator: " / "))")
            lines.append("- Helpers: \(app.helperItems.count)")
            lines.append("- Login Items: \(app.loginItems.count)")
            lines.append("- Launch Items: \(app.launchItems.count)")
        }
        if let pkg = result.pkgDetails {
            lines.append("- Package Scripts: \(pkg.scripts.count)")
            lines.append("- Install Locations: \(pkg.installLocations.joined(separator: ", "))")
        }
        lines.append("")
        lines.append("## Summary")
        result.plainSummary.forEach { lines.append("- \($0)") }
        lines.append("")
        lines.append("## Dynamic")
        if let dynamic = result.dynamicReport {
            lines.append("- Status: \(dynamic.overview.status.rawValue)")
            lines.append("- Duration: \(Int(dynamic.overview.actualDuration))s")
            lines.append("- Child Processes: \(dynamic.overview.hasChildProcesses)")
            lines.append("- Network: \(dynamic.overview.hasNetworkActivity)")
            lines.append("- File Writes: \(dynamic.overview.hasFileWriteActivity)")
            lines.append("- Persistence Paths: \(dynamic.overview.hasPersistenceAttempt)")
            if let session = dynamic.dynamicResults {
                lines.append("- Session ID: \(session.sessionID)")
                lines.append("- Structured Events: \(session.events.count)")
                lines.append("- High-risk Events: \(session.highRiskEvents.count)")
            }
            if let diff = dynamic.fileSystemDiff {
                lines.append("- File Diff: added=\(diff.added.count), modified=\(diff.modified.count), deleted=\(diff.deleted.count)")
                lines.append("- File Diff Records: \(diff.records.count)")
                if diff.isIncomplete {
                    lines.append("- Diff Incomplete: true")
                }
            }
            if let net = dynamic.networkSummary {
                lines.append("- Network Summary: total=\(net.totalConnections), remote=\(net.remoteConnections), uniqueDest=\(net.uniqueDestinations.count)")
            }
            if !dynamic.networkObservations.isEmpty {
                lines.append("")
                lines.append("### Network Endpoints")
                dynamic.networkObservations.forEach { net in
                    lines.append("- \(net.proto) \(net.endpoint):\(net.port) x\(net.count)")
                }
            }
            if !dynamic.networkRecords.isEmpty {
                lines.append("")
                lines.append("### Network Connections")
                dynamic.networkRecords.prefix(200).forEach { record in
                    lines.append("- [\(record.protocolName)] \(record.processName)(\(record.processID)) -> \(record.destination):\(record.port) remote=\(record.whetherRemote)")
                }
            }
            if let events = dynamic.dynamicResults?.events, !events.isEmpty {
                let formatter = DateFormatter()
                formatter.dateFormat = "HH:mm:ss"
                lines.append("")
                lines.append("### Behavior Timeline")
                events
                    .sorted { $0.timestamp < $1.timestamp }
                    .forEach { event in
                        lines.append("- \(formatter.string(from: event.timestamp)) [\(event.category.rawValue)] \(event.action) -> \(event.target)")
                    }
            } else if !dynamic.behaviorTimeline.isEmpty {
                let formatter = DateFormatter()
                formatter.dateFormat = "HH:mm:ss"
                lines.append("")
                lines.append("### Behavior Timeline (Legacy)")
                dynamic.behaviorTimeline
                    .sorted { $0.timestamp < $1.timestamp }
                    .forEach { event in
                        lines.append("- \(formatter.string(from: event.timestamp)) [\(event.type.rawValue)] \(event.summary)")
                    }
            }
            if !dynamic.highRiskChains.isEmpty {
                lines.append("")
                lines.append("### High-Risk Chains")
                dynamic.highRiskChains.forEach { lines.append("- \($0)") }
            }
            if !dynamic.warnings.isEmpty {
                lines.append("")
                lines.append("### Dynamic Warnings")
                dynamic.warnings.forEach { lines.append("- \($0)") }
            }
            if !dynamic.failureIssues.isEmpty {
                lines.append("")
                lines.append("### Dynamic Failure Reasons")
                dynamic.failureIssues.forEach { issue in
                    let suggestion = language == .zhHans ? issue.suggestionZH : issue.suggestionEN
                    lines.append("- \(issue.code): \(issue.rawMessage)")
                    lines.append("  - Suggestion: \(suggestion)")
                }
            }
        } else {
            lines.append("- Not executed")
        }
        if !result.failureIssues.isEmpty {
            lines.append("")
            lines.append("## Failure Reasons")
            for issue in result.failureIssues {
                let title = issue.title(language: language)
                let suggestion = issue.suggestion(language: language)
                lines.append("- \(title): \(issue.rawMessage)")
                lines.append("  - \(suggestion)")
            }
        }
        return lines.joined(separator: "\n")
    }

    private static func buildPlainText(result: AnalysisResult, language: AppLanguage) -> String {
        let evaluation = resolvedRiskEvaluation(for: result)
        var lines: [String] = []
        lines.append("BeforeInstall Summary")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("Risk: \(result.riskAssessment.level.displayName(language: language)) (\(evaluation.totalScore)/100)")
        lines.append("Verdict: \(evaluation.verdict.displayName(language: language))")
        lines.append("Reasoning: \(evaluation.reasoningSummary(language: language))")
        lines.append("Mode: \(result.analysisMode.rawValue)")
        lines.append("Depth: \(result.analysisDepth.rawValue)")
        lines.append("File: \(result.basicInfo.fileName)")
        lines.append("Type: \(result.basicInfo.fileType.displayName(language: language))")
        lines.append("")
        if !evaluation.topFindings.isEmpty {
            lines.append("Top findings:")
            evaluation.topFindings.forEach { finding in
                lines.append("- [\(finding.id)] \(finding.title(language: language)): +\(finding.scoreDelta)")
                lines.append("  \(finding.shortSummary(language: language))")
                lines.append("  technical: \(finding.technicalDetails)")
            }
            lines.append("")
        }
        if !evaluation.allFindings.isEmpty {
            lines.append("Why this risk level:")
            evaluation.allFindings.forEach { reason in
                lines.append("- \(reason.title(language: language)): +\(reason.scoreDelta) [\(reason.technicalDetails)]")
            }
            lines.append("")
        }
        result.plainSummary.forEach { lines.append("- \($0)") }
        if !result.warnings.isEmpty {
            lines.append("")
            lines.append("Warnings:")
            result.warnings.forEach { lines.append("- \($0)") }
        }
        if let dynamic = result.dynamicReport {
            lines.append("")
            lines.append("Dynamic Status: \(dynamic.overview.status.rawValue)")
            lines.append("Duration: \(Int(dynamic.overview.actualDuration))s")
            lines.append("Network: \(dynamic.overview.hasNetworkActivity)")
            lines.append("Persistence Path Writes: \(dynamic.overview.hasPersistenceAttempt)")
            if let session = dynamic.dynamicResults {
                lines.append("Structured Events: \(session.events.count)")
                lines.append("High-risk Events: \(session.highRiskEvents.count)")
            }
            if let summary = dynamic.networkSummary {
                lines.append("Network Connections: total=\(summary.totalConnections), remote=\(summary.remoteConnections)")
            }
            if let diff = dynamic.fileSystemDiff {
                lines.append("Filesystem Diff: added=\(diff.added.count), modified=\(diff.modified.count), deleted=\(diff.deleted.count)")
            }
            if !dynamic.highRiskChains.isEmpty {
                lines.append("High-risk Chains:")
                dynamic.highRiskChains.forEach { lines.append("- \($0)") }
            }
            if !dynamic.failureIssues.isEmpty {
                lines.append("Dynamic Failures:")
                dynamic.failureIssues.forEach { lines.append("- \($0.rawMessage)") }
            }
        } else if result.analysisMode == .dynamicOnly || result.analysisMode == .combined {
            lines.append("")
            lines.append("Dynamic Status: insufficient or not executed.")
        }
        return lines.joined(separator: "\n")
    }

    private static func resolvedRiskEvaluation(for result: AnalysisResult) -> RiskEvaluation {
        if let cached = result.riskEvaluation {
            return cached
        }
        return RiskEngine().evaluate(result: result)
    }

    private static func riskLevel(for verdict: ScanVerdict) -> RiskLevel {
        switch verdict {
        case .clean:
            return .low
        case .suspicious, .unknown:
            return .medium
        case .malicious:
            return .high
        }
    }

    private static func save(content: String, suggestedFileName: String) throws -> URL {
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = suggestedFileName
        let response = panel.runModal()
        guard response == .OK, let url = panel.url else {
            throw NSError(domain: "BeforeInstall.Export", code: 1, userInfo: [NSLocalizedDescriptionKey: "Export canceled"])
        }
        guard let data = content.data(using: .utf8) else {
            throw NSError(domain: "BeforeInstall.Export", code: 2, userInfo: [NSLocalizedDescriptionKey: "UTF-8 encoding failed"])
        }
        try data.write(to: url, options: .atomic)
        return url
    }

    private static func timestampString() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }
}
