import SwiftUI

struct AnalysisResultView: View {
    let result: AnalysisResult
    let language: AppLanguage
    let sessionLogs: [String]
    let scanReport: ScanReport?
    @Environment(\.appFontScale) private var appFontScale

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            TopSummaryCard(result: result, language: language, metrics: metrics, scanReport: scanReport, analysisMode: result.analysisMode)
            ComprehensiveReportSection(result: result, language: language, metrics: metrics, scanReport: scanReport, analysisMode: result.analysisMode)
            WhyRiskSection(assessment: result.riskAssessment, language: language, metrics: metrics)
            BasicInfoSection(result: result, language: language, metrics: metrics, scanReport: scanReport)

            if result.analysisMode != .dynamicOnly {
                DisclosureGroup(language == .zhHans ? "静态分析详情" : "Static Analysis Details") {
                    TypeSpecificSection(result: result, language: language, metrics: metrics)
                        .padding(.top, 8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }

            if (result.analysisMode == .dynamicOnly || result.analysisMode == .combined),
               let dynamic = result.dynamicReport
            {
                DynamicSection(report: dynamic, logs: sessionLogs, language: language, metrics: metrics)
            }

            SummarySection(lines: result.plainSummary, metrics: metrics)

            if !result.failureIssues.isEmpty {
                FailureIssuesSection(issues: result.failureIssues, language: language, metrics: metrics)
            }

            if !result.warnings.isEmpty {
                WarningsSection(warnings: result.warnings, language: language, metrics: metrics)
            }

            DisclosureGroup(Localizer.text("details.title", language: language)) {
                TechnicalDetailsSection(details: result.technicalDetails, language: language, metrics: metrics)
                    .padding(.top, 8)
            }
        }
        .padding(.top, 8)
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: appFontScale)
    }
}

private struct TopSummaryCard: View {
    let result: AnalysisResult
    let language: AppLanguage
    let metrics: AppScaleMetrics
    let scanReport: ScanReport?
    let analysisMode: AnalysisMode

    var body: some View {
        GroupBox(language == .zhHans ? "结论摘要" : "Summary") {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                HStack {
                    VStack(alignment: .leading, spacing: metrics.compactPadding * 0.2) {
                        Text(language == .zhHans ? "风险等级" : "Risk Level")
                            .appFont(.caption, metrics: metrics)
                            .foregroundStyle(.secondary)
                        Text("\(result.riskAssessment.level.displayName(language: language))  •  \(result.riskAssessment.score)/100")
                            .appFont(.headline, metrics: metrics)
                            .foregroundStyle(scoreColor(result.riskAssessment.score))
                    }
                    Spacer()
                }

                AdaptiveStack(tier: metrics.layoutTier, spacing: metrics.rowSpacing) {
                    if analysisMode != .dynamicOnly {
                        signalRow(language == .zhHans ? "签名" : "Signed", value: boolText(result.signatureInfo?.isSigned == true))
                        signalRow(language == .zhHans ? "公证" : "Notarized", value: boolText(result.signatureInfo?.isLikelyNotarized == true))
                        signalRow(language == .zhHans ? "后台/持久化线索" : "Persistence clues", value: boolText(hasPersistenceClues))
                    }
                }

                if analysisMode != .staticOnly {
                    AdaptiveStack(tier: metrics.layoutTier, spacing: metrics.rowSpacing) {
                        signalRow(language == .zhHans ? "网络活动" : "Network", value: boolText(result.dynamicReport?.overview.hasNetworkActivity == true))
                        signalRow(language == .zhHans ? "关键目录变更" : "Key path writes", value: boolText(hasKeyPathWrites))
                        signalRow(language == .zhHans ? "建议进一步 VM 分析" : "Recommend VM follow-up", value: boolText(shouldRecommendVM))
                    }
                }

                if let scanReport {
                    signalRow(
                        language == .zhHans ? "最终结论" : "Final Verdict",
                        value: scanReport.finalVerdict.displayName(language: language)
                    )
                }

                if analysisMode != .staticOnly {
                    Text(language == .zhHans
                         ? "动态分析属于受限动态观察/实验性行为分析，不是完整隔离沙箱。"
                         : "Dynamic analysis is restricted observation / experimental behavior analysis, not a full isolation sandbox.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                } else {
                    Text(language == .zhHans
                         ? "当前为静态分析模式，不包含网络/进程等动态观测板块。"
                         : "Static-only mode: dynamic network/process sections are intentionally hidden.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.top, metrics.compactPadding * 0.5)
        }
    }

    private var hasPersistenceClues: Bool {
        let staticHit = !(result.appDetails?.loginItems.isEmpty ?? true) || !(result.appDetails?.launchItems.isEmpty ?? true)
        let dynamicHit = result.dynamicReport?.overview.hasPersistenceAttempt == true
        return staticHit || dynamicHit
    }

    private var hasKeyPathWrites: Bool {
        result.dynamicReport?.fileObservations.contains(where: {
            $0.isSensitivePath && ($0.operation == "create" || $0.operation == "modify" || $0.operation == "delete")
        }) == true
    }

    private var shouldRecommendVM: Bool {
        result.riskAssessment.level == .high || hasKeyPathWrites || (result.dynamicReport?.overview.hasNetworkActivity == true)
    }

    private func boolText(_ value: Bool) -> String {
        value ? (language == .zhHans ? "是" : "Yes") : (language == .zhHans ? "否" : "No")
    }

    private func signalRow(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .appFont(.caption, metrics: metrics)
                .foregroundStyle(.secondary)
            Text(value)
                .appFont(.body, metrics: metrics)
                .fontWeight(.semibold)
        }
    }

    private func scoreColor(_ score: Int) -> Color {
        if score >= 70 { return .red }
        if score >= 40 { return .orange }
        return .green
    }
}

private struct ComprehensiveReportSection: View {
    let result: AnalysisResult
    let language: AppLanguage
    let metrics: AppScaleMetrics
    let scanReport: ScanReport?
    let analysisMode: AnalysisMode

    private var evaluation: RiskEvaluation {
        if let reportEval = scanReport?.riskEvaluation {
            return reportEval
        }
        if let cached = result.riskEvaluation {
            return cached
        }
        return RiskEngine().evaluate(result: result)
    }

    private var timelinePreview: [AnalysisEvent] {
        let events = result.dynamicResults?.events ?? result.dynamicReport?.dynamicResults?.events ?? []
        return events.sorted { $0.timestamp < $1.timestamp }
    }

    private var byteFormatter: ByteCountFormatter {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter
    }

    var body: some View {
        GroupBox(language == .zhHans ? "完整报告页" : "Comprehensive Report") {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                Text("\(language == .zhHans ? "最终风险分" : "Total Score"): \(evaluation.totalScore)/100  •  \(language == .zhHans ? "最终判定" : "Verdict"): \(evaluation.verdict.displayName(language: language))")
                    .appFont(.headline, metrics: metrics)
                    .foregroundStyle(scoreColor(evaluation.totalScore))
                Text(evaluation.reasoningSummary(language: language))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                Divider()

                sectionTitle(language == .zhHans ? "样本基本信息" : "Sample Basics")
                keyValue(language == .zhHans ? "路径" : "Path", value: result.basicInfo.fullPath)
                keyValue(language == .zhHans ? "类型" : "Type", value: result.basicInfo.fileType.displayName(language: language))
                keyValue(language == .zhHans ? "大小" : "Size", value: byteFormatter.string(fromByteCount: result.basicInfo.fileSizeBytes))
                keyValue("SHA256", value: scanReport?.sha256 ?? result.genericDetails?.sha256 ?? "-")

                sectionTitle("Top Findings")
                if evaluation.topFindings.isEmpty {
                    Text(language == .zhHans ? "未命中高风险规则，当前结论偏保守。" : "No high-risk rules hit; current conclusion is conservative.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(evaluation.topFindings.prefix(6)) { finding in
                        VStack(alignment: .leading, spacing: 2) {
                            Text("[\(finding.id)] \(finding.title(language: language)) (+\(finding.scoreDelta))")
                                .appFont(.body, metrics: metrics)
                                .fontWeight(.semibold)
                            if let evidence = finding.evidenceStrength,
                               let semantics = finding.executionSemantics
                            {
                                Text("\(language == .zhHans ? "证据" : "Evidence"): \(evidence)  •  \(language == .zhHans ? "语义" : "Semantics"): \(semantics)")
                                    .appFont(.caption, metrics: metrics)
                                    .foregroundStyle(.secondary)
                            }
                            Text(finding.shortSummary(language: language))
                                .appFont(.footnote, metrics: metrics)
                                .foregroundStyle(.secondary)
                            Text("\(language == .zhHans ? "技术细节" : "Technical"): \(finding.technicalDetails)")
                                .appFont(.caption, metrics: metrics)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                }

                if let trace = evaluation.staticScoringTrace, analysisMode != .dynamicOnly {
                    sectionTitle(language == .zhHans ? "静态评分 Trace" : "Static Scoring Trace")
                    keyValue(language == .zhHans ? "类型评分器" : "Type Scorer", value: trace.typeScorerUsed)
                    keyValue(language == .zhHans ? "基础分" : "Base Score", value: String(trace.baseScore))
                    keyValue(language == .zhHans ? "上下文调整" : "Context Adjustments", value: "\(trace.contextAdjustments.count)")
                    keyValue(language == .zhHans ? "链条加分" : "Chain Bonuses", value: "\(trace.chainBonuses.count)")
                    keyValue(language == .zhHans ? "封顶策略" : "Score Cap Decisions", value: "\(trace.scoreCapsApplied.count)")
                }

                if analysisMode != .dynamicOnly {
                    sectionTitle(language == .zhHans ? "静态分析摘要" : "Static Summary")
                    keyValue(language == .zhHans ? "签名状态" : "Signature", value: signatureStatus)
                    keyValue(language == .zhHans ? "静态能力线索" : "Static Capability Signals", value: "\(result.sensitiveCapabilities.count)")
                    keyValue(language == .zhHans ? "持久化线索" : "Persistence Signals", value: "\(result.persistenceIndicators.count)")

                    sectionTitle(language == .zhHans ? "脚本分析摘要" : "Script Summary")
                    if let script = result.scriptDetails {
                        keyValue(language == .zhHans ? "脚本类型" : "Script Type", value: script.scriptType.displayName(language: language))
                        keyValue(language == .zhHans ? "命中规则" : "Rule Hits", value: "\(script.ruleHits.count)")
                        ForEach(script.summary.prefix(3), id: \.self) { line in
                            Text("- \(line)")
                                .appFont(.caption, metrics: metrics)
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        Text(language == .zhHans ? "该样本不属于脚本类型或未启用脚本分析。" : "This sample is not a script type, or script analysis was not available.")
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                    }
                }

                if analysisMode != .staticOnly {
                    sectionTitle(language == .zhHans ? "动态行为时间线" : "Dynamic Timeline")
                    if timelinePreview.isEmpty {
                        Text(language == .zhHans ? "未采集到结构化动态事件。" : "No structured dynamic events were collected.")
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(timelinePreview.prefix(8)) { event in
                            Text("\(time(event.timestamp)) [\(event.category.rawValue)] \(event.action) -> \(event.target)")
                                .appFont(.caption, metrics: metrics)
                                .foregroundStyle(event.riskScoreDelta > 0 ? .orange : .secondary)
                                .textSelection(.enabled)
                        }
                    }

                    sectionTitle(language == .zhHans ? "进程树" : "Process Tree")
                    if let dynamic = result.dynamicReport, !dynamic.processTreeRoots.isEmpty {
                        let treePreview = dynamic.processTreeRoots.prefix(2).map { "\($0.command) [\($0.pid)]" }.joined(separator: "  |  ")
                        Text(treePreview)
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    } else {
                        Text(language == .zhHans ? "未生成进程树或父子关系不足。" : "Process tree unavailable or parent-child links were incomplete.")
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                    }

                    sectionTitle(language == .zhHans ? "文件系统改动" : "Filesystem Changes")
                    if let diff = result.dynamicReport?.fileSystemDiff {
                        keyValue(language == .zhHans ? "新增/修改/删除" : "Added/Modified/Deleted", value: "\(diff.added.count) / \(diff.modified.count) / \(diff.deleted.count)")
                        keyValue(language == .zhHans ? "敏感路径命中" : "Sensitive Path Hits", value: "\(diff.records.filter(\.whetherSensitivePath).count)")
                    } else {
                        Text(language == .zhHans ? "本次未获得差分结果。" : "No filesystem diff was produced for this run.")
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                    }

                    sectionTitle(language == .zhHans ? "网络行为" : "Network Behavior")
                    if let network = result.dynamicReport?.networkSummary {
                        keyValue(language == .zhHans ? "连接总数" : "Total Connections", value: "\(network.totalConnections)")
                        keyValue(language == .zhHans ? "远程连接" : "Remote Connections", value: "\(network.remoteConnections)")
                        keyValue(language == .zhHans ? "唯一目标" : "Unique Destinations", value: "\(network.uniqueDestinations.count)")
                        ForEach(network.highlights.prefix(3), id: \.self) { line in
                            Text("- \(line)")
                                .appFont(.caption, metrics: metrics)
                                .foregroundStyle(.orange)
                                .textSelection(.enabled)
                        }
                    } else {
                        Text(language == .zhHans ? "未观察到可用网络记录。" : "No network behavior records were available.")
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                    }
                }

                Text(language == .zhHans
                     ? "可通过上方“导出 -> JSON”按钮导出完整结构化报告。"
                     : "Use the Export -> JSON action above to save the full structured report.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, metrics.compactPadding * 0.5)
        }
    }

    private var signatureStatus: String {
        guard let signature = result.signatureInfo else {
            return language == .zhHans ? "未知" : "Unknown"
        }
        let status = signature.isSigned ? (language == .zhHans ? "已签名" : "Signed") : (language == .zhHans ? "未签名" : "Unsigned")
        let signer = signature.signerName ?? "-"
        return "\(status) (\(signer))"
    }

    private func sectionTitle(_ title: String) -> some View {
        Text(title)
            .appFont(.body, metrics: metrics)
            .fontWeight(.semibold)
    }

    private func keyValue(_ key: String, value: String) -> some View {
        HStack(alignment: .top, spacing: metrics.compactPadding * 0.5) {
            Text(key)
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
                .frame(width: metrics.layoutTier == .normal ? 128 : nil, alignment: .leading)
            Text(value)
                .appFont(.footnote, metrics: metrics)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func time(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }

    private func scoreColor(_ score: Int) -> Color {
        if score >= 70 { return .red }
        if score >= 40 { return .orange }
        return .green
    }
}

private struct WhyRiskSection: View {
    let assessment: RiskAssessment
    let language: AppLanguage
    let metrics: AppScaleMetrics

    var body: some View {
        GroupBox(language == .zhHans ? "为什么是这个风险等级？" : "Why this risk level?") {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                if assessment.breakdown.isEmpty {
                    Text(language == .zhHans ? "当前没有命中规则或证据不足。" : "No rules were triggered or evidence is insufficient.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(assessment.breakdown) { item in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(item.title(language: language))
                                    .appFont(.body, metrics: metrics)
                                Spacer()
                                Text("\(item.delta >= 0 ? "+" : "")\(item.delta)")
                                    .appFont(.body, metrics: metrics)
                                    .fontWeight(.semibold)
                                    .foregroundStyle(item.delta >= 0 ? .orange : .green)
                            }
                            Text(item.evidence)
                                .appFont(.caption, metrics: metrics)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                }

                Divider()
                Text(language == .zhHans
                     ? "总分 \(assessment.score) / 100，等级：\(assessment.level.displayName(language: language))"
                     : "Total \(assessment.score)/100, level: \(assessment.level.displayName(language: language))")
                    .appFont(.body, metrics: metrics)
                    .fontWeight(.semibold)
                    .foregroundStyle(scoreColor(assessment.score))
            }
            .padding(.top, metrics.compactPadding * 0.5)
        }
    }

    private func scoreColor(_ score: Int) -> Color {
        if score >= 70 { return .red }
        if score >= 40 { return .orange }
        return .green
    }
}

private struct BasicInfoSection: View {
    let result: AnalysisResult
    let language: AppLanguage
    let metrics: AppScaleMetrics
    let scanReport: ScanReport?

    private let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter
    }()

    private let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    var body: some View {
        GroupBox(Localizer.text("basic.title", language: language)) {
            VStack(alignment: .leading, spacing: 8) {
                infoRow(t("文件名", "File"), result.basicInfo.fileName)
                infoRow(t("类型", "Type"), result.basicInfo.fileType.displayName(language: language))
                infoRow(t("大小", "Size"), byteFormatter.string(fromByteCount: result.basicInfo.fileSizeBytes))
                infoRow(t("路径", "Path"), result.basicInfo.fullPath)
                infoRow(t("分析时间", "Analyzed At"), dateFormatter.string(from: result.analyzedAt))
                if let scanReport {
                    infoRow("SHA256", scanReport.sha256 ?? "-")
                    infoRow(t("识别来源", "Detection Source"), scanReport.detection.source.rawValue)
                }

                if let createdAt = result.basicInfo.createdAt {
                    infoRow(t("创建时间", "Created"), dateFormatter.string(from: createdAt))
                }

                if let modifiedAt = result.basicInfo.modifiedAt {
                    infoRow(t("修改时间", "Modified"), dateFormatter.string(from: modifiedAt))
                }

                if let app = result.appDetails {
                    infoRow(t("应用名", "App"), app.appName ?? "-")
                    infoRow(t("Bundle 标识", "Bundle ID"), app.bundleIdentifier ?? "-")
                    let versionText = [app.shortVersion, app.buildVersion].compactMap { $0 }.joined(separator: " / ")
                    infoRow(t("版本", "Version"), versionText.isEmpty ? "-" : versionText)
                }

                if let signature = result.signatureInfo {
                    infoRow(
                        t("签名", "Signature"),
                        signature.isSigned ? t("已签名", "Signed") : t("未签名", "Unsigned")
                    )
                    infoRow(t("开发者", "Developer"), signature.signerName ?? "-")
                    if let notarization = signature.notarizationStatus {
                        infoRow(t("公证状态", "Notarization"), notarization)
                    }
                }
            }
            .textSelection(.enabled)
            .padding(.top, metrics.compactPadding * 0.5)
        }
    }

    private func infoRow(_ title: String, _ value: String) -> some View {
        AdaptiveStack(tier: metrics.layoutTier, spacing: metrics.compactPadding * 0.6) {
            Text(title)
                .appFont(.body, metrics: metrics)
                .foregroundStyle(.secondary)
                .frame(width: metrics.layoutTier == .normal ? 120 : nil, alignment: .leading)
            Text(value.isEmpty ? "-" : value)
                .appFont(.body, metrics: metrics)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func t(_ zh: String, _ en: String) -> String {
        language == .zhHans ? zh : en
    }
}

private struct TypeSpecificSection: View {
    let result: AnalysisResult
    let language: AppLanguage
    let metrics: AppScaleMetrics

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            if let app = result.appDetails {
                GroupBox(t("应用结构线索", "Application Signals")) {
                    VStack(alignment: .leading, spacing: 6) {
                        tagLine(t("辅助组件", "Helpers"), app.helperItems)
                        tagLine(t("登录项", "Login Items"), app.loginItems)
                        tagLine(t("嵌入式框架", "Embedded Frameworks"), app.embeddedFrameworks)
                        tagLine(t("启动项", "Launch Items"), app.launchItems)
                    }
                    .padding(.top, 4)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            if let pkg = result.pkgDetails {
                GroupBox(t("安装包行为", "Package Behavior")) {
                    VStack(alignment: .leading, spacing: 6) {
                        tagLine(t("包标识", "Package IDs"), pkg.packageIdentifiers)
                        tagLine(t("安装目标路径", "Install Locations"), pkg.installLocations)
                        tagLine(t("修改位置", "Modified Locations"), pkg.modifiedLocations)
                        tagLine(t("脚本", "Scripts"), pkg.scripts.map { "\($0.scriptType): \($0.scriptPath)" })
                    }
                    .padding(.top, 4)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            if let dmg = result.dmgDetails {
                GroupBox(t("DMG 内容", "DMG Contents")) {
                    VStack(alignment: .leading, spacing: 6) {
                        tagLine(t("顶层内容", "Top-Level"), dmg.topLevelContents)
                        tagLine(t("内嵌目标", "Embedded Targets"), dmg.embeddedTargets.map {
                            let risk = $0.riskLevel?.displayName(language: language) ?? t("未知", "Unknown")
                            return "\($0.path) [\(t("风险", "Risk")): \(risk)]"
                        })
                    }
                    .padding(.top, 4)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            if let script = result.scriptDetails {
                GroupBox(t("脚本分析", "Script Analysis")) {
                    VStack(alignment: .leading, spacing: 8) {
                        tagLine(
                            t("基础信息", "Metadata"),
                            [
                                "\(t("脚本类型", "Type")): \(script.scriptType.displayName(language: language))",
                                "\(t("行数", "Lines")): \(script.lineCount)",
                                "\(t("Token 数", "Tokens")): \(script.tokenCount)",
                                "\(t("Shebang", "Shebang")): \(script.shebang ?? "-")"
                            ]
                        )
                        tagLine(t("摘要", "Summary"), script.summary)

                        if script.ruleHits.isEmpty {
                            Text(t("未发现高风险规则命中", "No high-risk rule hits found"))
                                .appFont(.footnote, metrics: metrics)
                                .foregroundStyle(.secondary)
                        } else {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(t("命中规则", "Rule Hits"))
                                    .appFont(.body, metrics: metrics)
                                    .fontWeight(.semibold)
                                ForEach(script.ruleHits.prefix(40)) { hit in
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("[\(hit.ruleID)] \(hit.title)")
                                            .appFont(.footnote, metrics: metrics)
                                            .fontWeight(.semibold)
                                        Text("\(t("严重级别", "Severity")): \(hit.severity.displayName(language: language))  •  L\(hit.lineStart)-\(hit.lineEnd)  •  Δ\(hit.suggestedRiskScoreDelta)")
                                            .appFont(.caption, metrics: metrics)
                                            .foregroundStyle(severityColor(hit.severity))
                                        Text("\(t("命中片段", "Matched")): \(hit.matchedContent)")
                                            .appFont(.caption, metrics: metrics)
                                            .foregroundStyle(.secondary)
                                            .textSelection(.enabled)
                                        Text("\(t("解释", "Explanation")): \(hit.explanation)")
                                            .appFont(.caption, metrics: metrics)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }
                    .padding(.top, 4)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            if let generic = result.genericDetails {
                GroupBox(t("通用文件线索", "Generic File Signals")) {
                    VStack(alignment: .leading, spacing: 6) {
                        tagLine("SHA256", [generic.sha256].compactMap { $0 })
                        tagLine(t("魔术类型", "Magic Type"), [generic.fileTypeByMagic].compactMap { $0 })
                        tagLine(t("MIME 类型", "MIME"), [generic.mimeType].compactMap { $0 })
                        tagLine(t("关键词命中", "Keyword Hits"), generic.suspiciousKeywordHits)
                    }
                    .padding(.top, 4)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func tagLine(_ title: String, _ values: [String]) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .appFont(.body, metrics: metrics)
                .fontWeight(.semibold)
            Text(values.isEmpty ? t("无", "None") : values.joined(separator: "\n"))
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }

    private func t(_ zh: String, _ en: String) -> String {
        language == .zhHans ? zh : en
    }

    private func severityColor(_ severity: ScriptFindingSeverity) -> Color {
        switch severity {
        case .low:
            return .secondary
        case .medium:
            return .orange
        case .high:
            return .red
        case .critical:
            return .red
        }
    }
}

private struct DynamicSection: View {
    let report: DynamicAnalysisReport
    let logs: [String]
    let language: AppLanguage
    let metrics: AppScaleMetrics
    @State private var showProcessFlatList = false
    @State private var showFileDiffDetails = false
    @State private var showNetworkDetails = false
    @State private var selectedTimelineCategory = "all"

    private var structuredEvents: [AnalysisEvent] {
        report.dynamicResults?.events ?? []
    }

    private var highRiskEvents: [AnalysisEvent] {
        report.dynamicResults?.highRiskEvents ?? structuredEvents.filter { $0.riskScoreDelta > 0 }
    }

    private var highRiskChains: [String] {
        report.highRiskChains
    }

    private var filteredStructuredEvents: [AnalysisEvent] {
        guard selectedTimelineCategory != "all",
              let category = AnalysisEventCategory(rawValue: selectedTimelineCategory)
        else {
            return structuredEvents
        }
        return structuredEvents.filter { $0.category == category }
    }

    var body: some View {
        GroupBox(Localizer.text("dynamic.section", language: language)) {
            VStack(alignment: .leading, spacing: metrics.groupSpacing) {
                dynamicSummary
                dynamicLaunchSection
                highRiskSection
                highRiskChainSection
                processTreeSection
                fileSystemSection
                networkSection
                timelineSection

                if !logs.isEmpty {
                    DisclosureGroup(language == .zhHans ? "会话日志（可折叠）" : "Session Logs (Collapsible)") {
                        ScrollView {
                            VStack(alignment: .leading, spacing: metrics.compactPadding * 0.3) {
                                ForEach(Array(logs.suffix(200).enumerated()), id: \.offset) { _, log in
                                    Text(log)
                                        .appFont(.monospacedCaption, metrics: metrics)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                            }
                        }
                        .frame(maxHeight: metrics.scaled(180))
                    }
                }
            }
            .padding(.top, metrics.compactPadding * 0.5)
            .frame(maxWidth: .infinity, alignment: .leading)
            .appFont(.body, metrics: metrics)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var dynamicLaunchSection: some View {
        VStack(alignment: .leading, spacing: metrics.compactPadding * 0.4) {
            Text(language == .zhHans ? "Dynamic Launch" : "Dynamic Launch")
                .appFont(.headline, metrics: metrics)

            if let launch = report.launchResult {
                VStack(alignment: .leading, spacing: metrics.compactPadding * 0.2) {
                    Text("\(language == .zhHans ? "启动方式" : "Launch Mode"): \(launchModeName(launch.launchMode))")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                    Text("\(language == .zhHans ? "启动成功" : "Launch Succeeded"): \(boolText(launch.launchSucceeded))")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                    Text("\(language == .zhHans ? "已尝试隐藏" : "Hide Attempted"): \(boolText(launch.hideAttempted))")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                    Text("\(language == .zhHans ? "隐藏成功" : "Hide Succeeded"): \(optionalBoolText(launch.hideSucceeded))")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                    Text("\(language == .zhHans ? "疑似抢占前台" : "Likely Foreground Activation"): \(optionalBoolText(launch.appLikelyActivatedForeground))")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle((launch.appLikelyActivatedForeground == true || launch.appLikelyDisplayedWindow == true) ? .orange : .secondary)
                    Text("\(language == .zhHans ? "疑似显示窗口" : "Likely Displayed Window"): \(optionalBoolText(launch.appLikelyDisplayedWindow))")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle((launch.appLikelyDisplayedWindow == true) ? .orange : .secondary)
                    Text("\(language == .zhHans ? "需要用户交互" : "Interaction Required"): \(boolText(launch.interactionRequired))")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(launch.interactionRequired ? .orange : .secondary)
                    if !launch.notes.isEmpty {
                        Text(launch.notes.joined(separator: " | "))
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
            } else {
                Text(language == .zhHans ? "未记录后台非激活启动结果。" : "No background launch result recorded.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var dynamicSummary: some View {
        VStack(alignment: .leading, spacing: metrics.compactPadding * 0.4) {
            Text(Localizer.text("dynamic.summary", language: language))
                .appFont(.headline, metrics: metrics)

            Text("\(language == .zhHans ? "状态" : "Status"): \(statusName(report.overview.status))")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
            Text("\(language == .zhHans ? "启动成功" : "Launch Succeeded"): \(boolText(report.overview.launchSucceeded))")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
            Text("\(language == .zhHans ? "运行时长" : "Duration"): \(Int(report.overview.actualDuration))s")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
            Text("\(language == .zhHans ? "子进程" : "Child Process"): \(boolText(report.overview.hasChildProcesses))  •  \(language == .zhHans ? "网络" : "Network"): \(boolText(report.overview.hasNetworkActivity))")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
            Text("\(language == .zhHans ? "关键目录" : "Key Paths"): \(boolText(report.overview.hasPersistenceAttempt))  •  \(language == .zhHans ? "崩溃" : "Crashed"): \(boolText(report.overview.crashed))")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)

            if let dynamic = report.dynamicResults {
                Text("\(language == .zhHans ? "会话 ID" : "Session ID"): \(dynamic.sessionID)")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                Text("\(language == .zhHans ? "结构化事件" : "Structured Events"): \(dynamic.events.count)  •  \(language == .zhHans ? "高风险事件" : "High-Risk Events"): \(dynamic.highRiskEvents.count)")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
                if !dynamic.fallbackSources.isEmpty {
                    Text("\(language == .zhHans ? "Fallback 来源" : "Fallback Sources"): \(dynamic.fallbackSources.joined(separator: " | "))")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            if let networkSummary = report.networkSummary {
                Text("\(language == .zhHans ? "网络连接总计" : "Network Connections"): \(networkSummary.totalConnections)  •  \(language == .zhHans ? "远程连接" : "Remote"): \(networkSummary.remoteConnections)")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }
            if let fs = report.fileSystemDiff {
                Text("\(language == .zhHans ? "文件差分记录" : "Filesystem Diff Records"): \(fs.records.count)")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }

            if !report.summaryLines.isEmpty {
                ForEach(report.summaryLines, id: \.self) { line in
                    Text("- \(line)")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var highRiskSection: some View {
        VStack(alignment: .leading, spacing: metrics.compactPadding * 0.35) {
            Text(language == .zhHans ? "高风险事件摘要" : "High-Risk Event Summary")
                .appFont(.headline, metrics: metrics)

            if highRiskEvents.isEmpty {
                Text(language == .zhHans ? "本次动态会话未命中高风险事件规则。": "No high-risk dynamic events were captured in this session.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(highRiskEvents.prefix(16)) { event in
                    Text("\(time(event.timestamp))  Δ+\(event.riskScoreDelta)  [\(eventCategoryName(event.category))]  \(event.action) -> \(event.target)")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(event.riskScoreDelta >= 16 ? .red : .orange)
                        .textSelection(.enabled)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var highRiskChainSection: some View {
        VStack(alignment: .leading, spacing: metrics.compactPadding * 0.35) {
            Text(language == .zhHans ? "高风险链路摘要" : "High-Risk Chain Summary")
                .appFont(.headline, metrics: metrics)

            if highRiskChains.isEmpty {
                Text(language == .zhHans ? "当前未形成明确高风险行为链。" : "No explicit high-risk behavior chain was built in this run.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(highRiskChains, id: \.self) { chain in
                    Text("- \(chain)")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var processTreeSection: some View {
        VStack(alignment: .leading, spacing: metrics.compactPadding * 0.4) {
            Text(Localizer.text("dynamic.processTree", language: language))
                .appFont(.headline, metrics: metrics)

            if report.processTreeRoots.isEmpty {
                Text(Localizer.text("dynamic.noTree", language: language))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(report.processTreeRoots) { node in
                    Text(treeLines(for: node).joined(separator: "\n"))
                        .appFont(.monospacedBody, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }

            if !report.processObservations.isEmpty {
                DisclosureGroup(
                    isExpanded: $showProcessFlatList,
                    content: {
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 4) {
                                ForEach(report.processObservations.prefix(120)) { process in
                                    Text("PID \(process.pid) <- \(process.ppid)  \(process.arguments)")
                                        .appFont(.footnote, metrics: metrics)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(2)
                                        .truncationMode(.middle)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .textSelection(.enabled)
                                }
                            }
                        }
                        .frame(maxHeight: metrics.scaled(190))
                    },
                    label: {
                        Text(Localizer.text("dynamic.flatList", language: language))
                            .appFont(.body, metrics: metrics)
                    }
                )
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var fileSystemSection: some View {
        VStack(alignment: .leading, spacing: metrics.compactPadding * 0.4) {
            Text(Localizer.text("dynamic.fsChanges", language: language))
                .appFont(.headline, metrics: metrics)

            if let diff = report.fileSystemDiff {
                Text("\(language == .zhHans ? "新增" : "Added"): \(diff.added.count)  •  \(language == .zhHans ? "修改" : "Modified"): \(diff.modified.count)  •  \(language == .zhHans ? "删除" : "Deleted"): \(diff.deleted.count)")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                if diff.isIncomplete {
                    Text(diff.note ?? Localizer.text("dynamic.diffIncomplete", language: language))
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.orange)
                }

                DisclosureGroup(
                    isExpanded: $showFileDiffDetails,
                    content: {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 8) {
                                if !diff.records.isEmpty {
                                    if !diff.addedRecords.isEmpty {
                                        fileChangeRecords(title: Localizer.text("dynamic.createdFiles", language: language), records: diff.addedRecords)
                                    }
                                    if !diff.modifiedRecords.isEmpty {
                                        fileChangeRecords(title: Localizer.text("dynamic.modifiedFiles", language: language), records: diff.modifiedRecords)
                                    }
                                    if !diff.deletedRecords.isEmpty {
                                        fileChangeRecords(title: Localizer.text("dynamic.deletedFiles", language: language), records: diff.deletedRecords)
                                    }
                                } else {
                                    if !diff.added.isEmpty {
                                        categoryPaths(title: Localizer.text("dynamic.createdFiles", language: language), paths: diff.added)
                                    }
                                    if !diff.modified.isEmpty {
                                        categoryPaths(title: Localizer.text("dynamic.modifiedFiles", language: language), paths: diff.modified)
                                    }
                                    if !diff.deleted.isEmpty {
                                        categoryPaths(title: Localizer.text("dynamic.deletedFiles", language: language), paths: diff.deleted)
                                    }
                                }
                            }
                        }
                        .frame(maxHeight: metrics.scaled(210))
                    },
                    label: {
                        Text(Localizer.text("dynamic.showDetails", language: language))
                            .appFont(.body, metrics: metrics)
                    }
                )
            } else {
                Text(Localizer.text("dynamic.noDiff", language: language))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var networkSection: some View {
        VStack(alignment: .leading, spacing: metrics.compactPadding * 0.4) {
            Text(Localizer.text("dynamic.network", language: language))
                .appFont(.headline, metrics: metrics)

            if report.networkRecords.isEmpty && report.networkObservations.isEmpty {
                Text(Localizer.text("dynamic.noNetwork", language: language))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            } else {
                if let summary = report.networkSummary {
                    Text(
                        language == .zhHans
                        ? "总连接 \(summary.totalConnections) 条，远程连接 \(summary.remoteConnections) 条，唯一目标 \(summary.uniqueDestinations.count) 个"
                        : "\(summary.totalConnections) total, \(summary.remoteConnections) remote, \(summary.uniqueDestinations.count) unique destinations"
                    )
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                    if !summary.highlights.isEmpty {
                        ForEach(summary.highlights, id: \.self) { highlight in
                            Text("- \(highlight)")
                                .appFont(.footnote, metrics: metrics)
                                .foregroundStyle(.orange)
                                .textSelection(.enabled)
                        }
                    }
                } else {
                    Text(
                        language == .zhHans
                        ? "已记录 \(report.networkObservations.count) 条连接摘要"
                        : "\(report.networkObservations.count) connection summaries captured"
                    )
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
                }

                DisclosureGroup(
                    isExpanded: $showNetworkDetails,
                    content: {
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 4) {
                                if !report.networkRecords.isEmpty {
                                    ForEach(report.networkRecords.prefix(220)) { record in
                                        VStack(alignment: .leading, spacing: 1) {
                                            Text("\(time(record.timestamp))  [\(record.protocolName)] \(record.processName)(\(record.processID)) -> \(record.destination):\(record.port)")
                                                .appFont(.footnote, metrics: metrics)
                                                .foregroundStyle(record.whetherRemote ? .orange : .secondary)
                                                .lineLimit(2)
                                                .truncationMode(.middle)
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                                .textSelection(.enabled)
                                            Text(verbatim:
                                                "\(language == .zhHans ? "远程" : "Remote")=\(record.whetherRemote)  \(language == .zhHans ? "域名" : "Domain")=\(record.dnsDomain ?? "-")"
                                            )
                                            .appFont(.caption, metrics: metrics)
                                            .foregroundStyle(.secondary)
                                        }
                                    }
                                } else {
                                    ForEach(report.networkObservations.prefix(120)) { net in
                                        Text("\(net.proto) \(net.endpoint):\(net.port) x\(net.count)")
                                            .appFont(.footnote, metrics: metrics)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(2)
                                            .truncationMode(.middle)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                            .textSelection(.enabled)
                                    }
                                }
                            }
                        }
                        .frame(maxHeight: metrics.scaled(210))
                    },
                    label: {
                        Text(Localizer.text("dynamic.showDetails", language: language))
                            .appFont(.body, metrics: metrics)
                    }
                )
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var timelineSection: some View {
        VStack(alignment: .leading, spacing: metrics.compactPadding * 0.4) {
            Text(Localizer.text("dynamic.timeline", language: language))
                .appFont(.headline, metrics: metrics)

            if !structuredEvents.isEmpty {
                Picker(
                    language == .zhHans ? "类别过滤" : "Category Filter",
                    selection: $selectedTimelineCategory
                ) {
                    Text(language == .zhHans ? "全部" : "All")
                        .tag("all")
                    ForEach(AnalysisEventCategory.allCases, id: \.rawValue) { category in
                        Text(eventCategoryName(category))
                            .tag(category.rawValue)
                    }
                }
                .pickerStyle(.menu)

                if filteredStructuredEvents.isEmpty {
                    Text(language == .zhHans ? "当前筛选下无事件。" : "No events in selected filter.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(filteredStructuredEvents.prefix(220)) { event in
                        VStack(alignment: .leading, spacing: 2) {
                            let processInfo = event.processID.map { " pid=\($0)" } ?? ""
                            Text("\(time(event.timestamp))  [\(eventCategoryName(event.category))]  \(event.action) -> \(event.target)\(processInfo)")
                                .appFont(.footnote, metrics: metrics)
                                .foregroundStyle(event.riskScoreDelta > 0 ? .orange : .secondary)
                                .textSelection(.enabled)
                            if !event.details.isEmpty {
                                Text(event.details.keys.sorted().map { "\($0)=\(event.details[$0] ?? "")" }.joined(separator: ", "))
                                    .appFont(.caption, metrics: metrics)
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }
                        }
                    }
                }
            } else if report.behaviorTimeline.isEmpty {
                Text(Localizer.text("dynamic.noTimeline", language: language))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(report.behaviorTimeline.sorted { $0.timestamp < $1.timestamp }) { event in
                    Text("\(time(event.timestamp))  [\(eventTypeName(event.type))]  \(event.summary)")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(event.isRiskHighlighted ? .orange : .secondary)
                        .textSelection(.enabled)
                }
            }
        }
    }

    private func categoryPaths(title: String, paths: [String]) -> some View {
        VStack(alignment: .leading, spacing: metrics.compactPadding * 0.3) {
            Text(title)
                .appFont(.footnote, metrics: metrics)
                .fontWeight(.semibold)
            ForEach(paths.prefix(80), id: \.self) { path in
                Text(path)
                    .appFont(.monospacedCaption, metrics: metrics)
                    .foregroundStyle(path.lowercased().contains("launch") ? .orange : .secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
        }
    }

    private func fileChangeRecords(title: String, records: [FileSystemChangeRecord]) -> some View {
        VStack(alignment: .leading, spacing: metrics.compactPadding * 0.3) {
            Text(title)
                .appFont(.footnote, metrics: metrics)
                .fontWeight(.semibold)
            ForEach(records.prefix(120)) { record in
                VStack(alignment: .leading, spacing: 1) {
                    Text(record.path)
                        .appFont(.monospacedCaption, metrics: metrics)
                        .foregroundStyle(record.whetherSensitivePath ? .orange : .secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                    Text(verbatim: "type=\(record.detectedType.rawValue) size=\(record.fileSize ?? 0) hash=\(record.hash ?? "-") sensitive=\(record.whetherSensitivePath)")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
        }
    }

    private func treeLines(for root: ProcessNode) -> [String] {
        var lines: [String] = []
        func walk(_ node: ProcessNode, prefix: String, isRoot: Bool, isLast: Bool) {
            let branch = isRoot ? "" : (isLast ? "└─ " : "├─ ")
            lines.append("\(prefix)\(branch)\(node.command) [\(node.pid)]")
            let children = node.children
            for (idx, child) in children.enumerated() {
                let nextPrefix = isRoot ? "" : (prefix + (isLast ? "   " : "│  "))
                walk(child, prefix: nextPrefix, isRoot: false, isLast: idx == children.count - 1)
            }
        }
        walk(root, prefix: "", isRoot: true, isLast: true)
        return lines
    }

    private func statusName(_ status: DynamicStatus) -> String {
        switch status {
        case .notRequested:
            return language == .zhHans ? "未请求" : "Not Requested"
        case .skipped:
            return language == .zhHans ? "已跳过" : "Skipped"
        case .completed:
            return language == .zhHans ? "已完成" : "Completed"
        case .failed:
            return language == .zhHans ? "失败" : "Failed"
        case .partial:
            return language == .zhHans ? "部分完成" : "Partial"
        case .interrupted:
            return language == .zhHans ? "已中断" : "Interrupted"
        case .noObservableActivity:
            return language == .zhHans ? "已执行（无明显行为）" : "Executed (No Obvious Activity)"
        }
    }

    private func boolText(_ value: Bool) -> String {
        value ? (language == .zhHans ? "是" : "Yes") : (language == .zhHans ? "否" : "No")
    }

    private func optionalBoolText(_ value: Bool?) -> String {
        guard let value else { return language == .zhHans ? "不确定" : "Unknown" }
        return boolText(value)
    }

    private func launchModeName(_ mode: String) -> String {
        if language != .zhHans { return mode }
        switch mode {
        case "background_non_activating":
            return "后台非激活启动"
        case "regular_launch":
            return "普通启动"
        case "direct_process_launch":
            return "直接进程启动"
        case "dyld_insert_libraries":
            return "DYLD 注入启动"
        case "launch_services_open":
            return "LaunchServices 启动"
        case "sandbox_exec":
            return "Sandbox 隔离启动"
        default:
            return mode
        }
    }

    private func eventTypeName(_ type: BehaviorEventType) -> String {
        if language != .zhHans {
            return type.rawValue
        }
        switch type {
        case .analysisStarted: return "分析开始"
        case .launchAttempted: return "尝试启动"
        case .launchFailed: return "启动失败"
        case .appLaunchStarted: return "后台启动流程开始"
        case .appLaunchSucceeded: return "后台启动成功"
        case .appHideAttempted: return "尝试隐藏应用"
        case .appHideSucceeded: return "隐藏成功"
        case .appHideFailed: return "隐藏失败"
        case .appLikelyActivatedForeground: return "疑似抢占前台"
        case .appLikelyDisplayedWindow: return "疑似显示窗口"
        case .interactionRequired: return "需要用户交互"
        case .processStarted: return "主进程启动"
        case .childProcessDiscovered: return "发现子进程"
        case .helperOrShellDiscovered: return "发现 helper/shell"
        case .fileCreated: return "新增文件"
        case .fileModified: return "修改文件"
        case .fileDeleted: return "删除文件"
        case .sensitivePathTouched: return "关键目录触达"
        case .networkConnection: return "网络连接"
        case .analysisFinished: return "分析结束"
        case .interrupted: return "分析中断"
        case .crashed: return "目标异常退出"
        case .warning: return "警告"
        }
    }

    private func eventCategoryName(_ category: AnalysisEventCategory) -> String {
        if language != .zhHans {
            return category.rawValue
        }
        switch category {
        case .processCreated: return "进程创建"
        case .processExited: return "进程退出"
        case .fileCreated: return "文件创建"
        case .fileModified: return "文件修改"
        case .fileDeleted: return "文件删除"
        case .networkConnect: return "网络连接"
        case .persistenceAttempt: return "持久化尝试"
        case .scriptExecuted: return "脚本执行"
        case .privilegeRelatedAction: return "权限相关行为"
        case .unknown: return "未知/其他"
        }
    }

    private func time(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }
}

private struct TechnicalDetailsSection: View {
    let details: [TechnicalDetail]
    let language: AppLanguage
    let metrics: AppScaleMetrics

    var body: some View {
        if details.isEmpty {
            Text(language == .zhHans ? "暂无可展示的技术详情" : "No technical details available")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
                .padding(.top, 4)
        } else {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(details) { detail in
                    TechnicalDetailRow(detail: detail, language: language, metrics: metrics)
                }
            }
            .padding(.top, 4)
        }
    }
}

private struct TechnicalDetailRow: View {
    let detail: TechnicalDetail
    let language: AppLanguage
    let metrics: AppScaleMetrics
    @State private var isExpanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            ScrollView(.horizontal) {
                Text(detail.content.isEmpty ? (language == .zhHans ? "（空）" : "(empty)") : detail.content)
                    .appFont(.monospacedBody, metrics: metrics)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(.top, 4)
            }
            .frame(maxHeight: 180)
        } label: {
            Text(detail.title)
                .appFont(.body, metrics: metrics)
        }
    }
}

private struct SummarySection: View {
    let lines: [String]
    let metrics: AppScaleMetrics

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                if lines.isEmpty {
                    Text("-")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                        Text("- \(line)")
                            .appFont(.body, metrics: metrics)
                    }
                }
            }
            .padding(.top, 4)
        }
    }
}

private struct WarningsSection: View {
    let warnings: [String]
    let language: AppLanguage
    let metrics: AppScaleMetrics

    var body: some View {
        GroupBox(Localizer.text("warnings.title", language: language)) {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(warnings.uniquePreservingOrder(), id: \.self) { warning in
                    Text("- \(warning)")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.orange)
                }
            }
            .padding(.top, 4)
        }
    }
}

private struct FailureIssuesSection: View {
    let issues: [FailureIssue]
    let language: AppLanguage
    let metrics: AppScaleMetrics

    var body: some View {
        GroupBox(Localizer.text("issues.title", language: language)) {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(issues) { issue in
                    VStack(alignment: .leading, spacing: 2) {
                        Text("• \(issue.title(language: language))")
                            .appFont(.body, metrics: metrics)
                            .fontWeight(.semibold)
                        Text(issue.rawMessage)
                            .appFont(.caption, metrics: metrics)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                        Text("\(Localizer.text("issues.suggestionPrefix", language: language))\(issue.suggestion(language: language))")
                            .appFont(.caption, metrics: metrics)
                            .foregroundStyle(.orange)
                    }
                }
            }
            .padding(.top, 4)
        }
    }
}
