import SwiftUI
import AppKit

struct DeveloperBenchmarkPanelView: View {
    private enum DeveloperModule: String, CaseIterable, Identifiable {
        case benchmark
        case modelTraining

        var id: String { rawValue }
    }

    @ObservedObject var settings: AppSettingsStore
    @ObservedObject var viewModel: AnalysisViewModel
    let metrics: AppScaleMetrics

    @State private var selectedDetailRow: BenchmarkResultTableRow?
    @State private var selectedRowID: BenchmarkResultTableRow.ID?
    @State private var onlyMismatch = false
    @State private var onlyFailed = false
    @State private var groupFilter = "all"
    @State private var verdictFilter = "all"
    @State private var scoreSortDescending = true
    @State private var selectedModule: DeveloperModule = .benchmark

    private let groupOrder: [String] = ["clean", "noisy_benign", "suspicious", "replay_clean", "replay_suspicious", "replay_malicious"]

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            internalBanner
            moduleTabs
            switch selectedModule {
            case .benchmark:
                benchmarkRootSection
                runControlsSection
                benchmarkHistorySection
                summaryCardsSection
                groupBreakdownSection
                sampleTableSection
                diffViewSection
            case .modelTraining:
                modelTrainingSection
            }
        }
        .sheet(item: $selectedDetailRow) { row in
            benchmarkDetailSheet(row)
        }
    }

    private var filteredRows: [BenchmarkResultTableRow] {
        var rows = viewModel.benchmarkRows

        if onlyMismatch {
            rows = rows.filter { $0.matchedExpectation == false || $0.mismatchReason != nil }
        }
        if onlyFailed {
            rows = rows.filter { $0.status == .failed }
        }
        if groupFilter != "all" {
            rows = rows.filter { $0.group == groupFilter }
        }
        if verdictFilter != "all" {
            rows = rows.filter { normalizeVerdict($0.verdict) == verdictFilter }
        }

        rows.sort { lhs, rhs in
            let left = lhs.score ?? -1
            let right = rhs.score ?? -1
            if left == right {
                return lhs.sampleID < rhs.sampleID
            }
            return scoreSortDescending ? left > right : left < right
        }

        return rows
    }

    private var groupFilterOptions: [String] {
        ["all"] + viewModel.benchmarkRows.map(\.group).uniquePreservingOrder().sorted()
    }

    private var internalBanner: some View {
        HStack(spacing: metrics.rowSpacing) {
            labelTag("Internal")
            labelTag("Benchmark")
            labelTag("Developer Tools")
            labelTag("Regression")

            Spacer()
        }
    }

    private var moduleTabs: some View {
        HStack(spacing: metrics.rowSpacing) {
            ForEach(DeveloperModule.allCases) { module in
                Button {
                    selectedModule = module
                } label: {
                    Text(moduleTitle(module))
                        .appFont(.body, metrics: metrics)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(
                            Capsule()
                                .fill(selectedModule == module ? Color.accentColor.opacity(0.16) : Color(nsColor: .controlBackgroundColor))
                        )
                }
                .buttonStyle(.plain)
            }
            Spacer()
            Text(t("构建通道：", "Build: ") + DeveloperModePolicy.buildLabel)
                .appFont(.caption, metrics: metrics)
                .foregroundStyle(.secondary)
        }
    }

    private func moduleTitle(_ module: DeveloperModule) -> String {
        switch module {
        case .benchmark:
            return t("Benchmark 评测", "Benchmark Evaluation")
        case .modelTraining:
            return t("训练模型", "Train Model")
        }
    }

    private var modelTrainingSection: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            GroupBox(t("A. 随机森林训练", "A. Random-Forest Training")) {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    HStack(spacing: metrics.rowSpacing) {
                        Button(t("选择样本目录", "Choose Dataset")) {
                            viewModel.openAITrainingDatasetImporter()
                        }
                        .buttonStyle(.bordered)

                        Button(t("选择输出目录", "Choose Output")) {
                            viewModel.openAITrainingOutputImporter()
                        }
                        .buttonStyle(.bordered)

                        Button(t("开始训练", "Start Training")) {
                            viewModel.runAIModelTraining()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(viewModel.isAITrainingRunning)

                        Spacer()

                        if viewModel.isAITrainingRunning {
                            ProgressView()
                                .controlSize(.small)
                        }
                    }

                    detailLine(
                        t("训练脚本", "Training Script"),
                        RandomForestModelService.shared.runtimeScriptURL.path
                    )
                    detailLine(
                        t("样本目录", "Dataset"),
                        viewModel.aiTrainingDatasetPath.isEmpty ? t("未选择", "Not selected") : viewModel.aiTrainingDatasetPath
                    )
                    detailLine(
                        t("输出目录", "Output"),
                        viewModel.aiTrainingOutputPath.isEmpty ? t("未选择", "Not selected") : viewModel.aiTrainingOutputPath
                    )

                    if let status = viewModel.aiTrainingStatusMessage, !status.isEmpty {
                        Text(status)
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                    }

                    if !viewModel.aiTrainingOutputPath.isEmpty {
                        HStack(spacing: metrics.rowSpacing) {
                            Button(t("打开输出目录", "Open Output Folder")) {
                                NSWorkspace.shared.open(URL(fileURLWithPath: viewModel.aiTrainingOutputPath))
                            }
                            .buttonStyle(.bordered)
                            .disabled(!FileManager.default.fileExists(atPath: viewModel.aiTrainingOutputPath))

                            Spacer()
                        }
                    }

                    Text(t(
                        "训练会调用：python3 <内置脚本> <样本目录> --output-dir <输出目录>，并在输出目录生成 .joblib 与报告文件。",
                        "Training runs: python3 <bundled script> <dataset> --output-dir <output>, then writes .joblib and reports into that output folder."
                    ))
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
                }
                .padding(.top, 4)
            }

            GroupBox(t("B. 核心切换提示", "B. Model Core Switch")) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(t(
                        "训练完成后，到主界面“配置文件”页点击“上传 joblib 核心”，即可替换当前运行模型。",
                        "After training, open the Config Profiles tab and use “Upload joblib Core” to replace the active runtime model."
                    ))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 4)
            }
        }
    }

    private var benchmarkRootSection: some View {
        GroupBox(t("A. Benchmark 根目录", "A. Benchmark Root")) {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                HStack(spacing: metrics.rowSpacing) {
                    Button(t("选择 benchmark 目录", "Choose Benchmark Root")) {
                        viewModel.openBenchmarkRootImporter()
                    }
                    .buttonStyle(.bordered)

                    Spacer()
                }

                Text(settings.benchmarkRootPath.isEmpty ? t("未设置 benchmark 根目录", "Benchmark root is not set") : settings.benchmarkRootPath)
                    .appFont(.monospacedCaption, metrics: metrics)
                    .foregroundStyle(settings.benchmarkRootPath.isEmpty ? .secondary : .primary)
                    .textSelection(.enabled)

                Text(t("路径已持久化，沙盒场景下优先走 security-scoped bookmark。", "Path is persisted; sandbox mode prefers security-scoped bookmark."))
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 4)
        }
    }

    private var runControlsSection: some View {
        GroupBox(t("B. 运行控制", "B. Run Controls")) {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                HStack(spacing: metrics.rowSpacing) {
                    Button(t("扫描 Benchmark", "Scan Benchmark")) {
                        viewModel.scanBenchmarkCatalog()
                    }
                    .buttonStyle(.bordered)
                    .disabled(viewModel.isBenchmarkRunning)

                    Button(t("运行全量 Benchmark", "Run Full Benchmark")) {
                        viewModel.runFullBenchmark()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(viewModel.isBenchmarkRunning)

                    Button(t("取消", "Cancel")) {
                        viewModel.cancelBenchmarkRun()
                    }
                    .buttonStyle(.bordered)
                    .disabled(!viewModel.isBenchmarkRunning)

                    Button(t("导出全部", "Export Bundle")) {
                        viewModel.exportBenchmarkResults()
                    }
                    .buttonStyle(.bordered)

                    Spacer()

                    if viewModel.isBenchmarkRunning {
                        ProgressView()
                            .controlSize(.small)
                    }
                }

                HStack(spacing: metrics.rowSpacing) {
                    Button("raw_results.json") {
                        viewModel.exportBenchmarkArtifact(.rawResults)
                    }
                    .buttonStyle(.borderless)

                    Button("summary.md") {
                        viewModel.exportBenchmarkArtifact(.summaryMarkdown)
                    }
                    .buttonStyle(.borderless)

                    Button("samples.csv") {
                        viewModel.exportBenchmarkArtifact(.samplesCSV)
                    }
                    .buttonStyle(.borderless)

                    Button("diff.md") {
                        viewModel.exportBenchmarkArtifact(.diffMarkdown)
                    }
                    .buttonStyle(.borderless)
                    .disabled(viewModel.benchmarkDiffSummary == nil)

                    Button("scoring_trace.json") {
                        viewModel.exportBenchmarkArtifact(.scoringTrace)
                    }
                    .buttonStyle(.borderless)

                    Button("findings_trace.json") {
                        viewModel.exportBenchmarkArtifact(.findingsTrace)
                    }
                    .buttonStyle(.borderless)

                    Button("score_cap_trace.json") {
                        viewModel.exportBenchmarkArtifact(.scoreCapTrace)
                    }
                    .buttonStyle(.borderless)

                    Button("context_trace.json") {
                        viewModel.exportBenchmarkArtifact(.contextTrace)
                    }
                    .buttonStyle(.borderless)
                }

                if let status = viewModel.benchmarkStatusMessage, !status.isEmpty {
                    Text(status)
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                }

                if let output = viewModel.benchmarkLastRunDirectoryPath, !output.isEmpty {
                    HStack(spacing: metrics.rowSpacing) {
                        Text(t("最近输出：", "Latest output: "))
                            .appFont(.caption, metrics: metrics)
                            .foregroundStyle(.secondary)
                        Text(output)
                            .appFont(.monospacedCaption, metrics: metrics)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                        Button(t("打开", "Open")) {
                            NSWorkspace.shared.open(URL(fileURLWithPath: output))
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
            .padding(.top, 4)
        }
    }

    private var benchmarkHistorySection: some View {
        GroupBox(t("B1. 历史运行", "B1. Run History")) {
            if viewModel.benchmarkRunHistory.isEmpty {
                Text(t("暂无 benchmark 历史运行。", "No benchmark history runs yet."))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    ForEach(viewModel.benchmarkRunHistory.prefix(8), id: \.runID) { run in
                        HStack(alignment: .top, spacing: metrics.rowSpacing) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(run.runID)
                                    .appFont(.monospacedCaption, metrics: metrics)
                                Text(t(
                                    "总 \(run.summary.totalSamples) • 已分析 \(run.summary.analyzedSamples) • 失败 \(run.summary.failedSamples) • 均分 \(String(format: "%.2f", run.summary.averageScore))",
                                    "total \(run.summary.totalSamples) • analyzed \(run.summary.analyzedSamples) • failed \(run.summary.failedSamples) • avg \(String(format: "%.2f", run.summary.averageScore))"
                                ))
                                .appFont(.caption, metrics: metrics)
                                .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button(t("加载", "Open")) {
                                viewModel.openBenchmarkHistoryRun(run.runID)
                            }
                            .buttonStyle(.borderless)
                        }
                        Divider()
                    }
                }
            }
        }
    }

    private var summaryCardsSection: some View {
        GroupBox(t("C. 摘要卡片", "C. Summary Cards")) {
            let stats = viewModel.benchmarkStatistics
            let cleanFP = viewModel.benchmarkRows.filter { row in
                row.group == "clean" && (normalizeVerdict(row.verdict) == "suspicious" || normalizeVerdict(row.verdict) == "malicious")
            }.count
            let maliciousMiss = viewModel.benchmarkRows.filter { row in
                row.group == "replay_malicious" && (normalizeVerdict(row.verdict) == "clean" || normalizeVerdict(row.verdict) == "unknown")
            }.count

            let cards: [(String, String)] = [
                (t("总样本", "Total"), String(stats.totalSamples)),
                (t("平均分", "Avg Score"), String(format: "%.2f", stats.averageScore)),
                (t("clean 误报", "Clean FP"), String(cleanFP)),
                (t("恶意漏报", "Malicious Miss"), String(maliciousMiss)),
                (t("失败数", "Failed"), String(stats.failedSamples))
            ]

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 128), alignment: .leading)], spacing: metrics.rowSpacing) {
                ForEach(cards, id: \.0) { item in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.0)
                            .appFont(.caption, metrics: metrics)
                            .foregroundStyle(.secondary)
                        Text(item.1)
                            .appFont(.body, metrics: metrics)
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 2)
                }
            }

            Divider()

            Text(t("准确性指标", "Accuracy Metrics"))
                .appFont(.caption, metrics: metrics)
                .foregroundStyle(.secondary)
            Text("\(t("判定准确率", "Verdict accuracy")): \(rateText(viewModel.benchmarkStatistics.verdictAccuracy))")
                .appFont(.footnote, metrics: metrics)
            Text("\(t("分数区间匹配率", "Score range match")): \(rateText(viewModel.benchmarkStatistics.scoreRangeMatchRate))")
                .appFont(.footnote, metrics: metrics)
            Text("\(t("clean 误报率", "Clean FP rate")): \(rateText(viewModel.benchmarkStatistics.cleanFalsePositiveRate))")
                .appFont(.footnote, metrics: metrics)
            Text("\(t("noisy_benign 误报率", "Noisy benign FP rate")): \(rateText(viewModel.benchmarkStatistics.noisyBenignFalsePositiveRate))")
                .appFont(.footnote, metrics: metrics)
            Text("\(t("suspicious 命中率", "Suspicious hit rate")): \(rateText(viewModel.benchmarkStatistics.suspiciousHitRate))")
                .appFont(.footnote, metrics: metrics)
            Text("\(t("replay_malicious 检出率", "Replay malicious detection rate")): \(rateText(viewModel.benchmarkStatistics.replayMaliciousDetectionRate))")
                .appFont(.footnote, metrics: metrics)
        }
    }

    private var groupBreakdownSection: some View {
        GroupBox(t("D. 分组明细", "D. Group Breakdown")) {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                Table(groupRows()) {
                    TableColumn(t("分组", "Group")) { item in
                        Text(item.group)
                            .appFont(.caption, metrics: metrics)
                    }
                    TableColumn(t("总数", "Total")) { item in
                        Text(String(item.summary?.total ?? 0))
                            .appFont(.caption, metrics: metrics)
                    }
                    TableColumn(t("已分析", "Analyzed")) { item in
                        Text(String(item.summary?.analyzed ?? 0))
                            .appFont(.caption, metrics: metrics)
                    }
                    TableColumn(t("失败", "Failed")) { item in
                        Text(String(item.summary?.failed ?? 0))
                            .appFont(.caption, metrics: metrics)
                    }
                    TableColumn(t("均分", "Avg")) { item in
                        Text(String(format: "%.2f", item.summary?.avgScore ?? 0))
                            .appFont(.caption, metrics: metrics)
                    }
                }
                .frame(minHeight: 140)

                if let run = viewModel.benchmarkLastReport, !run.summary.scoreMonotonicityHints.isEmpty {
                    Text(t("分数组间单调性提示", "Score Monotonicity Hints"))
                        .appFont(.caption, metrics: metrics)
                        .foregroundColor(run.summary.isScoreMonotonic ? .secondary : .orange)
                    ForEach(run.summary.scoreMonotonicityHints, id: \.self) { hint in
                        Text("- \(hint)")
                            .appFont(.footnote, metrics: metrics)
                            .foregroundColor(run.summary.isScoreMonotonic ? .secondary : .orange)
                    }
                }
            }
        }
    }

    private var sampleTableSection: some View {
        GroupBox(t("E. 样本结果表", "E. Sample Result Table")) {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                HStack(spacing: metrics.rowSpacing) {
                    Toggle(t("仅 mismatch", "Only mismatch"), isOn: $onlyMismatch)
                        .toggleStyle(.checkbox)
                    Toggle(t("仅 failed", "Only failed"), isOn: $onlyFailed)
                        .toggleStyle(.checkbox)

                    Picker(t("分组", "Group"), selection: $groupFilter) {
                        ForEach(groupFilterOptions, id: \.self) { group in
                            Text(groupLabel(group)).tag(group)
                        }
                    }
                    .frame(width: 180)

                    Picker(t("判定", "Verdict"), selection: $verdictFilter) {
                        Text(t("全部", "All")).tag("all")
                        Text("clean").tag("clean")
                        Text("suspicious").tag("suspicious")
                        Text("malicious").tag("malicious")
                        Text("unknown").tag("unknown")
                    }
                    .frame(width: 140)

                    Picker(t("排序", "Sort"), selection: $scoreSortDescending) {
                        Text(t("分数降序", "Score desc")).tag(true)
                        Text(t("分数升序", "Score asc")).tag(false)
                    }
                    .frame(width: 140)

                    Spacer()
                }

                if filteredRows.isEmpty {
                    Text(t("暂无匹配结果。", "No matching rows."))
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                } else {
                    Table(filteredRows, selection: $selectedRowID) {
                        TableColumn("sample_id") { row in
                            Text(row.sampleID)
                                .appFont(.monospacedCaption, metrics: metrics)
                        }
                        TableColumn(t("分组", "Group")) { row in
                            Text(groupLabel(row.group))
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(t("类型", "Subtype")) { row in
                            Text(row.subtype)
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(t("分数", "Score")) { row in
                            Text(row.score.map(String.init) ?? "-")
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(t("判定", "Verdict")) { row in
                            Text(row.verdict ?? "unknown")
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(t("期望", "Expected")) { row in
                            Text(row.expectedVerdict ?? "-")
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(t("匹配", "Match")) { row in
                            Text(matchStatusText(row))
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(t("耗时", "Duration")) { row in
                            Text(row.analysisDurationMs.map { "\($0) ms" } ?? "-")
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(t("发现", "Findings")) { row in
                            Text(row.hasFindings ? t("有", "Yes") : t("无", "No"))
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(t("状态", "Status")) { row in
                            Text(statusText(row.status))
                                .appFont(.caption, metrics: metrics)
                        }
                    }
                    .frame(minHeight: 250)

                    HStack {
                        Button(t("查看样本详情", "View Sample Details")) {
                            guard let selectedRowID,
                                  let row = filteredRows.first(where: { $0.id == selectedRowID }) else {
                                return
                            }
                            selectedDetailRow = row
                        }
                        .disabled(selectedRowID == nil)
                        .buttonStyle(.bordered)

                        Spacer()
                    }
                }
            }
        }
    }

    private var diffViewSection: some View {
        GroupBox(t("F. 回归 Diff", "F. Diff View")) {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                if let diff = viewModel.benchmarkDiffSummary {
                    Text("\(t("上一次运行", "Previous run")): \(diff.previousRunID ?? t("无", "none"))")
                        .appFont(.monospacedCaption, metrics: metrics)

                    Text(t("新增误报样本", "New False Positives"))
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                    if diff.newlyRaisedFalsePositives.isEmpty {
                        Text("- \(t("无", "none"))")
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(diff.newlyRaisedFalsePositives.prefix(8), id: \.self) { sampleID in
                            Text("- \(sampleID)")
                                .appFont(.footnote, metrics: metrics)
                        }
                    }

                    Text(t("新增漏报样本", "New False Negatives"))
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                    if diff.newlyRaisedFalseNegatives.isEmpty {
                        Text("- \(t("无", "none"))")
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(diff.newlyRaisedFalseNegatives.prefix(8), id: \.self) { sampleID in
                            Text("- \(sampleID)")
                                .appFont(.footnote, metrics: metrics)
                        }
                    }

                    Text(t("分数变化最大样本", "Largest Score Changes"))
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                    let nonZeroScoreChanges = diff.topScoreChanges.filter { $0.delta != 0 }
                    if nonZeroScoreChanges.isEmpty {
                        Text("- \(t("无", "none"))")
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(nonZeroScoreChanges.prefix(8)) { change in
                            Text("- \(change.sampleID): \(change.previousScore) -> \(change.currentScore) (\(change.delta >= 0 ? "+\(change.delta)" : "\(change.delta)"))")
                                .appFont(.footnote, metrics: metrics)
                        }
                    }
                } else {
                    Text(t("暂无历史对比结果。请至少运行两次 benchmark。", "No regression diff yet. Run benchmark at least twice."))
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func benchmarkDetailSheet(_ row: BenchmarkResultTableRow) -> some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            Text(row.sampleID)
                .appFont(.headline, metrics: metrics)

            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                detailLine(t("分组", "Group"), row.group)
                detailLine(t("类型", "Subtype"), row.subtype)
                detailLine(t("路径", "Path"), row.relativePath)
                detailLine(t("实际结果", "Actual"), "\(row.verdict ?? "unknown") / \(row.score.map(String.init) ?? "-")")
                detailLine(t("期望结果", "Expected"), row.expectedVerdict ?? "-")
                detailLine(t("期望分数", "Expected Score"), row.expectedScoreRange.map { "[\($0.min), \($0.max)]" } ?? "-")
                detailLine(t("匹配状态", "Match"), matchStatusText(row))
                detailLine(t("不匹配原因", "Mismatch"), row.mismatchReason?.rawValue ?? "-")
                detailLine(t("分析耗时", "Duration"), row.analysisDurationMs.map { "\($0) ms" } ?? "-")
                detailLine(t("执行状态", "Status"), statusText(row.status))
            }

            Divider()
            Text(t("原始分析摘要", "Raw Analysis Summary"))
                .appFont(.caption, metrics: metrics)
                .foregroundStyle(.secondary)
            Text(row.analysisSummary ?? t("暂无摘要", "No summary"))
                .appFont(.footnote, metrics: metrics)
                .textSelection(.enabled)

            Divider()
            Text(t("风险发现", "Findings"))
                .appFont(.caption, metrics: metrics)
                .foregroundStyle(.secondary)
            if row.findings.isEmpty {
                Text("- \(t("无", "none"))")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(row.findings, id: \.self) { finding in
                            Text("- \(finding)")
                                .appFont(.footnote, metrics: metrics)
                                .textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 140)
            }

            if !row.notes.isEmpty {
                Divider()
                Text(t("备注", "Notes"))
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
                ForEach(row.notes, id: \.self) { note in
                    Text("- \(note)")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
            }

            HStack {
                Spacer()
                Button(t("关闭", "Close")) {
                    selectedDetailRow = nil
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(metrics.cardPadding)
        .frame(minWidth: 700, minHeight: 520)
    }

    private func groupRows() -> [GroupRow] {
        groupOrder.map { group in
            GroupRow(group: group, summary: viewModel.benchmarkGroupBreakdown[group])
        }
    }

    private func matchStatusText(_ row: BenchmarkResultTableRow) -> String {
        if row.status == .failed {
            return statusText(.failed)
        }
        guard let matched = row.matchedExpectation else {
            return "-"
        }
        return matched ? t("匹配", "match") : t("不匹配", "mismatch")
    }

    private func statusText(_ status: BenchmarkSampleExecutionStatus) -> String {
        switch status {
        case .pending:
            return t("待处理", "pending")
        case .completed:
            return t("完成", "completed")
        case .failed:
            return t("失败", "failed")
        }
    }

    private func groupLabel(_ value: String) -> String {
        switch value {
        case "all":
            return t("全部", "all")
        case "clean":
            return t("clean（干净）", "clean")
        case "noisy_benign":
            return t("noisy_benign（噪声良性）", "noisy_benign")
        case "suspicious":
            return t("suspicious（可疑）", "suspicious")
        case "replay_clean":
            return t("replay_clean（回放干净）", "replay_clean")
        case "replay_suspicious":
            return t("replay_suspicious（回放可疑）", "replay_suspicious")
        case "replay_malicious":
            return t("replay_malicious（回放恶意）", "replay_malicious")
        default:
            return value
        }
    }

    private func normalizeVerdict(_ value: String?) -> String {
        let normalized = value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? "unknown"
        switch normalized {
        case "clean", "benign", "benign_noisy": return "clean"
        case "suspicious": return "suspicious"
        case "malicious": return "malicious"
        default: return "unknown"
        }
    }

    private func rateText(_ value: Double?) -> String {
        guard let value else {
            return "-"
        }
        return String(format: "%.2f%%", value * 100)
    }

    private func detailLine(_ title: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text("\(title):")
                .appFont(.caption, metrics: metrics)
                .foregroundStyle(.secondary)
                .frame(width: 110, alignment: .leading)
            Text(value)
                .appFont(.footnote, metrics: metrics)
                .textSelection(.enabled)
            Spacer()
        }
    }

    private func labelTag(_ title: String) -> some View {
        Text(title)
            .appFont(.caption, metrics: metrics)
            .fontWeight(.semibold)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(Color.orange.opacity(0.16))
            .foregroundStyle(.orange)
            .clipShape(Capsule())
    }

    private func t(_ zh: String, _ en: String) -> String {
        settings.language == .zhHans ? zh : en
    }
}

private struct GroupRow: Identifiable {
    var group: String
    var summary: BenchmarkGroupSummary?

    var id: String { group }
}
