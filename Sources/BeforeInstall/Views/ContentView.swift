import SwiftUI

struct ContentView: View {
    private enum UnifiedHistoryEntry: Identifiable {
        case single(AnalysisHistoryRecord)
        case batch(MainBatchRunRecord)

        var id: String {
            switch self {
            case let .single(record):
                return "single-\(record.id.uuidString)"
            case let .batch(run):
                return "batch-\(run.id.uuidString)"
            }
        }

        var createdAt: Date {
            switch self {
            case let .single(record):
                return record.createdAt
            case let .batch(run):
                return run.createdAt
            }
        }
    }

    private enum MainFeatureTab: String, CaseIterable, Identifiable {
        case fileAnalysis
        case launchApp
        case fullDiskScan
        case configProfiles

        var id: String { rawValue }

        func title(language: AppLanguage) -> String {
            switch (self, language) {
            case (.fileAnalysis, .zhHans):
                return "文件分析"
            case (.fileAnalysis, .en):
                return "File Analysis"
            case (.launchApp, .zhHans):
                return "启动 App"
            case (.launchApp, .en):
                return "Launch App"
            case (.fullDiskScan, .zhHans):
                return "全盘扫描"
            case (.fullDiskScan, .en):
                return "Full Disk Scan"
            case (.configProfiles, .zhHans):
                return "配置文件"
            case (.configProfiles, .en):
                return "Config Profiles"
            }
        }

        var icon: String {
            switch self {
            case .fileAnalysis:
                return "doc.text.magnifyingglass"
            case .launchApp:
                return "play.circle"
            case .fullDiskScan:
                return "scope"
            case .configProfiles:
                return "doc.text"
            }
        }
    }

    @ObservedObject var viewModel: AnalysisViewModel
    @ObservedObject var settings: AppSettingsStore
    @AppStorage("beforeinstall.permissionBannerDismissed") private var permissionBannerDismissed = false
    @State private var isHistoryExpanded = true
    @State private var isDiagnosticsPresented = false
    @State private var selectedFeatureTab: MainFeatureTab = .fileAnalysis
    @State private var launchTabInitialized = false
    @State private var fullDiskScanTabInitialized = false
    @State private var configTabInitialized = false
    @Environment(\.appFontScale) private var appFontScale
    @StateObject private var threatExplorerViewModel: ThreatExplorerViewModel

    init(viewModel: AnalysisViewModel, settings: AppSettingsStore) {
        self.viewModel = viewModel
        self.settings = settings
        _threatExplorerViewModel = StateObject(wrappedValue: ThreatExplorerViewModel(settings: settings))
    }

    var body: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: metrics.sectionSpacing) {
                mainFeatureTabs

                if shouldShowPermissionBanner {
                    permissionBanner
                }

                mainFeatureContent
            }
            .padding(metrics.cardPadding)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .appLiquidGlassScene(metrics: metrics)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onChange(of: settings.language) { _ in
            DispatchQueue.main.async {
                viewModel.refreshLocalizedContent()
            }
        }
        .onChange(of: selectedFeatureTab) { tab in
            if tab == .launchApp {
                launchTabInitialized = true
            } else if tab == .fullDiskScan {
                fullDiskScanTabInitialized = true
            } else if tab == .configProfiles {
                configTabInitialized = true
            }
        }
        .sheet(isPresented: $isDiagnosticsPresented) {
            DiagnosticsLogPanelView(settings: settings)
        }
        .sheet(item: $viewModel.dynamicSafetyPrompt) { _ in
            DynamicSafetyPromptView(
                language: settings.language,
                onConfirm: { dontShowAgain in
                    viewModel.confirmDynamicPrompt(continueRun: true, doNotShowAgain: dontShowAgain)
                },
                onCancel: { dontShowAgain in
                    viewModel.confirmDynamicPrompt(continueRun: false, doNotShowAgain: dontShowAgain)
                }
            )
        }
        .alert(item: $viewModel.activeAlert) { alert in
            Alert(
                title: Text(alert.title),
                message: Text(alert.message),
                dismissButton: .default(Text(settings.language == .zhHans ? "知道了" : "OK"))
            )
        }
    }

    private var appAnalysisPanel: some View {
        VStack(alignment: .leading, spacing: metrics.sectionSpacing) {
            controlPanel

            DropZoneView(
                hintText: viewModel.text("drop.hint"),
                supportText: viewModel.text("drop.support"),
                buttonText: viewModel.text("drop.pick"),
                onDropFiles: { urls in
                    viewModel.requestAnalyze(fileURLs: urls)
                },
                onSelectFiles: {
                    viewModel.openFileImporter()
                }
            )

            statusView
            mainBatchResultSection
            analysisHistorySection

            if !viewModel.latestBatchResultEntries.isEmpty {
                GroupBox(settings.language == .zhHans ? "多文件分析详情" : "Multi-file Analysis Details") {
                    VStack(alignment: .leading, spacing: metrics.sectionSpacing) {
                        ForEach(viewModel.latestBatchResultEntries) { entry in
                            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                                Text(entry.result.basicInfo.fileName)
                                    .appFont(.headline, metrics: metrics)
                                HStack(spacing: 6) {
                                    Text("\(entry.result.basicInfo.fileType.displayName(language: settings.language))  •  \(entry.scanReport.finalVerdict.rawValue)  •")
                                        .appFont(.caption, metrics: metrics)
                                        .foregroundStyle(.secondary)
                                    Text("score \(entry.scanReport.riskScore)")
                                        .appFont(.caption, metrics: metrics)
                                        .foregroundStyle(scoreColor(for: entry.scanReport.riskScore))
                                }
                                AnalysisResultView(
                                    result: entry.result,
                                    language: settings.language,
                                    sessionLogs: entry.result.dynamicReport?.sessionLogs ?? [],
                                    scanReport: entry.scanReport
                                )
                                Divider()
                            }
                        }
                    }
                    .padding(.top, metrics.compactPadding * 0.6)
                }
            } else if let result = viewModel.analysisResult {
                resultActionBar
                AnalysisResultView(
                    result: result,
                    language: settings.language,
                    sessionLogs: viewModel.sessionLogs,
                    scanReport: viewModel.scanReport
                )
            }
        }
    }

    private var mainFeatureTabs: some View {
        HStack(spacing: metrics.compactPadding) {
            Picker("", selection: $selectedFeatureTab) {
                ForEach(MainFeatureTab.allCases) { tab in
                    Label(tab.title(language: settings.language), systemImage: tab.icon)
                        .appFont(.body, metrics: metrics)
                        .tag(tab)
                }
            }
            .labelsHidden()
            .appLiquidPalettePickerStyle()
            .controlSize(.large)
            .fixedSize(horizontal: true, vertical: false)

            Spacer()

            Button {
                isDiagnosticsPresented = true
            } label: {
                Label(settings.language == .zhHans ? "日志" : "Logs", systemImage: "text.justify.left")
                    .appFont(.body, metrics: metrics)
            }
            .appSecondaryButtonStyle()
        }
    }

    private var mainFeatureContent: some View {
        ZStack(alignment: .topLeading) {
            appAnalysisPanel
                .opacity(selectedFeatureTab == .fileAnalysis ? 1 : 0)
                .allowsHitTesting(selectedFeatureTab == .fileAnalysis)

            if launchTabInitialized || selectedFeatureTab == .launchApp {
                AppLauncherView(settings: settings)
                    .opacity(selectedFeatureTab == .launchApp ? 1 : 0)
                    .allowsHitTesting(selectedFeatureTab == .launchApp)
            }

            if fullDiskScanTabInitialized || selectedFeatureTab == .fullDiskScan {
                FullDiskScanView(viewModel: threatExplorerViewModel, settings: settings)
                    .opacity(selectedFeatureTab == .fullDiskScan ? 1 : 0)
                    .allowsHitTesting(selectedFeatureTab == .fullDiskScan)
            }

            if configTabInitialized || selectedFeatureTab == .configProfiles {
                ConfigProfilesView(settings: settings)
                    .opacity(selectedFeatureTab == .configProfiles ? 1 : 0)
                    .allowsHitTesting(selectedFeatureTab == .configProfiles)
            }
        }
    }

    private var shouldShowPermissionBanner: Bool {
        !permissionBannerDismissed && PermissionGuidanceService.fullDiskAccessStatus() == .notGranted
    }

    private var permissionBanner: some View {
        GroupBox(viewModel.text("permissions.banner.title")) {
            VStack(alignment: .leading, spacing: 8) {
                Text(viewModel.text("permissions.banner.body"))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                AdaptiveStack(tier: metrics.layoutTier, spacing: metrics.rowSpacing) {
                    Button(viewModel.text("permissions.banner.fullDisk")) {
                        PermissionGuidanceService.openFullDiskAccess()
                    }
                    .appPrimaryButtonStyle()

                    Button(viewModel.text("permissions.banner.dismiss")) {
                        permissionBannerDismissed = true
                    }
                    .buttonStyle(.bordered)
                }
            }
            .padding(.top, metrics.compactPadding)
        }
    }

    private var controlPanel: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) {
                    Text(viewModel.text("controls.analysisMode"))
                        .appFont(.body, metrics: metrics)
                        .foregroundStyle(.secondary)
                    Picker("", selection: $viewModel.analysisMode) {
                        ForEach(AnalysisMode.allCases) { mode in
                            Text(mode.displayName(language: settings.language))
                                .appFont(.body, metrics: metrics)
                                .tag(mode)
                        }
                    }
                    .labelsHidden()
                    .appLiquidPalettePickerStyle()
                }

                modeSpecificControls

                Text(viewModel.text("controls.experimental"))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.orange)

                HStack(spacing: 10) {
                    Button(viewModel.text("controls.clean")) {
                        viewModel.cleanupTemporaryEnvironments()
                    }
                    .buttonStyle(.bordered)

                    if shouldShowEndInteractionButton {
                        Button(viewModel.text("controls.endInteraction")) {
                            viewModel.requestStopDynamicAnalysis()
                        }
                        .appPrimaryButtonStyle()
                    }

                    Spacer()
                }

                if shouldShowEndInteractionButton {
                    Text(dynamicGuideText)
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.top, metrics.compactPadding)
        }
    }

    @ViewBuilder
    private var modeSpecificControls: some View {
        switch viewModel.analysisMode {
        case .staticOnly:
            depthPickerRow
            Text(settings.language == .zhHans
                 ? "快速：优先提取核心结构与规则命中，适合日常快速筛查。深度：补充更多上下文关联与技术细节，耗时更长。"
                 : "Quick: focuses on core structure and rule hits for fast triage. Deep: adds broader context correlation and technical details with longer runtime.")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
        case .dynamicOnly:
            depthPickerRow
            dynamicDurationControl
            Toggle(
                settings.language == .zhHans ? "手动分析对象交互（更高情报）" : "Manual target interaction (higher telemetry)",
                isOn: $viewModel.manualDynamicInteraction
            )
            .appFont(.body, metrics: metrics)

            Text(settings.language == .zhHans
                 ? "勾选后将忽略“后台隐藏运行”偏好，并在你手动点击“结束交互”前持续收集动态情报。"
                 : "When enabled, background-hidden launch preference is ignored and telemetry continues until you click 'Finish Interaction'.")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
        case .combined:
            depthPickerRow
            dynamicDurationControl
            Text(settings.language == .zhHans
                 ? "组合模式会先执行静态分析，再执行动态分析。此模式下不提供手动交互流程。"
                 : "Combined mode runs static analysis first, then dynamic analysis. Manual interaction is not available in this mode.")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
        }
    }

    private var depthPickerRow: some View {
        HStack(spacing: 12) {
            Text(viewModel.text("controls.depth"))
                .appFont(.body, metrics: metrics)
                .foregroundStyle(.secondary)

            Picker("", selection: $viewModel.analysisDepth) {
                ForEach(AnalysisDepth.allCases) { depth in
                    Text(depth.displayName(language: settings.language))
                        .appFont(.body, metrics: metrics)
                        .tag(depth)
                }
            }
            .labelsHidden()
            .appLiquidPalettePickerStyle()
            .frame(maxWidth: 260)

            Spacer()
        }
    }

    private var dynamicDurationControl: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                Text(settings.language == .zhHans ? "动态分析时长" : "Dynamic Duration")
                    .appFont(.body, metrics: metrics)
                    .foregroundStyle(.secondary)

                Slider(
                    value: Binding(
                        get: { Double(viewModel.dynamicDurationSeconds) },
                        set: { viewModel.dynamicDurationSeconds = Int($0.rounded()) }
                    ),
                    in: 5...120,
                    step: 1
                )
                .disabled(viewModel.shouldDisableDynamicDurationControl)

                Text("\(viewModel.dynamicDurationSeconds)s")
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
                    .frame(minWidth: 52, alignment: .trailing)
            }

            Text(settings.language == .zhHans
                 ? "可调范围 5s-120s。快速模式更轻量，深度模式会执行更密集采样与链路关联。"
                 : "Range: 5s-120s. Quick mode is lighter; deep mode performs denser sampling and chain correlation.")
                .appFont(.caption, metrics: metrics)
                .foregroundStyle(.secondary)
        }
    }

    private var shouldShowEndInteractionButton: Bool {
        viewModel.isDynamicSessionRunning && (viewModel.manualDynamicInteraction || viewModel.analysisDepth == .deep)
    }

    private var dynamicGuideText: String {
        if viewModel.manualDynamicInteraction {
            return settings.language == .zhHans
                ? "手动交互模式进行中：请在目标窗口完成操作，完成后点击“结束交互并完成动态分析”。"
                : "Manual interaction is active. Operate the target window, then click 'Finish Interaction and Stop Dynamic Analysis'."
        }
        return viewModel.text("controls.deepGuide")
    }

    private var mainBatchResultSection: some View {
        GroupBox(settings.language == .zhHans ? "多文件批量结果" : "Multi-file Batch Results") {
            if let run = viewModel.latestMainBatchRun {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    Text(settings.language == .zhHans
                         ? "运行 \(run.runID) · 总 \(run.totalSamples) · 成功 \(run.completedSamples) · 失败 \(run.failedSamples)"
                         : "Run \(run.runID) · total \(run.totalSamples) · success \(run.completedSamples) · failed \(run.failedSamples)")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)

                    if let status = viewModel.mainBatchStatusMessage, !status.isEmpty {
                        Text(status)
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                    }

                    Table(run.sampleSummaries.prefix(40)) {
                        TableColumn(settings.language == .zhHans ? "文件" : "File") { item in
                            Text(item.fileName)
                                .appFont(.caption, metrics: metrics)
                                .lineLimit(1)
                        }
                        TableColumn(settings.language == .zhHans ? "类型" : "Type") { item in
                            Text(item.fileType.displayName(language: settings.language))
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(settings.language == .zhHans ? "分数" : "Score") { item in
                            if let score = item.score {
                                Text(String(score))
                                    .appFont(.caption, metrics: metrics)
                                    .foregroundStyle(scoreColor(for: score))
                            } else {
                                Text("-")
                                    .appFont(.caption, metrics: metrics)
                            }
                        }
                        TableColumn(settings.language == .zhHans ? "判定" : "Verdict") { item in
                            Text(item.verdict?.rawValue ?? item.status.rawValue)
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(settings.language == .zhHans ? "操作" : "Action") { item in
                            Button(settings.language == .zhHans ? "查看" : "Open") {
                                viewModel.openMainBatchSample(item)
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                    .frame(minHeight: 180, maxHeight: 260)
                }
            } else {
                Text(settings.language == .zhHans
                     ? "拖入多个文件，或在“选择文件”时多选，即可批量分析。"
                     : "Drop multiple files, or multi-select in file picker, to run batch analysis.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var resultActionBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: metrics.compactPadding) {
                Menu {
                    Button("Markdown") { viewModel.exportCurrentReport(format: .markdown) }
                    Button("JSON") { viewModel.exportCurrentReport(format: .json) }
                    Button(viewModel.text("actions.exportText")) { viewModel.exportCurrentReport(format: .text) }
                } label: {
                    Text(viewModel.text("actions.export"))
                        .appFont(.body, metrics: metrics)
                }
                .menuStyle(.borderlessButton)

                Button {
                    viewModel.copySummary()
                } label: {
                    Text(viewModel.text("actions.copySummary"))
                        .appFont(.body, metrics: metrics)
                }
                .buttonStyle(.bordered)

                Button {
                    viewModel.copySHA256()
                } label: {
                    Text(viewModel.text("actions.copySHA"))
                        .appFont(.body, metrics: metrics)
                }
                .buttonStyle(.bordered)

                Button {
                    viewModel.copySignature()
                } label: {
                    Text(viewModel.text("actions.copySignature"))
                        .appFont(.body, metrics: metrics)
                }
                .buttonStyle(.bordered)

                Button {
                    viewModel.copyTechnicalDetails()
                } label: {
                    Text(viewModel.text("actions.copyDetails"))
                        .appFont(.body, metrics: metrics)
                }
                .buttonStyle(.bordered)

                if viewModel.analysisResult?.analysisMode != .staticOnly {
                    Button {
                        viewModel.copyTimeline()
                    } label: {
                        Text(viewModel.text("actions.copyTimeline"))
                            .appFont(.body, metrics: metrics)
                    }
                    .buttonStyle(.bordered)

                    Button {
                        viewModel.copyNetworkSummary()
                    } label: {
                        Text(viewModel.text("actions.copyNetwork"))
                            .appFont(.body, metrics: metrics)
                    }
                    .buttonStyle(.bordered)
                }

                Menu {
                    Button(settings.language == .zhHans ? "普通日志" : "Standard") {
                        viewModel.exportDiagnostics(includeDebug: false)
                    }
                    Button(settings.language == .zhHans ? "详细日志（含 debug）" : "Verbose (with debug)") {
                        viewModel.exportDiagnostics(includeDebug: true)
                    }
                } label: {
                    Text(viewModel.text("actions.exportDiagnostics"))
                        .appFont(.body, metrics: metrics)
                }
                .menuStyle(.borderlessButton)

                Spacer(minLength: metrics.compactPadding)
            }
            .padding(.vertical, 2)
        }
    }

    private var analysisHistorySection: some View {
        GroupBox(viewModel.text("history.title")) {
            DisclosureGroup(
                isExpanded: $isHistoryExpanded,
                content: {
                    if viewModel.historyRecords.isEmpty && viewModel.mainBatchRunHistory.isEmpty {
                        Text(viewModel.text("history.empty"))
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                            .padding(.top, 4)
                            .padding(.leading, metrics.compactPadding * 0.8)
                    } else {
                        VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                            ForEach(Array(unifiedHistoryEntries.prefix(20))) { entry in
                                switch entry {
                                case let .batch(run):
                                    batchHistoryRow(run)
                                case let .single(record):
                                    singleHistoryRow(record)
                                }
                                Divider()
                            }
                        }
                        .padding(.top, 4)
                        .padding(.leading, metrics.compactPadding * 0.8)
                    }
                },
                label: {
                    Text(isHistoryExpanded
                         ? (settings.language == .zhHans ? "收起" : "Collapse")
                         : (settings.language == .zhHans ? "展开" : "Expand"))
                        .appFont(.caption, metrics: metrics)
                }
            )
        }
    }

    @ViewBuilder
    private var statusView: some View {
        HStack(spacing: 10) {
            if isBusyStatus {
                ProgressView()
                    .controlSize(.small)
            }

            Text(viewModel.statusText())
                .appFont(.body, metrics: metrics)
                .foregroundStyle(statusColor)

            Spacer()
        }

        if let errorMessage = viewModel.errorMessage {
            Text(errorMessage)
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.orange)
                .padding(.top, 2)
        }
    }

    private var isBusyStatus: Bool {
        if case .analyzing = viewModel.status {
            return true
        }
        return viewModel.isDynamicSessionRunning || viewModel.isBenchmarkRunning
    }

    private var statusColor: Color {
        switch viewModel.status {
        case .idle, .completed:
            return .secondary
        case .analyzing:
            return .blue
        case .failed:
            return .red
        }
    }

    private func scoreColor(for score: Int) -> Color {
        if score >= 70 {
            return .red
        }
        if score >= 40 {
            return .orange
        }
        return .green
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    private var unifiedHistoryEntries: [UnifiedHistoryEntry] {
        let singleEntries = viewModel.historyRecords.map { UnifiedHistoryEntry.single($0) }
        let batchEntries = viewModel.mainBatchRunHistory.map { UnifiedHistoryEntry.batch($0) }
        return (singleEntries + batchEntries).sorted { lhs, rhs in
            lhs.createdAt > rhs.createdAt
        }
    }

    private func batchHistoryRow(_ run: MainBatchRunRecord) -> some View {
        HStack(alignment: .top, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text("[\(settings.language == .zhHans ? "多项" : "Batch")] \(run.runID)")
                    .appFont(.monospacedCaption, metrics: metrics)
                Text(settings.language == .zhHans
                     ? "\(formatDate(run.createdAt))  •  总 \(run.totalSamples) • 成功 \(run.completedSamples) • 失败 \(run.failedSamples) • \(run.mode.displayName(language: settings.language))"
                     : "\(formatDate(run.createdAt))  •  total \(run.totalSamples) • success \(run.completedSamples) • failed \(run.failedSamples) • \(run.mode.displayName(language: settings.language))")
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button(viewModel.text("history.open")) {
                viewModel.openMainBatchRun(run.runID)
            }
            .buttonStyle(.borderless)

            Button(role: .destructive) {
                viewModel.deleteMainBatchRun(run)
            } label: {
                Text(viewModel.text("history.delete"))
            }
            .buttonStyle(.borderless)
        }
    }

    private func singleHistoryRow(_ record: AnalysisHistoryRecord) -> some View {
        HStack(alignment: .top, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text("[\(settings.language == .zhHans ? "单项" : "Single")] \(record.fileName)")
                    .appFont(.body, metrics: metrics)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text("\(formatDate(record.createdAt))  •  \(record.fileType.displayName(language: settings.language))  •  \(record.mode.displayName(language: settings.language))")
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
                Text(settings.language == .zhHans ? "风险：\(record.riskLevel.displayName(language: settings.language))" : "Risk: \(record.riskLevel.displayName(language: settings.language))")
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button(viewModel.text("history.open")) {
                viewModel.selectHistoryRecord(record)
            }
            .buttonStyle(.borderless)

            Button(viewModel.text("history.rerun")) {
                viewModel.reanalyze(record)
            }
            .buttonStyle(.borderless)

            Button(role: .destructive) {
                viewModel.deleteHistoryRecord(record)
            } label: {
                Text(viewModel.text("history.delete"))
            }
            .buttonStyle(.borderless)
        }
        .contentShape(Rectangle())
        .onTapGesture {
            viewModel.selectHistoryRecord(record)
        }
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: appFontScale)
    }
}

private struct DynamicSafetyPromptView: View {
    let language: AppLanguage
    let onConfirm: (Bool) -> Void
    let onCancel: (Bool) -> Void

    @State private var dontShowAgain = false
    @Environment(\.appFontScale) private var appFontScale

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            Text(language == .zhHans ? "动态分析安全提示" : "Dynamic Analysis Safety Notice")
                .appFont(.headline, metrics: metrics)

            Text(language == .zhHans ? "当前动态分析属于受限观察，不是完整恶意软件沙箱。" : "Dynamic analysis is restricted observation mode, not a full malware sandbox.")
                .appFont(.body, metrics: metrics)
            Text(language == .zhHans ? "运行未知程序仍可能带来风险；非 .app 目标执行风险更高。" : "Running unknown targets can still be risky; non-.app execution is higher risk.")
                .appFont(.body, metrics: metrics)
            Text(language == .zhHans ? "建议优先静态分析，必要时再做动态分析。" : "Run static analysis first, then dynamic analysis when needed.")
                .appFont(.body, metrics: metrics)

            Toggle(
                language == .zhHans ? "本次后不再提示" : "Don't show this warning again",
                isOn: $dontShowAgain
            )
            .appFont(.body, metrics: metrics)

            HStack {
                Spacer()
                Button(language == .zhHans ? "取消" : "Cancel") {
                    onCancel(dontShowAgain)
                }
                .keyboardShortcut(.cancelAction)

                Button(language == .zhHans ? "继续" : "Continue") {
                    onConfirm(dontShowAgain)
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(metrics.cardPadding)
        .frame(minWidth: 520, idealWidth: 560)
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: appFontScale)
    }
}

#Preview {
    ContentView(
        viewModel: AnalysisViewModel(),
        settings: AppSettingsStore()
    )
}
