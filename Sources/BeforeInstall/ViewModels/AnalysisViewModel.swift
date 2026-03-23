import Foundation
import AppKit

@MainActor
final class AnalysisViewModel: ObservableObject {
    struct BatchAnalysisEntry: Identifiable {
        var id = UUID()
        var result: AnalysisResult
        var scanReport: ScanReport
    }

    enum Status {
        case idle
        case analyzing(String)
        case completed
        case failed(String)
    }

    struct DynamicSafetyPromptContext: Identifiable {
        let id = UUID()
        let fileURL: URL
        let mode: AnalysisMode
        let preflightNotice: String?
    }

    struct UserAlert: Identifiable {
        let id = UUID()
        let title: String
        let message: String
    }

    enum DynamicPreflightDecision {
        case proceed
        case block(title: String, message: String)
        case fallbackToStatic(message: String)
    }

    enum BenchmarkOperation {
        case scan
        case full
    }

    @Published var status: Status = .idle
    @Published var analysisResult: AnalysisResult?
    @Published var scanReport: ScanReport?
    @Published var errorMessage: String?
    @Published var activeAlert: UserAlert?

    @Published var analysisMode: AnalysisMode = .staticOnly {
        didSet {
            if analysisMode != .dynamicOnly {
                if manualDynamicInteraction {
                    DispatchQueue.main.async { [weak self] in
                        guard let self else { return }
                        self.manualDynamicInteraction = false
                    }
                }
            }
        }
    }
    @Published var analysisDepth: AnalysisDepth = .quick
    @Published var dynamicDurationSeconds: Int = 20
    @Published var manualDynamicInteraction = false

    @Published var sessionLogs: [String] = []
    @Published var isDynamicSessionRunning = false
    @Published var isAnalysisRunning = false

    @Published var historyRecords: [AnalysisHistoryRecord] = []
    @Published var latestMainBatchRun: MainBatchRunRecord?
    @Published var mainBatchRunHistory: [MainBatchRunRecord] = []
    @Published var mainBatchStatusMessage: String?
    @Published var latestBatchResultEntries: [BatchAnalysisEntry] = []
    @Published var dynamicSafetyPrompt: DynamicSafetyPromptContext?

    @Published var benchmarkStatusMessage: String?
    @Published var benchmarkLastReport: BenchmarkRun?
    @Published var benchmarkLastRunDirectoryPath: String?
    @Published var benchmarkRows: [BenchmarkResultTableRow] = []
    @Published var benchmarkStatistics: BenchmarkStatisticsSnapshot = .empty
    @Published var benchmarkGroupBreakdown: [String: BenchmarkGroupSummary] = [:]
    @Published var benchmarkDiffSummary: BenchmarkDiffSummary?
    @Published var benchmarkRunHistory: [BenchmarkRun] = []
    @Published var isBenchmarkRunning = false

    @Published var aiTrainingDatasetPath: String = ""
    @Published var aiTrainingOutputPath: String = ""
    @Published var aiTrainingStatusMessage: String?
    @Published var isAITrainingRunning = false

    private let coordinator: AnalyzerCoordinator
    private let historyStore: AnalysisHistoryStore
    private let mainBatchHistoryStore: MainBatchHistoryStore
    private let benchmarkService: BenchmarkService
    let settings: AppSettingsStore

    private var currentStopToken: DynamicStopToken?
    private var analysisTask: Task<Void, Never>?
    private var benchmarkTask: Task<Void, Never>?
    private var aiTrainingTask: Task<Void, Never>?

    init(
        coordinator: AnalyzerCoordinator = AnalyzerCoordinator(),
        settings: AppSettingsStore = AppSettingsStore(),
        historyStore: AnalysisHistoryStore = AnalysisHistoryStore(),
        mainBatchHistoryStore: MainBatchHistoryStore = MainBatchHistoryStore(),
        benchmarkService: BenchmarkService = BenchmarkService()
    ) {
        self.coordinator = coordinator
        self.settings = settings
        self.historyStore = historyStore
        self.mainBatchHistoryStore = mainBatchHistoryStore
        self.benchmarkService = benchmarkService
        dynamicDurationSeconds = settings.normalizedDuration(settings.defaultDurationSeconds)
        aiTrainingOutputPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Desktop", isDirectory: true).path
        historyRecords = historyStore.load()
        mainBatchRunHistory = mainBatchHistoryStore.load()
        latestMainBatchRun = mainBatchRunHistory.first
        if let benchmarkRoot = settings.resolveBenchmarkRootURL(),
           let latestBenchmark = benchmarkService.loadLatestRun(rootURL: benchmarkRoot) {
            applyBenchmarkRun(latestBenchmark)
        }
        refreshBenchmarkHistory()
    }

    func text(_ key: String) -> String {
        Localizer.text(key, language: settings.language)
    }

    func statusText() -> String {
        switch status {
        case .idle:
            return text("status.idle")
        case let .analyzing(fileName):
            return settings.language == .zhHans ? "正在分析：\(fileName)" : "Analyzing: \(fileName)"
        case .completed:
            return text("status.done")
        case let .failed(message):
            return settings.language == .zhHans ? "分析失败：\(message)" : "Failed: \(message)"
        }
    }

    var shouldShowManualInteractionOption: Bool {
        analysisMode == .dynamicOnly
    }

    var shouldDisableDynamicDurationControl: Bool {
        analysisMode == .dynamicOnly && manualDynamicInteraction
    }

    func openFileImporter() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.resolvesAliases = true
        panel.title = settings.language == .zhHans ? "选择要分析的文件（可多选）" : "Select files to analyze"
        panel.prompt = settings.language == .zhHans ? "选择" : "Select"

        panel.begin { [weak self] response in
            guard let self else { return }
            guard response == .OK else {
                return
            }
            let selectedURLs = panel.urls
            Task { @MainActor in
                DiagnosticsLogService.shared.log(.info, category: "ui.filePicker", "Selected \(selectedURLs.count) file(s) from open panel.")
                self.requestAnalyze(fileURLs: selectedURLs)
            }
        }
    }

    func openBenchmarkRootImporter() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.resolvesAliases = true
        panel.title = settings.language == .zhHans ? "选择 benchmark 根目录" : "Choose benchmark root directory"
        panel.prompt = settings.language == .zhHans ? "选择目录" : "Choose"

        if !settings.benchmarkRootPath.isEmpty {
            panel.directoryURL = URL(fileURLWithPath: settings.benchmarkRootPath)
        }

        panel.begin { [weak self] response in
            guard let self else { return }
            guard response == .OK, let selectedURL = panel.url else {
                return
            }
            Task { @MainActor in
                self.settings.updateBenchmarkRootURL(selectedURL)
                self.refreshBenchmarkContextAfterRootSelection()
            }
        }
    }

    func scanBenchmarkCatalog() {
        startBenchmarkOperation(.scan)
    }

    func runFullBenchmark() {
        startBenchmarkOperation(.full)
    }

    func cancelBenchmarkRun() {
        benchmarkTask?.cancel()
        benchmarkStatusMessage = settings.language == .zhHans ? "正在取消 benchmark 任务..." : "Cancelling benchmark task..."
    }

    func openAITrainingDatasetImporter() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.resolvesAliases = true
        panel.title = settings.language == .zhHans ? "选择训练样本目录" : "Choose training dataset directory"
        panel.prompt = settings.language == .zhHans ? "选择目录" : "Choose"

        panel.begin { [weak self] response in
            guard let self else { return }
            guard response == .OK, let selectedURL = panel.url else {
                return
            }
            Task { @MainActor in
                self.aiTrainingDatasetPath = selectedURL.standardizedFileURL.path
            }
        }
    }

    func openAITrainingOutputImporter() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.resolvesAliases = true
        panel.title = settings.language == .zhHans ? "选择训练输出目录" : "Choose training output directory"
        panel.prompt = settings.language == .zhHans ? "选择目录" : "Choose"

        if !aiTrainingOutputPath.isEmpty {
            panel.directoryURL = URL(fileURLWithPath: aiTrainingOutputPath)
        }

        panel.begin { [weak self] response in
            guard let self else { return }
            guard response == .OK, let selectedURL = panel.url else {
                return
            }
            Task { @MainActor in
                self.aiTrainingOutputPath = selectedURL.standardizedFileURL.path
            }
        }
    }

    func runAIModelTraining() {
        guard !isAITrainingRunning else {
            aiTrainingStatusMessage = settings.language == .zhHans ? "训练任务正在运行中。" : "A training task is already running."
            return
        }

        let datasetPath = aiTrainingDatasetPath.trimmingCharacters(in: .whitespacesAndNewlines)
        let outputPath = aiTrainingOutputPath.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !datasetPath.isEmpty else {
            aiTrainingStatusMessage = settings.language == .zhHans ? "请先选择训练样本目录。" : "Choose a training dataset directory first."
            return
        }
        guard !outputPath.isEmpty else {
            aiTrainingStatusMessage = settings.language == .zhHans ? "请先选择训练输出目录。" : "Choose a training output directory first."
            return
        }

        let datasetURL = URL(fileURLWithPath: datasetPath)
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: datasetURL.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            aiTrainingStatusMessage = settings.language == .zhHans
                ? "训练样本目录不存在或不可访问。"
                : "Training dataset directory does not exist or is inaccessible."
            return
        }

        let outputURL = URL(fileURLWithPath: outputPath)
        isAITrainingRunning = true
        aiTrainingStatusMessage = settings.language == .zhHans ? "正在训练随机森林模型..." : "Training Random-Forest model..."
        errorMessage = nil

        aiTrainingTask?.cancel()
        aiTrainingTask = Task { [weak self] in
            guard let self else { return }
            do {
                let result = try await runAITrainingInBackground(
                    datasetURL: datasetURL.standardizedFileURL,
                    outputURL: outputURL.standardizedFileURL
                )
                guard !Task.isCancelled else { return }
                self.isAITrainingRunning = false
                self.aiTrainingTask = nil

                let modelText = result.modelPath ?? (self.settings.language == .zhHans ? "未检测到模型文件" : "model file not found")
                self.aiTrainingStatusMessage = self.settings.language == .zhHans
                    ? "训练完成，模型：\(modelText)"
                    : "Training completed, model: \(modelText)"
                self.errorMessage = self.settings.language == .zhHans
                    ? "训练输出目录：\(result.outputDirectoryPath)"
                    : "Training output directory: \(result.outputDirectoryPath)"
            } catch is CancellationError {
                self.isAITrainingRunning = false
                self.aiTrainingTask = nil
                self.aiTrainingStatusMessage = self.settings.language == .zhHans ? "训练任务已取消。" : "Training task cancelled."
            } catch {
                self.isAITrainingRunning = false
                self.aiTrainingTask = nil
                self.aiTrainingStatusMessage = self.settings.language == .zhHans
                    ? "训练失败：\(error.localizedDescription)"
                    : "Training failed: \(error.localizedDescription)"
            }
        }
    }

    func exportBenchmarkResults() {
        guard let run = benchmarkLastReport else {
            errorMessage = settings.language == .zhHans ? "暂无可导出的 benchmark 结果。" : "No benchmark result to export."
            return
        }

        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.resolvesAliases = true
        panel.title = settings.language == .zhHans ? "选择 benchmark 导出目录" : "Choose benchmark export directory"
        panel.prompt = settings.language == .zhHans ? "导出" : "Export"

        panel.begin { [weak self] response in
            guard let self else { return }
            guard response == .OK, let directoryURL = panel.url else {
                return
            }
            Task { @MainActor in
                do {
                    let exportedDirectory = try benchmarkService.exportArtifacts(for: run, to: directoryURL)
                    errorMessage = settings.language == .zhHans
                        ? "Benchmark 已导出到：\(exportedDirectory.path)"
                        : "Benchmark exported to: \(exportedDirectory.path)"
                } catch {
                    errorMessage = settings.language == .zhHans
                        ? "导出失败：\(error.localizedDescription)"
                        : "Export failed: \(error.localizedDescription)"
                }
            }
        }
    }

    func exportBenchmarkArtifact(_ artifact: BenchmarkExportArtifact) {
        guard let run = benchmarkLastReport else {
            errorMessage = settings.language == .zhHans ? "暂无可导出的 benchmark 结果。" : "No benchmark result to export."
            return
        }

        guard let sourcePath = benchmarkService.exportArtifactPath(for: run, artifact: artifact) else {
            errorMessage = settings.language == .zhHans
                ? "当前运行暂无 \(artifact.filename) 可导出。"
                : "No \(artifact.filename) available for this run."
            return
        }

        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "\(run.runID)-\(artifact.filename)"
        panel.title = settings.language == .zhHans ? "导出 \(artifact.filename)" : "Export \(artifact.filename)"
        panel.prompt = settings.language == .zhHans ? "导出" : "Export"

        panel.begin { [weak self] response in
            guard let self else { return }
            guard response == .OK, let destinationURL = panel.url else {
                return
            }
            Task { @MainActor in
                do {
                    let sourceURL = URL(fileURLWithPath: sourcePath)
                    if FileManager.default.fileExists(atPath: destinationURL.path) {
                        try FileManager.default.removeItem(at: destinationURL)
                    }
                    try FileManager.default.copyItem(at: sourceURL, to: destinationURL)
                    errorMessage = settings.language == .zhHans
                        ? "已导出：\(destinationURL.path)"
                        : "Exported: \(destinationURL.path)"
                } catch {
                    errorMessage = settings.language == .zhHans
                        ? "导出失败：\(error.localizedDescription)"
                        : "Export failed: \(error.localizedDescription)"
                }
            }
        }
    }

    func refreshBenchmarkHistory() {
        guard let rootURL = resolvedBenchmarkRootURL() else {
            benchmarkRunHistory = []
            return
        }

        Task { [weak self] in
            guard let self else { return }
            let runs = await loadBenchmarkHistoryInBackground(rootURL: rootURL, limit: 12)
            guard !Task.isCancelled else { return }
            benchmarkRunHistory = runs
        }
    }

    func openBenchmarkHistoryRun(_ runID: String) {
        guard let run = benchmarkRunHistory.first(where: { $0.runID == runID }) else {
            return
        }
        applyBenchmarkRun(run)
        benchmarkStatusMessage = settings.language == .zhHans
            ? "已加载历史运行：\(runID)"
            : "Loaded benchmark history run: \(runID)"
    }

    private func startBenchmarkOperation(_ operation: BenchmarkOperation) {
        guard !isBenchmarkRunning else {
            errorMessage = settings.language == .zhHans ? "Benchmark 任务正在运行，请等待完成。" : "A benchmark run is in progress."
            return
        }

        guard let rootURL = resolvedBenchmarkRootURL() else {
            errorMessage = settings.language == .zhHans ? "请先选择 benchmark 根目录。" : "Choose a benchmark root first."
            return
        }

        benchmarkTask?.cancel()
        isBenchmarkRunning = true
        benchmarkStatusMessage = operation == .scan
            ? (settings.language == .zhHans ? "正在扫描 benchmark 样本..." : "Scanning benchmark samples...")
            : (settings.language == .zhHans ? "正在运行 benchmark 全量评测..." : "Running full benchmark...")
        errorMessage = nil
        if operation == .full {
            benchmarkStatistics = .empty
            benchmarkGroupBreakdown = [:]
            benchmarkDiffSummary = nil
        }

        benchmarkTask = Task { [weak self] in
            guard let self else { return }

            do {
                switch operation {
                case .scan:
                    let discovery = try await runBenchmarkDiscoveryInBackground(rootURL: rootURL)
                    guard !Task.isCancelled else { return }
                    applyBenchmarkDiscovery(discovery)
                    benchmarkStatusMessage = settings.language == .zhHans
                        ? "样本扫描完成：\(discovery.samples.count) 个样本。"
                        : "Scan completed: \(discovery.samples.count) samples."
                case .full:
                    let execution = try await runBenchmarkInBackground(rootURL: rootURL) { [weak self] progress in
                        Task { @MainActor [weak self] in
                            self?.applyBenchmarkProgress(progress)
                        }
                    }
                    guard !Task.isCancelled else { return }
                    applyBenchmarkRun(execution.run)
                    refreshBenchmarkHistory()
                    benchmarkStatusMessage = settings.language == .zhHans
                        ? "Benchmark 完成：共 \(execution.run.summary.totalSamples) 个样本，分析 \(execution.run.summary.analyzedSamples) 个，失败 \(execution.run.summary.failedSamples) 个。"
                        : "Benchmark finished: total \(execution.run.summary.totalSamples), analyzed \(execution.run.summary.analyzedSamples), failed \(execution.run.summary.failedSamples)."
                    errorMessage = settings.language == .zhHans
                        ? "Benchmark 输出目录：\(execution.exportBundle.outputDirectoryPath)"
                        : "Benchmark output directory: \(execution.exportBundle.outputDirectoryPath)"
                }
            } catch is CancellationError {
                benchmarkStatusMessage = settings.language == .zhHans ? "Benchmark 任务已取消。" : "Benchmark task cancelled."
            } catch {
                benchmarkStatusMessage = nil
                errorMessage = settings.language == .zhHans
                    ? "Benchmark 运行失败：\(error.localizedDescription)"
                    : "Benchmark failed: \(error.localizedDescription)"
            }

            isBenchmarkRunning = false
            benchmarkTask = nil
        }
    }

    func requestAnalyze(fileURL: URL) {
        guard !isAnalysisRunning else {
            errorMessage = text("status.busy")
            return
        }
        latestBatchResultEntries = []
        mainBatchStatusMessage = nil
        DiagnosticsLogService.shared.log(.info, category: "analysis", "Requested single analysis for: \(fileURL.lastPathComponent)")

        let dynamicDecision = dynamicPreflight(for: fileURL, mode: analysisMode)
        switch dynamicDecision {
        case let .block(title, message):
            activeAlert = UserAlert(title: title, message: message)
            errorMessage = message
            return
        case let .fallbackToStatic(message):
            analyze(fileURL: fileURL, forcedMode: .staticOnly, preflightNotice: message)
            return
        case .proceed:
            break
        }

        let needsDynamicPrompt = (analysisMode == .dynamicOnly || analysisMode == .combined) && settings.showDynamicSafetyPrompt
        if needsDynamicPrompt {
            dynamicSafetyPrompt = DynamicSafetyPromptContext(fileURL: fileURL, mode: analysisMode, preflightNotice: nil)
            return
        }

        analyze(fileURL: fileURL, forcedMode: analysisMode, preflightNotice: nil)
    }

    func requestAnalyze(fileURLs: [URL]) {
        let normalized = fileURLs
            .map { $0.standardizedFileURL }
            .uniquePreservingOrder()
        guard !normalized.isEmpty else { return }

        if normalized.count == 1, let single = normalized.first {
            requestAnalyze(fileURL: single)
            return
        }

        guard !isAnalysisRunning else {
            errorMessage = text("status.busy")
            return
        }

        DiagnosticsLogService.shared.log(.info, category: "analysis.batch", "Requested batch analysis for \(normalized.count) files.")
        analyzeMultiple(fileURLs: normalized)
    }

    func confirmDynamicPrompt(continueRun: Bool, doNotShowAgain: Bool) {
        guard let context = dynamicSafetyPrompt else { return }
        dynamicSafetyPrompt = nil

        if doNotShowAgain {
            settings.showDynamicSafetyPrompt = false
        }

        if continueRun {
            analyze(fileURL: context.fileURL, forcedMode: context.mode, preflightNotice: context.preflightNotice)
        }
    }

    func openMainBatchRun(_ runID: String) {
        guard let run = mainBatchRunHistory.first(where: { $0.runID == runID }) else { return }
        latestMainBatchRun = run
        mainBatchStatusMessage = settings.language == .zhHans
            ? "已加载批量运行：\(runID)"
            : "Loaded batch run: \(runID)"
    }

    func deleteMainBatchRun(_ run: MainBatchRunRecord) {
        mainBatchRunHistory = mainBatchHistoryStore.delete(id: run.id)
        if latestMainBatchRun?.id == run.id {
            latestMainBatchRun = mainBatchRunHistory.first
        }
    }

    func openMainBatchSample(_ sample: MainBatchSampleSummary) {
        if let history = historyRecords.first(where: { $0.filePath == sample.filePath }) {
            selectHistoryRecord(history)
            return
        }

        if FileManager.default.fileExists(atPath: sample.filePath) {
            requestAnalyze(fileURL: URL(fileURLWithPath: sample.filePath))
        }
    }

    func requestStopDynamicAnalysis() {
        currentStopToken?.requestStop()
    }

    func cleanupTemporaryEnvironments() {
        let removed = coordinator.cleanupDynamicWorkspaces()
        let message = settings.language == .zhHans
            ? "已清理 \(removed) 个临时分析目录"
            : "Removed \(removed) temporary analysis workspaces"
        errorMessage = message
    }

    func refreshLocalizedContent() {
        guard let analysisResult else { return }
        let localized = coordinator.refreshLocalizedPresentation(for: analysisResult, language: settings.language)
        self.analysisResult = localized
        if var currentReport = scanReport {
            currentReport.analysisResult = localized
            if let evaluation = localized.riskEvaluation {
                currentReport.riskScore = evaluation.totalScore
                currentReport.finalVerdict = evaluation.verdict
                currentReport.reasoningSummary = evaluation.reasoningSummary(language: settings.language)
                currentReport.topFindings = evaluation.topFindings
                currentReport.riskEvaluation = evaluation
            }
            scanReport = currentReport
        }
    }

    func selectHistoryRecord(_ record: AnalysisHistoryRecord) {
        let localized = coordinator.refreshLocalizedPresentation(for: record.result, language: settings.language)
        // Force a visible refresh even when selecting the same record repeatedly.
        analysisResult = nil
        analysisResult = localized
        scanReport = nil
        status = .completed
        errorMessage = nil
        sessionLogs = localized.dynamicReport?.sessionLogs ?? []
        isDynamicSessionRunning = false
        isAnalysisRunning = false
    }

    func deleteHistoryRecord(_ record: AnalysisHistoryRecord) {
        historyRecords = historyStore.delete(id: record.id)
    }

    func reanalyze(_ record: AnalysisHistoryRecord) {
        requestAnalyze(fileURL: URL(fileURLWithPath: record.filePath))
    }

    func exportCurrentReport(format: ReportExportFormat) {
        guard let analysisResult else { return }
        do {
            let url = try ReportExportService.export(result: analysisResult, language: settings.language, format: format)
            errorMessage = (settings.language == .zhHans ? "导出成功：" : "Exported: ") + url.path
        } catch {
            errorMessage = (settings.language == .zhHans ? "导出失败：" : "Export failed: ") + error.localizedDescription
        }
    }

    func exportDiagnostics(includeDebug: Bool = false) {
        do {
            let url = try DiagnosticsLogService.shared.export(includeDebug: includeDebug)
            errorMessage = (settings.language == .zhHans ? "日志已导出：" : "Diagnostics exported: ") + url.path
        } catch {
            errorMessage = (settings.language == .zhHans ? "日志导出失败：" : "Diagnostics export failed: ") + error.localizedDescription
        }
    }

    func copySummary() {
        guard let analysisResult else { return }
        ReportExportService.copySummary(analysisResult)
    }

    func copySHA256() {
        guard let analysisResult else { return }
        ReportExportService.copySHA256(analysisResult)
    }

    func copySignature() {
        guard let analysisResult else { return }
        ReportExportService.copySignature(analysisResult)
    }

    func copyTechnicalDetails() {
        guard let analysisResult else { return }
        ReportExportService.copyTechnicalDetails(analysisResult)
    }

    func copyTimeline() {
        guard let analysisResult else { return }
        ReportExportService.copyTimeline(analysisResult)
    }

    func copyNetworkSummary() {
        guard let analysisResult else { return }
        ReportExportService.copyNetworkSummary(analysisResult)
    }

    private func analyzeMultiple(fileURLs: [URL]) {
        currentStopToken?.requestStop()
        analysisTask?.cancel()

        let batchMode = analysisMode
        let normalizedDuration = settings.normalizedDuration(dynamicDurationSeconds)
        let shouldDisableManualInteraction = batchMode == .dynamicOnly && manualDynamicInteraction && fileURLs.count > 1

        status = .analyzing(settings.language == .zhHans ? "批量任务 (\(fileURLs.count))" : "Batch (\(fileURLs.count))")
        scanReport = nil
        sessionLogs = []
        isAnalysisRunning = true
        isDynamicSessionRunning = false
        errorMessage = nil
        latestBatchResultEntries = []
        mainBatchStatusMessage = settings.language == .zhHans
            ? "批量分析启动：共 \(fileURLs.count) 个样本。"
            : "Batch analysis started: \(fileURLs.count) samples."

        if shouldDisableManualInteraction {
            mainBatchStatusMessage = settings.language == .zhHans
                ? "批量动态分析不支持“手动交互”模式，已自动关闭并按定时模式执行。"
                : "Manual interaction is not supported for batch dynamic analysis. It was disabled and timed mode is used."
            DiagnosticsLogService.shared.log(.warning, category: "analysis.batch", "Manual dynamic interaction disabled for multi-file batch run.")
        }

        settings.normalizeDuration(normalizedDuration)

        let stopToken = DynamicStopToken()
        currentStopToken = stopToken

        analysisTask = Task { [weak self] in
            guard let self else { return }

            var summaries: [MainBatchSampleSummary] = []
            var completed = 0
            var failed = 0

            for (index, fileURL) in fileURLs.enumerated() {
                if Task.isCancelled {
                    break
                }

                mainBatchStatusMessage = settings.language == .zhHans
                    ? "批量分析中 \(index + 1)/\(fileURLs.count)：\(fileURL.lastPathComponent)"
                    : "Batch analyzing \(index + 1)/\(fileURLs.count): \(fileURL.lastPathComponent)"

                let sampleStart = Date()
                var modeForSample = batchMode

                let preflight = dynamicPreflight(for: fileURL, mode: batchMode)
                switch preflight {
                case let .block(title, message):
                    failed += 1
                    summaries.append(
                        MainBatchSampleSummary(
                            id: UUID(),
                            analyzedAt: Date(),
                            fileName: fileURL.lastPathComponent,
                            filePath: fileURL.path,
                            fileType: likelyFileType(for: fileURL),
                            mode: batchMode,
                            status: .blocked,
                            score: nil,
                            verdict: nil,
                            riskLevel: nil,
                            analysisDurationMs: Int(max(0, Date().timeIntervalSince(sampleStart) * 1000)),
                            errorMessage: "\(title): \(message)"
                        )
                    )
                    continue
                case .fallbackToStatic:
                    modeForSample = .staticOnly
                case .proceed:
                    break
                }

                let request = AnalysisRequest(
                    mode: modeForSample,
                    depth: analysisDepth,
                    dynamicDurationSeconds: normalizedDuration,
                    language: settings.language,
                    allowNonAppDynamicExecution: settings.allowNonAppDynamicExecution,
                    preferBackgroundAppLaunch: settings.preferBackgroundAppLaunch,
                    manualDynamicInteraction: false
                )

                isDynamicSessionRunning = request.mode == .dynamicOnly || request.mode == .combined
                let analysis = await runAnalysisInBackground(fileURL: fileURL, request: request, stopToken: stopToken)

                guard !Task.isCancelled, currentStopToken === stopToken else {
                    return
                }

                switch analysis {
                case let .success(report):
                    var localizedReport = report
                    let localizedResult = coordinator.refreshLocalizedPresentation(for: report.analysisResult, language: settings.language)
                    localizedReport.analysisResult = localizedResult
                    if let evaluation = localizedResult.riskEvaluation {
                        localizedReport.riskScore = evaluation.totalScore
                        localizedReport.finalVerdict = evaluation.verdict
                        localizedReport.reasoningSummary = evaluation.reasoningSummary(language: settings.language)
                        localizedReport.topFindings = evaluation.topFindings
                        localizedReport.riskEvaluation = evaluation
                    }

                    scanReport = localizedReport
                    analysisResult = localizedResult
                    sessionLogs = localizedResult.dynamicReport?.sessionLogs ?? []
                    historyRecords = historyStore.append(localizedResult)
                    latestBatchResultEntries.append(
                        BatchAnalysisEntry(
                            result: localizedResult,
                            scanReport: localizedReport
                        )
                    )
                    completed += 1
                    DiagnosticsLogService.shared.log(.info, category: "analysis.batch", "Batch sample completed: \(localizedResult.basicInfo.fileName)")

                    summaries.append(
                        MainBatchSampleSummary(
                            id: UUID(),
                            analyzedAt: localizedResult.analyzedAt,
                            fileName: localizedResult.basicInfo.fileName,
                            filePath: localizedResult.basicInfo.fullPath,
                            fileType: localizedResult.basicInfo.fileType,
                            mode: modeForSample,
                            status: .completed,
                            score: localizedResult.riskAssessment.score,
                            verdict: localizedResult.riskEvaluation?.verdict ?? localizedReport.finalVerdict,
                            riskLevel: localizedResult.riskAssessment.level,
                            analysisDurationMs: Int(max(0, Date().timeIntervalSince(sampleStart) * 1000)),
                            errorMessage: nil
                        )
                    )
                case let .failure(error):
                    failed += 1
                    DiagnosticsLogService.shared.log(.error, category: "analysis.batch", "Batch sample failed: \(fileURL.lastPathComponent) - \(error.localizedDescription)")
                    summaries.append(
                        MainBatchSampleSummary(
                            id: UUID(),
                            analyzedAt: Date(),
                            fileName: fileURL.lastPathComponent,
                            filePath: fileURL.path,
                            fileType: likelyFileType(for: fileURL),
                            mode: modeForSample,
                            status: .failed,
                            score: nil,
                            verdict: nil,
                            riskLevel: nil,
                            analysisDurationMs: Int(max(0, Date().timeIntervalSince(sampleStart) * 1000)),
                            errorMessage: error.localizedDescription
                        )
                    )
                }
            }

            let run = MainBatchRunRecord(
                id: UUID(),
                runID: makeMainBatchRunID(),
                createdAt: Date(),
                mode: batchMode,
                depth: analysisDepth,
                totalSamples: fileURLs.count,
                completedSamples: completed,
                failedSamples: failed,
                dynamicManualInteractionEnabled: false,
                sampleSummaries: summaries
            )

            mainBatchRunHistory = mainBatchHistoryStore.append(run)
            latestMainBatchRun = run

            if failed == fileURLs.count {
                status = .failed(settings.language == .zhHans ? "批量任务全部失败" : "Batch run failed for all samples")
            } else {
                status = .completed
            }

            mainBatchStatusMessage = settings.language == .zhHans
                ? "批量完成：总 \(fileURLs.count)，成功 \(completed)，失败 \(failed)。"
                : "Batch finished: total \(fileURLs.count), completed \(completed), failed \(failed)."
            DiagnosticsLogService.shared.log(.info, category: "analysis.batch", "Batch finished total=\(fileURLs.count), success=\(completed), failed=\(failed).")
            errorMessage = nil
            isDynamicSessionRunning = false
            isAnalysisRunning = false
            currentStopToken = nil
            analysisTask = nil

            _ = NSApp.requestUserAttention(.informationalRequest)
            if batchMode == .dynamicOnly || batchMode == .combined {
                NSApp.activate(ignoringOtherApps: true)
            }
        }
    }

    private func analyze(fileURL: URL, forcedMode: AnalysisMode? = nil, preflightNotice: String? = nil) {
        currentStopToken?.requestStop()
        analysisTask?.cancel()

        latestBatchResultEntries = []
        status = .analyzing(fileURL.lastPathComponent)
        errorMessage = preflightNotice
        sessionLogs = []
        isAnalysisRunning = true

        let mode = forcedMode ?? analysisMode
        let normalizedDuration = settings.normalizedDuration(dynamicDurationSeconds)
        let isManualInteraction = mode == .dynamicOnly && manualDynamicInteraction

        let stopToken = DynamicStopToken()
        currentStopToken = stopToken

        let request = AnalysisRequest(
            mode: mode,
            depth: analysisDepth,
            dynamicDurationSeconds: normalizedDuration,
            language: settings.language,
            allowNonAppDynamicExecution: settings.allowNonAppDynamicExecution,
            preferBackgroundAppLaunch: isManualInteraction ? false : settings.preferBackgroundAppLaunch,
            manualDynamicInteraction: isManualInteraction
        )

        isDynamicSessionRunning = request.mode == .dynamicOnly || request.mode == .combined
        settings.normalizeDuration(normalizedDuration)

        analysisTask = Task { [weak self] in
            guard let self else { return }

            let analysis = await runAnalysisInBackground(fileURL: fileURL, request: request, stopToken: stopToken)
            guard !Task.isCancelled, currentStopToken === stopToken else {
                return
            }

            DispatchQueue.main.async { [weak self] in
                guard let self, self.currentStopToken === stopToken else { return }

                switch analysis {
                case let .success(report):
                    var localizedReport = report
                    let localizedResult = self.coordinator.refreshLocalizedPresentation(for: report.analysisResult, language: self.settings.language)
                    localizedReport.analysisResult = localizedResult
                    if let evaluation = localizedResult.riskEvaluation {
                        localizedReport.riskScore = evaluation.totalScore
                        localizedReport.finalVerdict = evaluation.verdict
                        localizedReport.reasoningSummary = evaluation.reasoningSummary(language: self.settings.language)
                        localizedReport.topFindings = evaluation.topFindings
                        localizedReport.riskEvaluation = evaluation
                    }
                    self.scanReport = localizedReport
                    self.analysisResult = localizedResult
                    self.status = .completed
                    self.sessionLogs = localizedResult.dynamicReport?.sessionLogs ?? []
                    self.errorMessage = localizedResult.warnings.isEmpty ? nil : self.text("warning.partial")
                    self.historyRecords = self.historyStore.append(localizedResult)
                    DiagnosticsLogService.shared.log(.info, category: "analysis", "Analysis completed: \(localizedResult.basicInfo.fileName)")
                case let .failure(error):
                    self.scanReport = nil
                    self.analysisResult = nil
                    self.status = .failed(error.localizedDescription)
                    self.errorMessage = error.localizedDescription
                    DiagnosticsLogService.shared.log(.error, category: "analysis", "Analysis failed: \(error.localizedDescription)")
                }

                self.isDynamicSessionRunning = false
                self.isAnalysisRunning = false
                self.currentStopToken = nil
                self.analysisTask = nil
                _ = NSApp.requestUserAttention(.informationalRequest)

                if request.mode == .dynamicOnly || request.mode == .combined {
                    NSApp.activate(ignoringOtherApps: true)
                }
            }
        }
    }

    private func makeMainBatchRunID() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH-mm-ss'Z'"
        return "main-batch-\(formatter.string(from: Date()))"
    }

    private func runAnalysisInBackground(
        fileURL: URL,
        request: AnalysisRequest,
        stopToken: DynamicStopToken
    ) async -> Result<ScanReport, AnalysisCoordinatorError> {
        let coordinator = self.coordinator
        return await Task.detached(priority: .userInitiated) {
            await coordinator.analyze(
                fileURL: fileURL,
                request: request,
                stopToken: stopToken,
                progress: { _ in }
            )
        }.value
    }

    private func dynamicPreflight(for fileURL: URL, mode: AnalysisMode) -> DynamicPreflightDecision {
        guard mode == .dynamicOnly || mode == .combined else {
            return .proceed
        }

        let fileType = likelyFileType(for: fileURL)
        let scriptsBlocked = !settings.allowNonAppDynamicExecution

        if mode == .dynamicOnly {
            if scriptsBlocked && fileType.isScriptType {
                return .block(
                    title: settings.language == .zhHans ? "动态分析已拒绝此脚本类型" : "Dynamic analysis rejected this script type",
                    message: settings.language == .zhHans
                        ? "当前设置已启用“动态分析中拒绝脚本执行”。请到设置 > 高级取消该选项后再运行。"
                        : "The \"Reject script execution in dynamic analysis\" setting is enabled. Disable it in Settings > Advanced and retry."
                )
            }

            if !supportsDynamicExecution(for: fileType, allowScriptExecution: settings.allowNonAppDynamicExecution) {
                return .block(
                    title: settings.language == .zhHans ? "当前类型不支持动态执行" : "Unsupported type for dynamic execution",
                    message: settings.language == .zhHans
                        ? "该文件类型目前仅支持静态分析（例如 dmg/pkg/压缩包/plist/未知类型）。请切换到静态分析，或使用“静态+动态”让系统自动降级。"
                        : "This file type currently supports static analysis only (for example dmg/pkg/archive/plist/unknown). Switch to static mode, or use \"Static + Dynamic\" to auto-fallback."
                )
            }
        }

        if mode == .combined && !supportsDynamicExecution(for: fileType, allowScriptExecution: settings.allowNonAppDynamicExecution) {
            return .fallbackToStatic(
                message: settings.language == .zhHans
                    ? "该类型不支持动态执行，已自动降级为静态分析。"
                    : "Dynamic execution is not supported for this type. Automatically downgraded to static analysis."
            )
        }

        if mode == .combined && scriptsBlocked && fileType.isScriptType {
            return .fallbackToStatic(
                message: settings.language == .zhHans
                    ? "设置已拒绝脚本动态执行，本次“静态+动态”已自动降级为静态分析。"
                    : "Script execution is blocked by settings. This \"Static + Dynamic\" run was automatically downgraded to static analysis."
            )
        }

        return .proceed
    }

    private func likelyFileType(for fileURL: URL) -> SupportedFileType {
        let standardizedURL = fileURL.standardizedFileURL
        let detector = FileTypeDetector(commandRunner: ShellCommandService())
        return detector.detect(fileURL: standardizedURL).detectedType
    }

    private func supportsDynamicExecution(for type: SupportedFileType, allowScriptExecution: Bool) -> Bool {
        switch type {
        case .appBundle:
            return true
        case .shellScript, .pythonScript, .javaScript, .appleScript, .machO:
            return allowScriptExecution
        case .dmg, .pkg, .archive, .plist, .dylib, .unknown:
            return false
        }
    }

    private func refreshBenchmarkContextAfterRootSelection() {
        guard let rootURL = resolvedBenchmarkRootURL() else {
            benchmarkLastReport = nil
            benchmarkLastRunDirectoryPath = nil
            benchmarkRows = []
            benchmarkStatistics = .empty
            benchmarkGroupBreakdown = [:]
            benchmarkDiffSummary = nil
            benchmarkRunHistory = []
            return
        }

        if let latestBenchmark = benchmarkService.loadLatestRun(rootURL: rootURL) {
            applyBenchmarkRun(latestBenchmark)
        } else {
            benchmarkLastReport = nil
            benchmarkLastRunDirectoryPath = nil
            benchmarkRows = []
            benchmarkStatistics = .empty
            benchmarkGroupBreakdown = [:]
            benchmarkDiffSummary = nil
        }
        refreshBenchmarkHistory()
    }

    private func resolvedBenchmarkRootURL() -> URL? {
        settings.resolveBenchmarkRootURL()?.standardizedFileURL
    }

    private func applyBenchmarkProgress(_ progress: BenchmarkRunnerProgress) {
        if settings.language == .zhHans {
            let current = progress.currentPath ?? "-"
            benchmarkStatusMessage = "Benchmark 运行中：\(progress.completedSamples)/\(progress.totalSamples) (\(current))"
        } else {
            let current = progress.currentPath ?? "-"
            benchmarkStatusMessage = "Benchmark running: \(progress.completedSamples)/\(progress.totalSamples) (\(current))"
        }

        benchmarkStatistics = BenchmarkStatisticsSnapshot(
            totalSamples: progress.totalSamples,
            analyzedSamples: progress.completedSamples,
            failedSamples: benchmarkStatistics.failedSamples,
            effectiveCoverageRate: benchmarkStatistics.effectiveCoverageRate,
            cleanCount: benchmarkStatistics.cleanCount,
            suspiciousCount: benchmarkStatistics.suspiciousCount,
            maliciousCount: benchmarkStatistics.maliciousCount,
            unknownCount: benchmarkStatistics.unknownCount,
            averageScore: benchmarkStatistics.averageScore,
            medianScore: benchmarkStatistics.medianScore,
            verdictAccuracy: benchmarkStatistics.verdictAccuracy,
            scoreRangeMatchRate: benchmarkStatistics.scoreRangeMatchRate,
            falsePositiveCount: benchmarkStatistics.falsePositiveCount,
            falseNegativeCount: benchmarkStatistics.falseNegativeCount,
            cleanFalsePositiveRate: benchmarkStatistics.cleanFalsePositiveRate,
            noisyBenignFalsePositiveRate: benchmarkStatistics.noisyBenignFalsePositiveRate,
            suspiciousHitRate: benchmarkStatistics.suspiciousHitRate,
            replayMaliciousDetectionRate: benchmarkStatistics.replayMaliciousDetectionRate
        )
    }

    private func applyBenchmarkDiscovery(_ discovery: BenchmarkDiscoveryResult) {
        benchmarkRows = discovery.samples.map { sample in
            BenchmarkResultTableRow(
                sampleID: sample.sampleID,
                group: sample.group,
                subtype: sample.subtype,
                score: nil,
                verdict: nil,
                expectedVerdict: sample.expectation?.expectedVerdict,
                expectedScoreRange: sample.expectation?.expectedScoreRange,
                matchedExpectation: nil,
                matchedScoreRange: nil,
                mismatchReason: nil,
                status: .pending,
                relativePath: sample.relativePath,
                analysisDurationMs: nil,
                hasFindings: false,
                findings: [],
                findingDeltas: [],
                analysisSummary: nil,
                errorMessage: nil,
                errorCode: nil,
                notes: [
                    sample.sourceKind == .replayJSON
                        ? (settings.language == .zhHans ? "回放样本" : "replay sample")
                        : (settings.language == .zhHans ? "文件样本" : "file sample")
                ]
            )
        }
        benchmarkStatistics = BenchmarkStatisticsSnapshot(
            totalSamples: discovery.samples.count,
            analyzedSamples: 0,
            failedSamples: 0,
            effectiveCoverageRate: 0,
            cleanCount: 0,
            suspiciousCount: 0,
            maliciousCount: 0,
            unknownCount: discovery.samples.count,
            averageScore: 0,
            medianScore: 0,
            verdictAccuracy: nil,
            scoreRangeMatchRate: nil,
            falsePositiveCount: nil,
            falseNegativeCount: nil,
            cleanFalsePositiveRate: nil,
            noisyBenignFalsePositiveRate: nil,
            suspiciousHitRate: nil,
            replayMaliciousDetectionRate: nil
        )
        benchmarkGroupBreakdown = [:]
        benchmarkDiffSummary = nil

        if !discovery.warnings.isEmpty {
            benchmarkStatusMessage = discovery.warnings.joined(separator: " | ")
        }
    }

    private func applyBenchmarkRun(_ run: BenchmarkRun) {
        benchmarkLastReport = run
        benchmarkLastRunDirectoryPath = run.exportBundle?.outputDirectoryPath

        let resultMap = Dictionary(uniqueKeysWithValues: run.results.map { ($0.sampleID, $0) })
        benchmarkRows = run.samples.map { sample in
            guard let result = resultMap[sample.sampleID] else {
                return BenchmarkResultTableRow(
                    sampleID: sample.sampleID,
                    group: sample.group,
                    subtype: sample.subtype,
                    score: nil,
                    verdict: nil,
                    expectedVerdict: sample.expectation?.expectedVerdict,
                    expectedScoreRange: sample.expectation?.expectedScoreRange,
                    matchedExpectation: nil,
                    matchedScoreRange: nil,
                    mismatchReason: nil,
                    status: .pending,
                    relativePath: sample.relativePath,
                    analysisDurationMs: nil,
                    hasFindings: false,
                    findings: [],
                    findingDeltas: [],
                    analysisSummary: nil,
                    errorMessage: nil,
                    errorCode: nil,
                    notes: []
                )
            }

            let matchedExpectation: Bool?
            if let verdictMatched = result.matchedVerdict {
                if let scoreMatched = result.matchedScoreRange {
                    matchedExpectation = verdictMatched && scoreMatched
                } else {
                    matchedExpectation = verdictMatched
                }
            } else {
                matchedExpectation = result.matchedScoreRange
            }

            var notes: [String] = []
            if let mismatch = result.mismatchReason {
                notes.append(settings.language == .zhHans ? "不匹配：\(mismatch.rawValue)" : "mismatch: \(mismatch.rawValue)")
            }
            if let errorMessage = result.errorMessage, !errorMessage.isEmpty {
                notes.append(errorMessage)
            }
            if notes.isEmpty, result.status == .completed {
                notes.append(settings.language == .zhHans ? "分析完成" : "analysis completed")
            }

            return BenchmarkResultTableRow(
                sampleID: sample.sampleID,
                group: sample.group,
                subtype: result.subtype ?? sample.subtype,
                score: result.score,
                verdict: result.verdict,
                expectedVerdict: result.expectedVerdict,
                expectedScoreRange: result.expectedScoreRange,
                matchedExpectation: matchedExpectation,
                matchedScoreRange: result.matchedScoreRange,
                mismatchReason: result.mismatchReason,
                status: result.status,
                relativePath: sample.relativePath,
                analysisDurationMs: result.analysisDurationMs,
                hasFindings: !result.findings.isEmpty,
                findings: result.findings,
                findingDeltas: result.findingDeltas ?? [],
                analysisSummary: result.analysisSummary,
                errorMessage: result.errorMessage,
                errorCode: result.errorCode,
                notes: notes
            )
        }
        benchmarkStatistics = BenchmarkStatisticsSnapshot(
            totalSamples: run.summary.totalSamples,
            analyzedSamples: run.summary.analyzedSamples,
            failedSamples: run.summary.failedSamples,
            effectiveCoverageRate: run.summary.effectiveCoverageRate,
            cleanCount: run.summary.cleanCount,
            suspiciousCount: run.summary.suspiciousCount,
            maliciousCount: run.summary.maliciousCount,
            unknownCount: run.summary.unknownCount,
            averageScore: run.summary.averageScore,
            medianScore: run.summary.medianScore,
            verdictAccuracy: run.summary.verdictAccuracy,
            scoreRangeMatchRate: run.summary.scoreRangeMatchRate,
            falsePositiveCount: run.summary.falsePositiveCount,
            falseNegativeCount: run.summary.falseNegativeCount,
            cleanFalsePositiveRate: run.summary.cleanFalsePositiveRate,
            noisyBenignFalsePositiveRate: run.summary.noisyBenignFalsePositiveRate,
            suspiciousHitRate: run.summary.suspiciousHitRate,
            replayMaliciousDetectionRate: run.summary.replayMaliciousDetectionRate
        )
        benchmarkGroupBreakdown = run.summary.groupStats
        benchmarkDiffSummary = run.diffSummary
        benchmarkRunHistory.removeAll { $0.runID == run.runID }
        benchmarkRunHistory.insert(run, at: 0)
        if benchmarkRunHistory.count > 12 {
            benchmarkRunHistory = Array(benchmarkRunHistory.prefix(12))
        }
    }

    private func runBenchmarkDiscoveryInBackground(rootURL: URL) async throws -> BenchmarkDiscoveryResult {
        let root = rootURL
        return try await Task.detached(priority: .utility) {
            let hasScope = root.startAccessingSecurityScopedResource()
            defer {
                if hasScope {
                    root.stopAccessingSecurityScopedResource()
                }
            }
            return try BenchmarkService().discoverSamples(rootURL: root)
        }.value
    }

    private func runBenchmarkInBackground(
        rootURL: URL,
        progress: @escaping @Sendable (BenchmarkRunnerProgress) -> Void
    ) async throws -> BenchmarkRunExecution {
        let root = rootURL
        let language = settings.language
        return try await Task.detached(priority: .utility) {
            let hasScope = root.startAccessingSecurityScopedResource()
            defer {
                if hasScope {
                    root.stopAccessingSecurityScopedResource()
                }
            }
            return try await BenchmarkService().runBenchmark(rootURL: root, language: language, progress: progress)
        }.value
    }

    private func runAITrainingInBackground(
        datasetURL: URL,
        outputURL: URL
    ) async throws -> RandomForestTrainingResult {
        let dataset = datasetURL
        let output = outputURL
        return try await Task.detached(priority: .utility) {
            try RandomForestModelService.shared.train(datasetRoot: dataset, outputDirectory: output)
        }.value
    }

    private func loadBenchmarkHistoryInBackground(rootURL: URL, limit: Int) async -> [BenchmarkRun] {
        let root = rootURL
        return await Task.detached(priority: .utility) {
            let hasScope = root.startAccessingSecurityScopedResource()
            defer {
                if hasScope {
                    root.stopAccessingSecurityScopedResource()
                }
            }
            return BenchmarkService().loadRecentRuns(rootURL: root, limit: limit)
        }.value
    }
}
