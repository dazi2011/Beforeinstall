import Foundation
import AppKit

final class ScanCancellationSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    func reset() {
        lock.lock()
        cancelled = false
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

struct ThreatExplorerAlert: Identifiable {
    var id = UUID()
    var title: String
    var message: String
}

struct ThreatRemediationConfirmation: Identifiable {
    var id = UUID()
    var actionType: RemediationActionType
    var threatIDs: [String]
    var title: String
    var message: String
    var irreversibleCount: Int
}

@MainActor
final class ThreatExplorerViewModel: ObservableObject {
    @Published var selectedScanMode: FullDiskScanMode = .quick
    @Published var includeExternalVolumes = false
    @Published var customFocusPathsInput = ""
    @Published var persistCustomFocusPaths = false

    @Published var isScanning = false
    @Published var isStoppingScan = false
    @Published var scanProgressMessage = ""
    @Published var scanProgressStage = "idle"
    @Published var scanProgressProcessed = 0
    @Published var scanProgressTotal = 0
    @Published var scanCurrentPath: String?
    @Published var scanDiscoveredCount = 0
    @Published var scanSelectedCount = 0
    @Published var scanAnalyzedCount = 0
    @Published var scanThreatCount = 0

    @Published var currentSession: ScanSession?
    @Published var scanHistory: [ScanSession] = []
    @Published var remediationLogs: [RemediationLogEntry] = []
    @Published var quarantineRecords: [QuarantineRecord] = []
    @Published var ignoredItems: [IgnoreRuleRecord] = []

    @Published var filterState = ThreatFilterState()
    @Published var sortMode: ThreatSortMode = .riskDescending
    @Published var selectedThreatIDs: Set<String> = []
    @Published var selectedThreatID: String?

    @Published var remediationConfirmation: ThreatRemediationConfirmation?
    @Published var activeAlert: ThreatExplorerAlert?
    @Published var lastOperationMessage: String?

    private let settings: AppSettingsStore
    private let orchestrator: FullDiskScanOrchestrator
    private let remediationEngine: RemediationEngine
    private let quarantineManager: QuarantineManager
    private let ignoreStore: IgnoreListStore
    private let scanHistoryStore: ScanHistoryStore
    private let remediationHistoryStore: RemediationHistoryStore
    private let aggregator: ThreatAggregator

    private var scanItemsByID: [String: ScanItem] = [:]
    private var scanTask: Task<Void, Never>?
    private var scanCancellationSignal = ScanCancellationSignal()
    private var liveSessionID: String?
    private var activeScanRunID = UUID()

    private let defaults = UserDefaults.standard

    private enum DefaultsKeys {
        static let fullScanMode = "beforeinstall.fullscan.mode"
        static let includeExternalVolumes = "beforeinstall.fullscan.includeExternalVolumes"
        static let persistCustomPaths = "beforeinstall.fullscan.persistCustomPaths"
        static let customPathsText = "beforeinstall.fullscan.customPathsText"
    }

    init(
        settings: AppSettingsStore,
        orchestrator: FullDiskScanOrchestrator = FullDiskScanOrchestrator(),
        remediationEngine: RemediationEngine = RemediationEngine(),
        quarantineManager: QuarantineManager = QuarantineManager(),
        ignoreStore: IgnoreListStore = IgnoreListStore(),
        scanHistoryStore: ScanHistoryStore = ScanHistoryStore(),
        remediationHistoryStore: RemediationHistoryStore = RemediationHistoryStore(),
        aggregator: ThreatAggregator = ThreatAggregator()
    ) {
        self.settings = settings
        self.orchestrator = orchestrator
        self.remediationEngine = remediationEngine
        self.quarantineManager = quarantineManager
        self.ignoreStore = ignoreStore
        self.scanHistoryStore = scanHistoryStore
        self.remediationHistoryStore = remediationHistoryStore
        self.aggregator = aggregator

        if let rawMode = defaults.string(forKey: DefaultsKeys.fullScanMode),
           let mode = FullDiskScanMode(rawValue: rawMode)
        {
            selectedScanMode = mode
        }
        includeExternalVolumes = defaults.bool(forKey: DefaultsKeys.includeExternalVolumes)
        persistCustomFocusPaths = defaults.bool(forKey: DefaultsKeys.persistCustomPaths)
        customFocusPathsInput = defaults.string(forKey: DefaultsKeys.customPathsText) ?? ""

        reloadStores()
    }

    func reloadStores() {
        scanHistory = scanHistoryStore.load()
        remediationLogs = remediationHistoryStore.load()
        quarantineRecords = quarantineManager.loadRecords()
        ignoredItems = ignoreStore.load()

        if currentSession == nil {
            currentSession = scanHistory.first
        }
        if selectedThreatID == nil {
            selectedThreatID = currentSession?.threats.first?.threatID
        }
    }

    func startScan(mode: FullDiskScanMode? = nil) {
        guard !isScanning else {
            activeAlert = ThreatExplorerAlert(
                title: localized("扫描进行中", "Scan In Progress"),
                message: localized("已有扫描任务在运行，请等待完成。", "A scan task is already running.")
            )
            return
        }

        let activeMode = mode ?? selectedScanMode
        selectedScanMode = activeMode
        persistPreferences()
        let runID = UUID()
        activeScanRunID = runID

        let customPaths = parsedCustomFocusPaths()
        if persistCustomFocusPaths {
            defaults.set(customPaths.joined(separator: "\n"), forKey: DefaultsKeys.customPathsText)
            ConfigProfileService.shared.upsertPathPrefixRules(paths: customPaths, action: .notice)
        }

        isScanning = true
        isStoppingScan = false
        scanProgressStage = "starting"
        scanProgressMessage = localized("正在准备扫描计划...", "Preparing scan plan...")
        scanProgressProcessed = 0
        scanProgressTotal = 0
        scanCurrentPath = nil
        scanDiscoveredCount = 0
        scanSelectedCount = 0
        scanAnalyzedCount = 0
        scanThreatCount = 0
        lastOperationMessage = nil
        selectedThreatIDs.removeAll()
        liveSessionID = nil
        currentSession = nil

        scanCancellationSignal.cancel()
        scanTask?.cancel()
        scanCancellationSignal = ScanCancellationSignal()
        scanTask = Task { [weak self] in
            guard let self else { return }
            let language = settings.language
            let result = await orchestrator.run(
                mode: activeMode,
                customFocusPaths: customPaths,
                includeExternalVolumes: includeExternalVolumes,
                maxConcurrentAnalyses: settings.fullDiskScanMaxConcurrency,
                language: language,
                progress: { event in
                    Task { @MainActor [weak self] in
                        guard let self, self.activeScanRunID == runID else { return }
                        self.applyProgress(event)
                    }
                },
                shouldCancel: { [signal = scanCancellationSignal] in
                    signal.isCancelled
                }
            )
            await MainActor.run { [weak self] in
                guard let self, self.activeScanRunID == runID else { return }
                self.applyScanResult(result)
            }
        }
    }

    func cancelScan() {
        guard isScanning else { return }
        activeScanRunID = UUID()
        scanCancellationSignal.cancel()
        scanTask?.cancel()
        scanTask = nil
        isScanning = false
        isStoppingScan = false
        scanProgressStage = "cancelled"
        scanProgressMessage = localized("扫描已取消。", "Scan cancelled.")
        scanCurrentPath = nil
        liveSessionID = nil
        lastOperationMessage = scanProgressMessage
        scanHistory = scanHistoryStore.load()
    }

    func openHistorySession(_ session: ScanSession) {
        currentSession = session
        scanItemsByID = [:]
        selectedThreatIDs.removeAll()
        selectedThreatID = session.threats.first?.threatID
    }

    func exportCurrentSession(format: ThreatExportFormat) {
        guard let session = currentSession else {
            activeAlert = ThreatExplorerAlert(
                title: localized("无可导出数据", "Nothing to Export"),
                message: localized("请先运行一次全盘扫描。", "Run a full-disk scan first.")
            )
            return
        }
        do {
            let logs = remediationLogs.filter { $0.sessionID == session.sessionID }
            let url = try ThreatExportService.export(session: session, remediationLogs: logs, format: format)
            lastOperationMessage = localized("报告已导出：", "Exported: ") + url.path
        } catch {
            activeAlert = ThreatExplorerAlert(
                title: localized("导出失败", "Export Failed"),
                message: error.localizedDescription
            )
        }
    }

    func requestSingleAction(_ actionType: RemediationActionType, threatID: String) {
        requestAction(actionType, threatIDs: [threatID])
    }

    func requestBulkAction(_ actionType: RemediationActionType) {
        let targets = selectedThreatIDs.isEmpty ? filteredThreats.map(\.threatID) : Array(selectedThreatIDs)
        requestAction(actionType, threatIDs: targets)
    }

    func executeConfirmedAction() {
        guard let confirmation = remediationConfirmation else { return }
        remediationConfirmation = nil

        guard var session = currentSession else { return }

        var successCount = 0
        var failedCount = 0

        for threatID in confirmation.threatIDs {
            guard let index = session.threats.firstIndex(where: { $0.threatID == threatID }) else { continue }
            let threat = session.threats[index]
            let hash = scanItemsByID[threat.itemID]?.hash
            let execution = remediationEngine.execute(
                sessionID: session.sessionID,
                actionType: confirmation.actionType,
                threat: threat,
                hash: hash,
                userConfirmed: true
            )
            session.threats[index] = execution.updatedThreat
            if execution.action.status == .succeeded {
                successCount += 1
            } else {
                failedCount += 1
            }
        }

        session.summary = aggregator.buildSummary(threats: session.threats)
        session.completedAt = session.completedAt ?? Date()

        currentSession = session
        _ = scanHistoryStore.update(session)
        reloadStores()
        selectedThreatIDs.subtract(confirmation.threatIDs)

        lastOperationMessage = localized(
            "批量处置完成：成功 \(successCount) 项，失败 \(failedCount) 项。",
            "Remediation done: \(successCount) succeeded, \(failedCount) failed."
        )
    }

    func restoreFromQuarantine(_ record: QuarantineRecord) {
        let sessionID = currentSession?.sessionID ?? "manual-remediation"
        let result = remediationEngine.restoreFromQuarantine(sessionID: sessionID, quarantineID: record.quarantineID)

        if result.action.status == .succeeded {
            if var session = currentSession,
               let index = session.threats.firstIndex(where: { $0.path == record.originalPath })
            {
                session.threats[index].status = .restored
                session.threats[index].lastUpdatedAt = Date()
                session.summary = aggregator.buildSummary(threats: session.threats)
                currentSession = session
                _ = scanHistoryStore.update(session)
            }
            lastOperationMessage = result.action.resultMessage
        } else {
            activeAlert = ThreatExplorerAlert(
                title: localized("恢复失败", "Restore Failed"),
                message: result.action.resultMessage
            )
        }

        reloadStores()
    }

    func deleteFromQuarantine(_ record: QuarantineRecord) {
        do {
            try quarantineManager.deletePermanently(quarantineID: record.quarantineID)
            reloadStores()
            lastOperationMessage = localized("已从隔离区永久删除。", "Deleted from quarantine.")
        } catch {
            activeAlert = ThreatExplorerAlert(
                title: localized("删除失败", "Delete Failed"),
                message: error.localizedDescription
            )
        }
    }

    func revealThreatInFinder(_ threatID: String) {
        guard let threat = currentSession?.threats.first(where: { $0.threatID == threatID }) else {
            return
        }
        let url = URL(fileURLWithPath: threat.path)
        NSWorkspace.shared.activateFileViewerSelecting([url])
        lastOperationMessage = localized("已在访达中定位：\(url.lastPathComponent)", "Revealed in Finder: \(url.lastPathComponent)")
    }

    func moveThreatToTrashDirectly(_ threatID: String) {
        guard var session = currentSession,
              let index = session.threats.firstIndex(where: { $0.threatID == threatID })
        else {
            return
        }

        let threat = session.threats[index]
        guard threat.canDelete else {
            activeAlert = ThreatExplorerAlert(
                title: localized("不可移动", "Cannot Move"),
                message: localized("该项目当前不支持移动到废纸篓。", "This item cannot be moved to Trash right now.")
            )
            return
        }

        let hash = scanItemsByID[threat.itemID]?.hash
        let execution = remediationEngine.execute(
            sessionID: session.sessionID,
            actionType: .moveToTrash,
            threat: threat,
            hash: hash,
            userConfirmed: true
        )
        session.threats[index] = execution.updatedThreat
        session.summary = aggregator.buildSummary(threats: session.threats)
        session.completedAt = session.completedAt ?? Date()

        currentSession = session
        _ = scanHistoryStore.update(session)
        reloadStores()
        selectedThreatIDs.remove(threatID)

        if execution.action.status == .succeeded {
            lastOperationMessage = execution.action.resultMessage
        } else {
            activeAlert = ThreatExplorerAlert(
                title: localized("移到废纸篓失败", "Move to Trash Failed"),
                message: execution.action.resultMessage
            )
        }
    }

    func removeIgnoreRule(_ record: IgnoreRuleRecord) {
        _ = ignoreStore.remove(id: record.id)
        ignoredItems = ignoreStore.load()
        lastOperationMessage = localized("已移除忽略规则。", "Ignore rule removed.")
    }

    func selectAllFilteredThreats() {
        selectedThreatIDs = Set(filteredThreats.map(\.threatID))
    }

    func clearSelection() {
        selectedThreatIDs.removeAll()
    }

    func toggleSelection(for threatID: String) {
        if selectedThreatIDs.contains(threatID) {
            selectedThreatIDs.remove(threatID)
        } else {
            selectedThreatIDs.insert(threatID)
        }
    }

    var filteredThreats: [ThreatRecord] {
        guard let session = currentSession else { return [] }

        var threats = session.threats

        threats = threats.filter { threat in
            if !filterState.riskLevels.isEmpty, !filterState.riskLevels.contains(threat.riskLevel) {
                return false
            }
            if !filterState.verdicts.isEmpty, !filterState.verdicts.contains(threat.verdict) {
                return false
            }
            if !filterState.types.isEmpty, !filterState.types.contains(threat.detectedType) {
                return false
            }

            let location = locationCategory(for: threat.path)
            if !filterState.locations.isEmpty, !filterState.locations.contains(location) {
                return false
            }

            if filterState.onlyRemediable {
                let canHandle = threat.canQuarantine || threat.canDelete || threat.canIgnore || threat.canDisablePersistence
                if !canHandle { return false }
            }

            if filterState.onlyPersistenceRelated, threat.persistenceIndicators.isEmpty {
                return false
            }

            if filterState.onlyUnsignedExecutable {
                guard threat.detectedType.isExecutableLike else { return false }
                guard appearsUnsigned(threat: threat) else { return false }
            }

            return true
        }

        return sortThreats(threats)
    }

    var selectedThreat: ThreatRecord? {
        guard let selectedThreatID else { return nil }
        return currentSession?.threats.first(where: { $0.threatID == selectedThreatID })
    }

    var riskLevelDistribution: [RiskLevel: Int] {
        let threats = currentSession?.threats ?? []
        return Dictionary(grouping: threats, by: { $0.riskLevel }).mapValues(\.count)
    }

    var activeRemediationLogs: [RemediationLogEntry] {
        guard let sessionID = currentSession?.sessionID else { return [] }
        return remediationLogs.filter { $0.sessionID == sessionID }
    }

    var scanProgressPercent: Double {
        guard scanProgressTotal > 0 else { return 0 }
        return min(1, max(0, Double(scanProgressProcessed) / Double(scanProgressTotal)))
    }

    var scanProgressPercentText: String {
        "\(Int((scanProgressPercent * 100).rounded()))%"
    }

    var scanProgressStageDisplay: String {
        switch scanProgressStage {
        case "plan":
            return localized("准备扫描计划", "Preparing plan")
        case "fast_discovery":
            return localized("快速发现候选", "Fast discovery")
        case "candidate_selection":
            return localized("候选筛选与升级", "Candidate selection")
        case "focused_analysis":
            return localized("重点对象分析", "Focused analysis")
        case "cancelling":
            return localized("正在停止", "Stopping")
        case "completed":
            return localized("已完成", "Completed")
        case "cancelled":
            return localized("已停止", "Stopped")
        case "starting":
            return localized("启动中", "Starting")
        default:
            return scanProgressStage
        }
    }

    var customFocusPathCount: Int {
        parsedCustomFocusPaths().count
    }

    var availableTypeFilters: [SupportedFileType] {
        let types = Set((currentSession?.threats ?? []).map(\.detectedType))
        return types.sorted { $0.rawValue < $1.rawValue }
    }

    var availableLocationFilters: [LocationCategory] {
        let locations = Set((currentSession?.threats ?? []).map { locationCategory(for: $0.path) })
        return locations.sorted { $0.rawValue < $1.rawValue }
    }

    private func requestAction(_ actionType: RemediationActionType, threatIDs: [String]) {
        guard let session = currentSession else { return }
        let targetIDs = threatIDs.uniquePreservingOrder()
        let targets = session.threats.filter { targetIDs.contains($0.threatID) }
        guard !targets.isEmpty else {
            activeAlert = ThreatExplorerAlert(
                title: localized("没有可处理项目", "No Items"),
                message: localized("请选择至少一个风险项目。", "Select at least one threat item.")
            )
            return
        }

        let highCount = targets.filter { $0.riskLevel == .high || $0.riskLevel == .critical }.count
        let irreversibleCount = actionType == .deletePermanently ? targets.count : 0
        let actionName = actionTypeName(actionType)
        let msg = localized(
            "将执行 \(actionName) 操作，共 \(targets.count) 项（High/Critical: \(highCount)，不可恢复: \(irreversibleCount)）。",
            "Run \(actionName) on \(targets.count) item(s) (High/Critical: \(highCount), irreversible: \(irreversibleCount))."
        )

        remediationConfirmation = ThreatRemediationConfirmation(
            actionType: actionType,
            threatIDs: targets.map(\.threatID),
            title: localized("确认执行", "Confirm Action"),
            message: msg,
            irreversibleCount: irreversibleCount
        )
    }

    private func applyProgress(_ event: FullDiskScanProgressEvent) {
        scanProgressStage = event.stage
        scanProgressMessage = event.message
        scanProgressProcessed = event.processed
        scanProgressTotal = event.total
        scanCurrentPath = event.currentPath
        scanDiscoveredCount = event.discoveredCount
        scanSelectedCount = event.selectedCount
        scanAnalyzedCount = event.analyzedCount
        scanThreatCount = event.threatCount
        liveSessionID = event.sessionID

        if event.stage == "cancelled" || event.stage == "completed" {
            isStoppingScan = false
        }

        if let newThreat = event.newThreat {
            appendLiveThreat(newThreat, from: event)
        }
    }

    private func applyScanResult(_ result: FullDiskScanRunResult) {
        isScanning = false
        isStoppingScan = false
        scanTask = nil
        scanCancellationSignal.reset()

        currentSession = result.session
        scanItemsByID = result.scanItemsByID
        selectedThreatID = result.session.threats.first?.threatID
        selectedThreatIDs.removeAll()
        liveSessionID = nil
        scanProgressStage = result.session.notes.contains(where: { $0.lowercased().contains("cancel") }) ? "cancelled" : "completed"
        if scanProgressStage == "cancelled" {
            scanProgressMessage = localized("扫描已停止。", "Scan stopped.")
            lastOperationMessage = scanProgressMessage
        } else {
            lastOperationMessage = localized(
                "扫描完成：候选 \(result.session.totalCandidates) 项，风险 \(result.session.summary.threatCount) 项。",
                "Scan completed: \(result.session.totalCandidates) candidates, \(result.session.summary.threatCount) threats."
            )
        }

        scanHistory = scanHistoryStore.load()
        remediationLogs = remediationHistoryStore.load()
        ignoredItems = ignoreStore.load()
        quarantineRecords = quarantineManager.loadRecords()

        if !result.session.inaccessiblePaths.isEmpty {
            let preview = result.session.inaccessiblePaths.prefix(5).joined(separator: "\n")
            activeAlert = ThreatExplorerAlert(
                title: localized("部分路径无权限", "Permission Limited"),
                message: localized(
                    "以下路径无法完整扫描（示例）：\n\(preview)",
                    "Some paths could not be scanned (sample):\n\(preview)"
                )
            )
        }
    }

    private func appendLiveThreat(_ threat: ThreatRecord, from event: FullDiskScanProgressEvent) {
        var session = currentSession
        if session?.sessionID != event.sessionID {
            session = ScanSession(
                sessionID: event.sessionID,
                mode: selectedScanMode,
                startedAt: Date(),
                completedAt: nil,
                rootScopes: [],
                totalCandidates: event.discoveredCount,
                analyzedCount: event.analyzedCount,
                skippedCount: 0,
                failedCount: 0,
                summary: ScanSummary(
                    threatCount: 0,
                    criticalCount: 0,
                    highCount: 0,
                    mediumCount: 0,
                    lowCount: 0,
                    infoCount: 0,
                    persistenceCount: 0,
                    quarantinedCount: 0,
                    ignoredCount: 0
                ),
                threats: [],
                inaccessiblePaths: [],
                notes: ["Live session preview"],
                performanceTrace: nil
            )
        }

        guard var mutableSession = session else { return }
        if !mutableSession.threats.contains(where: { $0.threatID == threat.threatID }) {
            mutableSession.threats.append(threat)
        }
        mutableSession.totalCandidates = max(mutableSession.totalCandidates, event.discoveredCount)
        mutableSession.analyzedCount = max(mutableSession.analyzedCount, event.analyzedCount)
        mutableSession.summary = aggregator.buildSummary(threats: mutableSession.threats)
        currentSession = mutableSession
        if selectedThreatID == nil {
            selectedThreatID = threat.threatID
        }
    }

    private func sortThreats(_ threats: [ThreatRecord]) -> [ThreatRecord] {
        threats.sorted { lhs, rhs in
            switch sortMode {
            case .riskDescending:
                let l = riskPriority(lhs.riskLevel)
                let r = riskPriority(rhs.riskLevel)
                if l != r { return l > r }
                if lhs.score != rhs.score { return lhs.score > rhs.score }
                return lhs.path < rhs.path
            case .pathAscending:
                return lhs.path < rhs.path
            case .timeDescending:
                if lhs.lastUpdatedAt != rhs.lastUpdatedAt {
                    return lhs.lastUpdatedAt > rhs.lastUpdatedAt
                }
                return lhs.path < rhs.path
            case .typeAscending:
                if lhs.detectedType != rhs.detectedType {
                    return lhs.detectedType.rawValue < rhs.detectedType.rawValue
                }
                return lhs.path < rhs.path
            }
        }
    }

    private func riskPriority(_ level: RiskLevel) -> Int {
        switch level {
        case .critical: return 5
        case .high: return 4
        case .medium: return 3
        case .low: return 2
        case .info: return 1
        }
    }

    private func locationCategory(for path: String) -> LocationCategory {
        let lower = path.lowercased()
        let home = FileManager.default.homeDirectoryForCurrentUser.path.lowercased()

        if lower.hasPrefix("/applications/") { return .applications }
        if lower.hasPrefix("\(home)/applications/") { return .userApplications }
        if lower.hasPrefix("\(home)/downloads/") { return .downloads }
        if lower.hasPrefix("\(home)/desktop/") { return .desktop }
        if lower.hasPrefix("\(home)/documents/") { return .documents }
        if lower.contains("launchagents") { return .launchAgents }
        if lower.contains("launchdaemons") { return .launchDaemons }
        if lower.hasPrefix("\(home)/library/application support/") { return .appSupport }
        if lower.hasPrefix("\(home)/library/preferences/") { return .preferences }
        if lower.hasPrefix("\(home)/library/scripts/") { return .scripts }
        if lower.hasPrefix("\(home)/library/caches/") { return .caches }
        if lower.hasPrefix("/tmp/") || lower.hasPrefix("/private/tmp/") { return .temporary }
        if lower.hasPrefix("/library/") { return .library }
        if lower.hasPrefix("/usr/local/") || lower.hasPrefix("/opt/homebrew/") { return .brew }
        if lower.hasPrefix("/volumes/") { return .externalVolume }
        if lower.hasPrefix(home + "/") { return .userHome }
        return .unknown
    }

    private func appearsUnsigned(threat: ThreatRecord) -> Bool {
        let candidates = [
            threat.summary,
            threat.findings.map(\.title).joined(separator: " "),
            threat.findings.map(\.technicalDetails).joined(separator: " "),
            threat.findings.map(\.explanation).joined(separator: " ")
        ].joined(separator: " ").lowercased()

        return candidates.contains("unsigned")
            || candidates.contains("not signed")
            || candidates.contains("未签名")
    }

    private func actionTypeName(_ actionType: RemediationActionType) -> String {
        switch actionType {
        case .quarantine:
            return localized("隔离", "Quarantine")
        case .moveToTrash:
            return localized("移到废纸篓", "Move to Trash")
        case .deletePermanently:
            return localized("永久删除", "Delete Permanently")
        case .disablePersistence:
            return localized("禁用持久化", "Disable Persistence")
        case .removeLaunchAgent:
            return localized("移除启动项", "Remove Launch Agent")
        case .ignore:
            return localized("忽略", "Ignore")
        case .restoreFromQuarantine:
            return localized("恢复", "Restore")
        }
    }

    private func parsedCustomFocusPaths() -> [String] {
        customFocusPathsInput
            .split(whereSeparator: \ .isNewline)
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .uniquePreservingOrder()
    }

    private func persistPreferences() {
        defaults.set(selectedScanMode.rawValue, forKey: DefaultsKeys.fullScanMode)
        defaults.set(includeExternalVolumes, forKey: DefaultsKeys.includeExternalVolumes)
        defaults.set(persistCustomFocusPaths, forKey: DefaultsKeys.persistCustomPaths)
        if persistCustomFocusPaths {
            defaults.set(customFocusPathsInput, forKey: DefaultsKeys.customPathsText)
        }
    }

    private func localized(_ zh: String, _ en: String) -> String {
        settings.language == .zhHans ? zh : en
    }
}
