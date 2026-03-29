import SwiftUI

struct FullDiskScanView: View {
    private enum FullScanTab: String, CaseIterable, Identifiable {
        case scanCenter
        case threatExplorer
        case quarantine
        case history

        var id: String { rawValue }

        func title(language: AppLanguage) -> String {
            switch (self, language) {
            case (.scanCenter, .zhHans):
                return "扫描中心"
            case (.scanCenter, .en):
                return "Scan Center"
            case (.threatExplorer, .zhHans):
                return "风险浏览器"
            case (.threatExplorer, .en):
                return "Threat Explorer"
            case (.quarantine, .zhHans):
                return "隔离区"
            case (.quarantine, .en):
                return "Quarantine"
            case (.history, .zhHans):
                return "历史与日志"
            case (.history, .en):
                return "History & Logs"
            }
        }

        var icon: String {
            switch self {
            case .scanCenter:
                return "scope"
            case .threatExplorer:
                return "exclamationmark.shield"
            case .quarantine:
                return "archivebox"
            case .history:
                return "clock.arrow.circlepath"
            }
        }
    }

    @ObservedObject var viewModel: ThreatExplorerViewModel
    @ObservedObject var settings: AppSettingsStore
    @State private var selectedTab: FullScanTab = .scanCenter
    @State private var deleteQuarantineRecord: QuarantineRecord?
    @State private var isScanSettingsPresented = false

    @Environment(\.appFontScale) private var appFontScale

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.sectionSpacing) {
            tabBar
            switch selectedTab {
            case .scanCenter:
                scanCenterView
            case .threatExplorer:
                threatExplorerView
            case .quarantine:
                quarantineView
            case .history:
                historyView
            }
        }
        .onAppear {
            viewModel.reloadStores()
        }
        .alert(item: $viewModel.activeAlert) { alert in
            Alert(
                title: Text(alert.title),
                message: Text(alert.message),
                dismissButton: .default(Text(settings.language == .zhHans ? "知道了" : "OK"))
            )
        }
        .alert(item: $viewModel.remediationConfirmation) { confirmation in
            Alert(
                title: Text(confirmation.title),
                message: Text(confirmation.message),
                primaryButton: confirmation.irreversibleCount > 0
                    ? .destructive(Text(settings.language == .zhHans ? "确认执行" : "Proceed"), action: {
                        viewModel.executeConfirmedAction()
                    })
                    : .default(Text(settings.language == .zhHans ? "确认执行" : "Proceed"), action: {
                        viewModel.executeConfirmedAction()
                    }),
                secondaryButton: .cancel(Text(settings.language == .zhHans ? "取消" : "Cancel"))
            )
        }
        .alert(item: $deleteQuarantineRecord) { record in
            Alert(
                title: Text(settings.language == .zhHans ? "确认永久删除" : "Confirm Permanent Delete"),
                message: Text(record.quarantinePath),
                primaryButton: .destructive(Text(settings.language == .zhHans ? "永久删除" : "Delete"), action: {
                    viewModel.deleteFromQuarantine(record)
                }),
                secondaryButton: .cancel(Text(settings.language == .zhHans ? "取消" : "Cancel"))
            )
        }
    }

    private var tabBar: some View {
        HStack(spacing: metrics.compactPadding) {
            HStack(spacing: metrics.compactPadding) {
                ForEach(FullScanTab.allCases) { tab in
                    Button {
                        selectedTab = tab
                    } label: {
                        Label(tab.title(language: settings.language), systemImage: tab.icon)
                            .appFont(.body, metrics: metrics)
                            .fontWeight(selectedTab == tab ? .semibold : .regular)
                            .foregroundStyle(.primary)
                            .padding(.horizontal, metrics.compactPadding)
                            .padding(.vertical, metrics.compactPadding * 0.7)
                            .appGlassPanel(
                                metrics: metrics,
                                interactive: true,
                                emphasized: selectedTab == tab
                            )
                    }
                    .buttonStyle(.plain)
                }
            }
            .appGlassCluster(spacing: metrics.compactPadding)
            Spacer()
        }
    }

    private var scanCenterView: some View {
        VStack(alignment: .leading, spacing: metrics.sectionSpacing) {
            HStack {
                Text(settings.language == .zhHans ? "扫描中心" : "Scan Center")
                    .appFont(.headline, metrics: metrics)
                Spacer()
                Button {
                    isScanSettingsPresented = true
                } label: {
                    Image(systemName: "gearshape")
                        .imageScale(.medium)
                }
                .buttonStyle(.bordered)
                .help(settings.language == .zhHans ? "扫描设置" : "Scan Settings")
            }

            GroupBox(settings.language == .zhHans ? "扫描启动" : "Start Scan") {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    AdaptiveStack(tier: metrics.layoutTier, spacing: metrics.rowSpacing) {
                        Button {
                            viewModel.startScan(mode: .quick)
                        } label: {
                            Label(settings.language == .zhHans ? "快速扫描" : "Quick Scan", systemImage: "bolt.fill")
                                .appFont(.body, metrics: metrics)
                        }
                        .appPrimaryButtonStyle()
                        .disabled(viewModel.isScanning)

                        Button {
                            viewModel.startScan(mode: .deep)
                        } label: {
                            Label(settings.language == .zhHans ? "深度扫描" : "Deep Scan", systemImage: "shield.lefthalf.filled")
                                .appFont(.body, metrics: metrics)
                        }
                        .buttonStyle(.bordered)
                        .disabled(viewModel.isScanning)

                        if viewModel.isScanning {
                            Button(
                                viewModel.isStoppingScan
                                    ? (settings.language == .zhHans ? "正在停止..." : "Stopping...")
                                    : (settings.language == .zhHans ? "取消" : "Cancel")
                            ) {
                                viewModel.cancelScan()
                            }
                            .buttonStyle(.bordered)
                            .disabled(viewModel.isStoppingScan)
                        }
                    }

                    Toggle(
                        settings.language == .zhHans ? "扫描外接卷（默认关闭）" : "Scan external volumes (default off)",
                        isOn: $viewModel.includeExternalVolumes
                    )
                    .appFont(.body, metrics: metrics)

                    Text(
                        settings.language == .zhHans
                        ? "已配置重点路径 \(viewModel.customFocusPathCount) 项（通过右上角设置管理）"
                        : "\(viewModel.customFocusPathCount) focus paths configured (manage via top-right settings)"
                    )
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                    Text(
                        settings.language == .zhHans
                        ? "当前并发分析任务：\(settings.fullDiskScanMaxConcurrency)（可在 设置 > 高级 调整）"
                        : "Current concurrent analysis workers: \(settings.fullDiskScanMaxConcurrency) (adjust in Settings > Advanced)"
                    )
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                    if viewModel.isScanning {
                        ProgressView(value: Double(viewModel.scanProgressProcessed), total: max(1, Double(viewModel.scanProgressTotal))) {
                            Text(viewModel.scanProgressMessage)
                                .appFont(.footnote, metrics: metrics)
                        }
                        .controlSize(.small)

                        Text(
                            settings.language == .zhHans
                            ? "阶段：\(viewModel.scanProgressStageDisplay)  ·  进度：\(viewModel.scanProgressProcessed)/\(max(0, viewModel.scanProgressTotal))（\(viewModel.scanProgressPercentText)）"
                            : "Progress: \(viewModel.scanProgressProcessed)/\(max(0, viewModel.scanProgressTotal)) (\(viewModel.scanProgressPercentText))"
                        )
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)

                        Text(
                            settings.language == .zhHans
                            ? "发现候选 \(viewModel.scanDiscoveredCount) · 升级分析 \(viewModel.scanSelectedCount) · 已分析 \(viewModel.scanAnalyzedCount) · 风险 \(viewModel.scanThreatCount)"
                            : "Discovered \(viewModel.scanDiscoveredCount) · Focused \(viewModel.scanSelectedCount) · Analyzed \(viewModel.scanAnalyzedCount) · Threats \(viewModel.scanThreatCount)"
                        )
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)

                        if let path = viewModel.scanCurrentPath, !path.isEmpty {
                            Text(path)
                                .appFont(.caption, metrics: metrics)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                }
                .padding(.top, 6)
            }

            if !viewModel.scanHistory.isEmpty {
                GroupBox(settings.language == .zhHans ? "最近扫描" : "Recent Scans") {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(viewModel.scanHistory.prefix(4)) { session in
                            HStack(alignment: .top, spacing: metrics.rowSpacing) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(session.sessionID)
                                        .appFont(.monospacedCaption, metrics: metrics)
                                    Text(sessionLine(session: session))
                                        .appFont(.caption, metrics: metrics)
                                        .foregroundStyle(.secondary)
                                    Text(
                                        settings.language == .zhHans
                                        ? "风险 \(session.summary.threatCount) · 候选 \(session.totalCandidates) · 分析 \(session.analyzedCount)"
                                        : "Threats \(session.summary.threatCount) · Candidates \(session.totalCandidates) · Analyzed \(session.analyzedCount)"
                                    )
                                    .appFont(.caption, metrics: metrics)
                                    .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button(settings.language == .zhHans ? "打开" : "Open") {
                                    viewModel.openHistorySession(session)
                                    selectedTab = .threatExplorer
                                }
                                .buttonStyle(.borderless)
                            }
                            Divider()
                        }
                    }
                    .padding(.top, 4)
                }
            }

            if let session = viewModel.currentSession {
                GroupBox(settings.language == .zhHans ? "最近扫描摘要" : "Latest Scan Summary") {
                    VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                        Text(sessionLine(session: session))
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                        Text(
                            "Critical/High/Medium/Low/Info: \(session.summary.criticalCount)/\(session.summary.highCount)/\(session.summary.mediumCount)/\(session.summary.lowCount)/\(session.summary.infoCount)"
                        )
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)

                        Text(
                            settings.language == .zhHans
                            ? "风险项 \(session.summary.threatCount) · 持久化可疑 \(session.summary.persistenceCount) · 已隔离 \(session.summary.quarantinedCount) · 已忽略 \(session.summary.ignoredCount)"
                            : "Threats \(session.summary.threatCount) · Persistence \(session.summary.persistenceCount) · Quarantined \(session.summary.quarantinedCount) · Ignored \(session.summary.ignoredCount)"
                        )
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)

                        if !session.inaccessiblePaths.isEmpty {
                            Text(settings.language == .zhHans ? "存在无权限路径，建议授予 Full Disk Access 后重扫。" : "Permission-limited paths detected. Grant Full Disk Access and rescan.")
                                .appFont(.footnote, metrics: metrics)
                                .foregroundStyle(.orange)
                        }

                        if let perf = session.performanceTrace {
                            Text(
                                settings.language == .zhHans
                                ? "性能：枚举 \(perf.totalEnumerated) · 候选 \(perf.totalCandidates) · 升级 \(perf.totalEscalated) · 分析 \(perf.totalAnalyzed) · 用时 \(perf.elapsedTimeMs)ms"
                                : "Perf: enumerated \(perf.totalEnumerated) · candidates \(perf.totalCandidates) · escalated \(perf.totalEscalated) · analyzed \(perf.totalAnalyzed) · elapsed \(perf.elapsedTimeMs)ms"
                            )
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.top, 6)
                }
            }

            if let message = viewModel.lastOperationMessage {
                Text(message)
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }
        }
        .sheet(isPresented: $isScanSettingsPresented) {
            scanSettingsSheet
                .padding(metrics.cardPadding)
                .frame(minWidth: 560, minHeight: 420)
        }
    }

    private var scanSettingsSheet: some View {
        VStack(alignment: .leading, spacing: metrics.sectionSpacing) {
            Text(settings.language == .zhHans ? "扫描设置" : "Scan Settings")
                .appFont(.headline, metrics: metrics)

            Text(settings.language == .zhHans
                 ? "输入多个重点路径（每行一个）。快速扫描会优先补扫这些路径；深度扫描会递归覆盖。"
                 : "Enter focus paths (one per line). Quick scan prioritizes these paths; deep scan recursively covers them.")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)

            TextEditor(text: $viewModel.customFocusPathsInput)
                .appFont(.monospacedBody, metrics: metrics)
                .frame(minHeight: metrics.scaled(220))
                .padding(metrics.compactPadding)
                .appGlassPanel(metrics: metrics, interactive: true, cornerRadius: metrics.scaled(14))

            Toggle(
                settings.language == .zhHans ? "将重点路径持久化到配置文件（RULE-PATH-PREFIX,notice）" : "Persist focus paths to profile (RULE-PATH-PREFIX,notice)",
                isOn: $viewModel.persistCustomFocusPaths
            )
            .appFont(.footnote, metrics: metrics)

            HStack {
                Text(
                    settings.language == .zhHans
                    ? "当前共 \(viewModel.customFocusPathCount) 个有效路径"
                    : "\(viewModel.customFocusPathCount) valid paths"
                )
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
                Spacer()
                Button(settings.language == .zhHans ? "关闭" : "Close") {
                    isScanSettingsPresented = false
                }
                .appPrimaryButtonStyle()
            }
        }
    }

    private var threatExplorerView: some View {
        VStack(alignment: .leading, spacing: metrics.sectionSpacing) {
            if let session = viewModel.currentSession {
                GroupBox(settings.language == .zhHans ? "扫描结果概览" : "Scan Result Overview") {
                    VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                        Text(sessionLine(session: session))
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)

                        Text(
                            settings.language == .zhHans
                            ? "已扫描 \(session.analyzedCount) 项，风险项 \(session.summary.threatCount)"
                            : "Analyzed \(session.analyzedCount), threats \(session.summary.threatCount)"
                        )
                        .appFont(.body, metrics: metrics)

                        Text(
                            "Critical/High/Medium/Low/Info: \(session.summary.criticalCount)/\(session.summary.highCount)/\(session.summary.mediumCount)/\(session.summary.lowCount)/\(session.summary.infoCount)"
                        )
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                    }
                    .padding(.top, 6)
                }

                filterBar
                bulkActionBar

                HStack(alignment: .top, spacing: metrics.sectionSpacing) {
                    threatList
                        .frame(minWidth: 460)

                    threatDetail
                        .frame(maxWidth: .infinity)
                }
            } else {
                GroupBox(settings.language == .zhHans ? "风险浏览器" : "Threat Explorer") {
                    Text(settings.language == .zhHans ? "暂无扫描结果，请先运行快速扫描或深度扫描。" : "No scan results yet. Run Quick Scan or Deep Scan first.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .padding(.top, 6)
                }
            }
        }
    }

    private var filterBar: some View {
        GroupBox(settings.language == .zhHans ? "筛选与排序" : "Filters & Sorting") {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                HStack(spacing: metrics.compactPadding) {
                    Menu(settings.language == .zhHans ? "风险等级" : "Risk Level") {
                        ForEach([RiskLevel.critical, .high, .medium, .low, .info], id: \.rawValue) { level in
                            Toggle(level.displayName(language: settings.language), isOn: binding(for: level))
                        }
                    }

                    Menu("Verdict") {
                        ForEach([ScanVerdict.malicious, .suspicious, .unknown, .clean], id: \.rawValue) { verdict in
                            Toggle(verdict.rawValue, isOn: binding(for: verdict))
                        }
                    }

                    Menu(settings.language == .zhHans ? "类型" : "Type") {
                        ForEach(viewModel.availableTypeFilters, id: \.rawValue) { type in
                            Toggle(type.displayName(language: settings.language), isOn: binding(for: type))
                        }
                    }

                    Menu(settings.language == .zhHans ? "位置" : "Location") {
                        ForEach(viewModel.availableLocationFilters, id: \.rawValue) { location in
                            Toggle(location.rawValue, isOn: binding(for: location))
                        }
                    }

                    Picker(settings.language == .zhHans ? "排序" : "Sort", selection: $viewModel.sortMode) {
                        Text(settings.language == .zhHans ? "风险降序" : "Risk Desc").tag(ThreatSortMode.riskDescending)
                        Text(settings.language == .zhHans ? "路径" : "Path").tag(ThreatSortMode.pathAscending)
                        Text(settings.language == .zhHans ? "时间" : "Time").tag(ThreatSortMode.timeDescending)
                        Text(settings.language == .zhHans ? "类型" : "Type").tag(ThreatSortMode.typeAscending)
                    }
                    .pickerStyle(.menu)

                    Spacer()
                }

                HStack(spacing: metrics.compactPadding) {
                    Toggle(settings.language == .zhHans ? "仅可处理" : "Remediable Only", isOn: $viewModel.filterState.onlyRemediable)
                    Toggle(settings.language == .zhHans ? "仅持久化相关" : "Persistence Only", isOn: $viewModel.filterState.onlyPersistenceRelated)
                    Toggle(settings.language == .zhHans ? "仅未签名可执行" : "Unsigned Executables", isOn: $viewModel.filterState.onlyUnsignedExecutable)
                }
                .appFont(.footnote, metrics: metrics)
            }
            .padding(.top, 6)
        }
    }

    private var bulkActionBar: some View {
        GroupBox(settings.language == .zhHans ? "批量处理" : "Bulk Actions") {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                HStack(spacing: metrics.compactPadding) {
                    Button(settings.language == .zhHans ? "按筛选全选" : "Select Filtered") {
                        viewModel.selectAllFilteredThreats()
                    }
                    .buttonStyle(.bordered)

                    Button(settings.language == .zhHans ? "清空选择" : "Clear Selection") {
                        viewModel.clearSelection()
                    }
                    .buttonStyle(.bordered)

                    Text(
                        settings.language == .zhHans
                        ? "已选 \(viewModel.selectedThreatIDs.count) / 当前筛选 \(viewModel.filteredThreats.count)"
                        : "Selected \(viewModel.selectedThreatIDs.count) / Filtered \(viewModel.filteredThreats.count)"
                    )
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                    Spacer()
                }

                HStack(spacing: metrics.compactPadding) {
                    Button(settings.language == .zhHans ? "隔离所选" : "Quarantine Selected") {
                        viewModel.requestBulkAction(.quarantine)
                    }
                    .appPrimaryButtonStyle()

                    Button(settings.language == .zhHans ? "移到废纸篓" : "Move to Trash") {
                        viewModel.requestBulkAction(.moveToTrash)
                    }
                    .buttonStyle(.bordered)

                    Button(settings.language == .zhHans ? "忽略所选" : "Ignore Selected") {
                        viewModel.requestBulkAction(.ignore)
                    }
                    .buttonStyle(.bordered)

                    Button(settings.language == .zhHans ? "禁用持久化" : "Disable Persistence") {
                        viewModel.requestBulkAction(.disablePersistence)
                    }
                    .buttonStyle(.bordered)
                }
            }
            .padding(.top, 6)
        }
    }

    private var threatList: some View {
        GroupBox(settings.language == .zhHans ? "风险列表" : "Threat List") {
            if viewModel.filteredThreats.isEmpty {
                Text(settings.language == .zhHans ? "当前筛选条件下无风险项。" : "No threats under current filters.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
                    .padding(.top, 6)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(viewModel.filteredThreats) { threat in
                            threatRow(threat)
                        }
                    }
                    .padding(.top, 4)
                }
                .frame(minHeight: metrics.scaled(380))
            }
        }
    }

    private func threatRow(_ threat: ThreatRecord) -> some View {
        let selected = viewModel.selectedThreatID == threat.threatID
        let checked = viewModel.selectedThreatIDs.contains(threat.threatID)

        return Button {
            viewModel.selectedThreatID = threat.threatID
        } label: {
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .center, spacing: 8) {
                    Button {
                        viewModel.toggleSelection(for: threat.threatID)
                    } label: {
                        Image(systemName: checked ? "checkmark.circle.fill" : "circle")
                    }
                    .buttonStyle(.plain)

                    Text(threat.displayName)
                        .appFont(.body, metrics: metrics)
                        .lineLimit(1)

                    Spacer()

                    Text(settings.language == .zhHans ? "分 \(threat.score)" : "Score \(threat.score)")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(scoreColor(threat.score))
                        .appGlassBadge(tint: scoreColor(threat.score), metrics: metrics)

                    Text(threat.riskLevel.displayName(language: settings.language))
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(riskColor(threat.riskLevel))
                        .appGlassBadge(tint: riskColor(threat.riskLevel), metrics: metrics)
                }

                Text(pathSummary(threat.path))
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)

                Text("score: \(threat.score) · verdict: \(threat.verdict.rawValue) · status: \(threat.status.rawValue) · type: \(threat.detectedType.displayName(language: settings.language))")
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)

                if !threat.findings.isEmpty {
                    Text(threat.findings.prefix(2).map { $0.title }.joined(separator: " · "))
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                if !threat.persistenceIndicators.isEmpty {
                    Text(settings.language == .zhHans ? "含持久化迹象" : "Persistence related")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.orange)
                }
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .appGlassPanel(
                metrics: metrics,
                interactive: true,
                cornerRadius: metrics.scaled(10),
                emphasized: selected
            )
        }
        .buttonStyle(.plain)
        .contextMenu {
            Button(settings.language == .zhHans ? "在访达中显示" : "Reveal in Finder") {
                viewModel.revealThreatInFinder(threat.threatID)
            }

            Button(settings.language == .zhHans ? "移到废纸篓" : "Move to Trash") {
                viewModel.moveThreatToTrashDirectly(threat.threatID)
            }
            .disabled(!threat.canDelete)
        }
    }

    private var threatDetail: some View {
        GroupBox(settings.language == .zhHans ? "风险详情" : "Threat Detail") {
            if let threat = viewModel.selectedThreat {
                ScrollView {
                    VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                        Text(threat.displayName)
                            .appFont(.headline, metrics: metrics)

                        Text(threat.path)
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)

                        Text("score: \(threat.score) · verdict: \(threat.verdict.rawValue) · risk: \(threat.riskLevel.displayName(language: settings.language))")
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)

                        Text(locationImportance(for: threat.path))
                            .appFont(.footnote, metrics: metrics)
                            .foregroundStyle(.secondary)

                        if !threat.persistenceIndicators.isEmpty {
                            Text(settings.language == .zhHans
                                 ? "持久化指标：\(threat.persistenceIndicators.joined(separator: ", "))"
                                 : "Persistence indicators: \(threat.persistenceIndicators.joined(separator: ", "))")
                                .appFont(.footnote, metrics: metrics)
                                .foregroundStyle(.orange)
                        }

                        Text(threat.summary)
                            .appFont(.body, metrics: metrics)

                        if !threat.findings.isEmpty {
                            Divider()
                            Text(settings.language == .zhHans ? "命中项" : "Findings")
                                .appFont(.body, metrics: metrics)
                                .fontWeight(.semibold)

                            ForEach(threat.findings) { finding in
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("[\(finding.ruleID)] \(finding.title) (+\(finding.scoreDelta))")
                                        .appFont(.footnote, metrics: metrics)
                                        .fontWeight(.semibold)
                                    Text("\(finding.severity) · \(finding.category)")
                                        .appFont(.caption, metrics: metrics)
                                        .foregroundStyle(.secondary)
                                    Text(finding.explanation)
                                        .appFont(.caption, metrics: metrics)
                                        .foregroundStyle(.secondary)
                                    if settings.developerModeEnabled {
                                        Text(finding.technicalDetails)
                                            .appFont(.monospacedCaption, metrics: metrics)
                                            .foregroundStyle(.secondary)
                                            .textSelection(.enabled)
                                    }
                                }
                            }
                        }

                        if !threat.cleanupRecommendations.isEmpty {
                            Divider()
                            Text(settings.language == .zhHans ? "建议处置" : "Recommendations")
                                .appFont(.body, metrics: metrics)
                                .fontWeight(.semibold)
                            ForEach(threat.cleanupRecommendations, id: \.self) { note in
                                Text("- \(note)")
                                    .appFont(.footnote, metrics: metrics)
                                    .foregroundStyle(.secondary)
                            }
                        }

                        Divider()
                        actionButtons(for: threat)
                    }
                    .padding(.top, 4)
                }
                .frame(minHeight: metrics.scaled(380))
            } else {
                Text(settings.language == .zhHans ? "请选择一个风险项查看详情。" : "Select a threat item to view details.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
                    .padding(.top, 6)
            }
        }
    }

    private func actionButtons(for threat: ThreatRecord) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: metrics.compactPadding) {
                Button(settings.language == .zhHans ? "隔离" : "Quarantine") {
                    viewModel.requestSingleAction(.quarantine, threatID: threat.threatID)
                }
                .appPrimaryButtonStyle()
                .disabled(!threat.canQuarantine)

                Button(settings.language == .zhHans ? "移到废纸篓" : "Move to Trash") {
                    viewModel.requestSingleAction(.moveToTrash, threatID: threat.threatID)
                }
                .buttonStyle(.bordered)

                Button(settings.language == .zhHans ? "忽略" : "Ignore") {
                    viewModel.requestSingleAction(.ignore, threatID: threat.threatID)
                }
                .buttonStyle(.bordered)
                .disabled(!threat.canIgnore)
            }

            HStack(spacing: metrics.compactPadding) {
                Button(settings.language == .zhHans ? "禁用持久化" : "Disable Persistence") {
                    viewModel.requestSingleAction(.disablePersistence, threatID: threat.threatID)
                }
                .buttonStyle(.bordered)
                .disabled(!threat.canDisablePersistence)

                Button(settings.language == .zhHans ? "永久删除（高风险）" : "Delete Permanently") {
                    viewModel.requestSingleAction(.deletePermanently, threatID: threat.threatID)
                }
                .buttonStyle(.bordered)
                .disabled(!threat.canDelete)
            }
        }
    }

    private var quarantineView: some View {
        VStack(alignment: .leading, spacing: metrics.sectionSpacing) {
            GroupBox(settings.language == .zhHans ? "隔离区管理" : "Quarantine Manager") {
                if viewModel.quarantineRecords.isEmpty {
                    Text(settings.language == .zhHans ? "隔离区为空。" : "Quarantine is empty.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .padding(.top, 6)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(viewModel.quarantineRecords) { record in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(record.originalPath)
                                        .appFont(.footnote, metrics: metrics)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                    Text(record.quarantinePath)
                                        .appFont(.caption, metrics: metrics)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                    Text(record.reason)
                                        .appFont(.caption, metrics: metrics)
                                        .foregroundStyle(.secondary)

                                    HStack(spacing: 8) {
                                        Button(settings.language == .zhHans ? "恢复" : "Restore") {
                                            viewModel.restoreFromQuarantine(record)
                                        }
                                        .buttonStyle(.bordered)
                                        .disabled(!record.canRestore)

                                        Button(settings.language == .zhHans ? "永久删除" : "Delete") {
                                            deleteQuarantineRecord = record
                                        }
                                        .buttonStyle(.bordered)
                                    }
                                }
                                .padding(8)
                                .appGlassPanel(metrics: metrics, interactive: true, cornerRadius: metrics.scaled(10))
                            }
                        }
                        .padding(.top, 4)
                    }
                    .frame(minHeight: metrics.scaled(320))
                }
            }

            if let message = viewModel.lastOperationMessage {
                Text(message)
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var historyView: some View {
        VStack(alignment: .leading, spacing: metrics.sectionSpacing) {
            GroupBox(settings.language == .zhHans ? "扫描历史" : "Scan History") {
                if viewModel.scanHistory.isEmpty {
                    Text(settings.language == .zhHans ? "暂无扫描历史。" : "No scan history.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .padding(.top, 6)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(viewModel.scanHistory) { session in
                                HStack(alignment: .top, spacing: metrics.rowSpacing) {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(session.sessionID)
                                            .appFont(.monospacedCaption, metrics: metrics)
                                        Text(sessionLine(session: session))
                                            .appFont(.caption, metrics: metrics)
                                            .foregroundStyle(.secondary)
                                        Text(
                                            settings.language == .zhHans
                                            ? "候选 \(session.totalCandidates) · 分析 \(session.analyzedCount) · 风险 \(session.summary.threatCount)"
                                            : "Candidates \(session.totalCandidates) · Analyzed \(session.analyzedCount) · Threats \(session.summary.threatCount)"
                                        )
                                        .appFont(.caption, metrics: metrics)
                                        .foregroundStyle(.secondary)
                                    }

                                    Spacer()

                                    Button(settings.language == .zhHans ? "打开" : "Open") {
                                        viewModel.openHistorySession(session)
                                        selectedTab = .threatExplorer
                                    }
                                    .buttonStyle(.borderless)
                                }
                                Divider()
                            }
                        }
                        .padding(.top, 4)
                    }
                    .frame(minHeight: metrics.scaled(220))
                }
            }

            GroupBox(settings.language == .zhHans ? "导出报告" : "Export Report") {
                HStack(spacing: metrics.compactPadding) {
                    Button("JSON") {
                        viewModel.exportCurrentSession(format: .json)
                    }
                    .buttonStyle(.bordered)

                    Button("CSV") {
                        viewModel.exportCurrentSession(format: .csv)
                    }
                    .buttonStyle(.bordered)

                    Button("Markdown") {
                        viewModel.exportCurrentSession(format: .markdown)
                    }
                    .buttonStyle(.bordered)

                    Spacer()
                }
                .padding(.top, 6)
            }

            GroupBox(settings.language == .zhHans ? "处置日志" : "Remediation Log") {
                if viewModel.activeRemediationLogs.isEmpty {
                    Text(settings.language == .zhHans ? "当前会话暂无处置日志。" : "No remediation logs for current session.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .padding(.top, 6)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 4) {
                            ForEach(viewModel.activeRemediationLogs) { log in
                                Text("\(shortTime(log.timestamp)) [\(log.actionType.rawValue)] [\(log.status.rawValue)] \(log.path) - \(log.message)")
                                    .appFont(.monospacedCaption, metrics: metrics)
                                    .foregroundStyle(.secondary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .textSelection(.enabled)
                            }
                        }
                        .padding(.top, 4)
                    }
                    .frame(minHeight: metrics.scaled(180), maxHeight: metrics.scaled(260))
                }
            }

            GroupBox(settings.language == .zhHans ? "忽略项" : "Ignored Items") {
                if viewModel.ignoredItems.isEmpty {
                    Text(settings.language == .zhHans ? "暂无忽略规则。" : "No ignore rules.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .padding(.top, 6)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(viewModel.ignoredItems) { item in
                                HStack(alignment: .top, spacing: 8) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(item.path ?? item.hash ?? "-")
                                            .appFont(.caption, metrics: metrics)
                                            .lineLimit(1)
                                            .truncationMode(.middle)
                                        Text(shortTime(item.createdAt))
                                            .appFont(.caption, metrics: metrics)
                                            .foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Button(settings.language == .zhHans ? "移除" : "Remove") {
                                        viewModel.removeIgnoreRule(item)
                                    }
                                    .buttonStyle(.borderless)
                                }
                            }
                        }
                        .padding(.top, 4)
                    }
                    .frame(minHeight: metrics.scaled(120), maxHeight: metrics.scaled(200))
                }
            }
        }
    }

    private func sessionLine(session: ScanSession) -> String {
        let start = shortDate(session.startedAt)
        let end = session.completedAt.map(shortDate) ?? "-"
        let mode = session.mode.displayName(language: settings.language)
        return "\(mode) · \(start) -> \(end)"
    }

    private func pathSummary(_ path: String) -> String {
        if path.count <= 90 {
            return path
        }
        let prefix = String(path.prefix(40))
        let suffix = String(path.suffix(40))
        return "\(prefix)…\(suffix)"
    }

    private func locationImportance(for path: String) -> String {
        let lower = path.lowercased()
        if lower.contains("/downloads/") || lower.contains("/desktop/") || lower.contains("/private/tmp/") || lower.contains("/tmp/") {
            return settings.language == .zhHans
                ? "位置上下文：下载/临时目录中的可执行或脚本文件风险更高。"
                : "Location context: executables/scripts in Downloads or temp paths are higher risk."
        }
        if lower.contains("launchagents") || lower.contains("launchdaemons") {
            return settings.language == .zhHans
                ? "位置上下文：该路径属于持久化启动项目录，需优先复核。"
                : "Location context: this path is persistence startup territory and should be reviewed first."
        }
        if lower.hasPrefix("/applications/") {
            return settings.language == .zhHans
                ? "位置上下文：系统应用目录，处置前请确认不是合法安装源。"
                : "Location context: system applications path; verify legitimacy before remediation."
        }
        return settings.language == .zhHans
            ? "位置上下文：非关键默认目录，建议结合命中规则进一步复核。"
            : "Location context: non-default critical path; review with matched findings."
    }

    private func riskColor(_ level: RiskLevel) -> Color {
        switch level {
        case .critical:
            return .red
        case .high:
            return .orange
        case .medium:
            return .yellow
        case .low:
            return .blue
        case .info:
            return .secondary
        }
    }

    private func scoreColor(_ score: Int) -> Color {
        switch score {
        case 85...:
            return .red
        case 70...:
            return .orange
        case 45...:
            return .yellow
        case 25...:
            return .blue
        default:
            return .secondary
        }
    }

    private func shortDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    private func shortTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }

    private func binding(for level: RiskLevel) -> Binding<Bool> {
        Binding(
            get: { viewModel.filterState.riskLevels.contains(level) },
            set: { enabled in
                if enabled {
                    viewModel.filterState.riskLevels.insert(level)
                } else {
                    viewModel.filterState.riskLevels.remove(level)
                }
            }
        )
    }

    private func binding(for verdict: ScanVerdict) -> Binding<Bool> {
        Binding(
            get: { viewModel.filterState.verdicts.contains(verdict) },
            set: { enabled in
                if enabled {
                    viewModel.filterState.verdicts.insert(verdict)
                } else {
                    viewModel.filterState.verdicts.remove(verdict)
                }
            }
        )
    }

    private func binding(for type: SupportedFileType) -> Binding<Bool> {
        Binding(
            get: { viewModel.filterState.types.contains(type) },
            set: { enabled in
                if enabled {
                    viewModel.filterState.types.insert(type)
                } else {
                    viewModel.filterState.types.remove(type)
                }
            }
        )
    }

    private func binding(for location: LocationCategory) -> Binding<Bool> {
        Binding(
            get: { viewModel.filterState.locations.contains(location) },
            set: { enabled in
                if enabled {
                    viewModel.filterState.locations.insert(location)
                } else {
                    viewModel.filterState.locations.remove(location)
                }
            }
        )
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: appFontScale)
    }
}
