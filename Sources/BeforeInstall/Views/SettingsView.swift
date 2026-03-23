import SwiftUI

struct SettingsView: View {
    private enum SettingsCategory: String, CaseIterable, Identifiable {
        case general
        case advanced
        case about
        case developer

        var id: String { rawValue }

        func title(language: AppLanguage) -> String {
            switch (self, language) {
            case (.general, .zhHans):
                return "常规"
            case (.advanced, .zhHans):
                return "高级"
            case (.about, .zhHans):
                return "关于"
            case (.developer, .zhHans):
                return "开发者"
            case (.general, .en):
                return "General"
            case (.advanced, .en):
                return "Advanced"
            case (.about, .en):
                return "About"
            case (.developer, .en):
                return "Developer"
            }
        }

        var icon: String {
            switch self {
            case .general:
                return "gearshape"
            case .advanced:
                return "slider.horizontal.3"
            case .about:
                return "info.circle"
            case .developer:
                return "wrench.and.screwdriver"
            }
        }
    }

    @ObservedObject var settings: AppSettingsStore
    @ObservedObject var viewModel: AnalysisViewModel
    @ObservedObject var updateManager: AppUpdateManager
    @State private var permissionItems: [PermissionHealthItem] = []
    @State private var selectedCategory: SettingsCategory = .general
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("uiFontScale") private var uiFontScale = 1.0

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: metrics.groupSpacing) {
                Text(Localizer.text("settings.title", language: settings.language))
                    .appFont(.headline, metrics: metrics)

                categoryTabs

                switch selectedCategory {
                case .general:
                    generalSection
                case .advanced:
                    advancedSection
                case .about:
                    aboutSection
                case .developer:
                    developerSection
                }
            }
            .padding(metrics.cardPadding)
            .padding(.top, metrics.compactPadding)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .appFont(.body, metrics: metrics)
        .onAppear {
            refreshPermissionItems(withDelay: false)
        }
        .onChange(of: settings.language) { _ in
            refreshPermissionItems(withDelay: false)
        }
        .onChange(of: scenePhase) { phase in
            if phase == .active {
                refreshPermissionItems(withDelay: false)
            }
        }
    }

    private var categoryTabs: some View {
        HStack(spacing: metrics.compactPadding) {
            ForEach(SettingsCategory.allCases) { category in
                Button {
                    selectedCategory = category
                } label: {
                    Label(category.title(language: settings.language), systemImage: category.icon)
                        .appFont(.body, metrics: metrics)
                        .padding(.horizontal, metrics.compactPadding)
                        .padding(.vertical, metrics.compactPadding * 0.7)
                        .background(
                            RoundedRectangle(cornerRadius: metrics.cornerRadius)
                                .fill(selectedCategory == category ? Color.accentColor.opacity(0.16) : Color(nsColor: .controlBackgroundColor))
                        )
                }
                .buttonStyle(.plain)
            }
            Spacer()
        }
    }

    private var generalSection: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            AdaptiveStack(tier: metrics.layoutTier, spacing: metrics.rowSpacing) {
                Text(Localizer.text("settings.language", language: settings.language))
                    .appFont(.body, metrics: metrics)
                Picker("", selection: $settings.language) {
                    ForEach(AppLanguage.allCases) { language in
                        Text(language.displayName)
                            .appFont(.body, metrics: metrics)
                            .tag(language)
                    }
                }
                .labelsHidden()
                .pickerStyle(.segmented)
                .frame(maxWidth: metrics.layoutTier == .normal ? 260 : .infinity)
            }

            AdaptiveStack(tier: metrics.layoutTier, spacing: metrics.rowSpacing) {
                Text(Localizer.text("settings.appearance", language: settings.language))
                    .appFont(.body, metrics: metrics)
                Picker("", selection: $settings.appearance) {
                    ForEach(AppAppearance.allCases) { appearance in
                        Text(appearance.displayName(language: settings.language))
                            .appFont(.body, metrics: metrics)
                            .tag(appearance)
                    }
                }
                .labelsHidden()
                .pickerStyle(.segmented)
                .frame(maxWidth: metrics.layoutTier == .normal ? 280 : .infinity)
            }

            GroupBox(Localizer.text("settings.fontScaleTitle", language: settings.language)) {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    HStack {
                        Slider(
                            value: $uiFontScale,
                            in: 0.85...1.40,
                            step: 0.05
                        )
                        .onChange(of: uiFontScale) { value in
                            uiFontScale = min(max(value, 0.85), 1.40)
                        }

                        Text(String(format: "%.2fx", uiFontScale))
                            .appFont(.body, metrics: metrics)
                            .foregroundStyle(.secondary)
                            .frame(minWidth: 56, alignment: .trailing)
                    }

                    Text(Localizer.text("settings.fontScaleHint", language: settings.language))
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, metrics.compactPadding * 0.5)
            }

        }
    }

    private var advancedSection: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            Toggle(
                settings.language == .zhHans ? "动态分析前显示安全提示" : "Show safety prompt before dynamic analysis",
                isOn: $settings.showDynamicSafetyPrompt
            )
            .appFont(.body, metrics: metrics)

            Toggle(
                settings.language == .zhHans ? "动态分析中拒绝脚本执行（推荐）" : "Reject script execution in dynamic analysis (recommended)",
                isOn: Binding(
                    get: { !settings.allowNonAppDynamicExecution },
                    set: { settings.allowNonAppDynamicExecution = !$0 }
                )
            )
            .appFont(.body, metrics: metrics)

            Text(settings.language == .zhHans
                 ? "勾选后，动态模式会拒绝 shell/python/js/applescript 等脚本类型；如需运行，需先在此处取消勾选。"
                 : "When enabled, dynamic mode rejects shell/python/js/applescript files. Disable this option first if you need to run them.")
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)

            Toggle(
                Localizer.text("settings.backgroundLaunch", language: settings.language),
                isOn: $settings.preferBackgroundAppLaunch
            )
            .appFont(.body, metrics: metrics)

            Text(Localizer.text("settings.backgroundLaunchHint", language: settings.language))
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)

            GroupBox(settings.language == .zhHans ? "评分策略" : "Scoring Profile") {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    Picker("", selection: $settings.scoringProfile) {
                        ForEach(ScoringProfile.allCases) { profile in
                            Text(profile.displayName(language: settings.language)).tag(profile)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)

                    Text(settings.language == .zhHans
                         ? "乐观：降低风险分并提高判定阈值；均衡：默认策略；激进：提高风险分并降低阈值。"
                         : "Optimistic lowers scores and raises verdict thresholds; Balanced is default; Aggressive raises scores and lowers thresholds.")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, metrics.compactPadding * 0.4)
            }

            GroupBox(settings.language == .zhHans ? "全盘扫描性能" : "Full-Disk Scan Performance") {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    Stepper(
                        value: $settings.fullDiskScanMaxConcurrency,
                        in: 1...16,
                        step: 1
                    ) {
                        Text(settings.language == .zhHans
                             ? "并发分析任务数：\(settings.fullDiskScanMaxConcurrency)"
                             : "Concurrent analysis workers: \(settings.fullDiskScanMaxConcurrency)")
                            .appFont(.body, metrics: metrics)
                    }

                    Text(settings.language == .zhHans
                         ? "并发越高通常越快，但 CPU/内存占用也更高。若出现卡顿可适当调低。"
                         : "Higher concurrency is usually faster, but uses more CPU/memory. Lower it if scans feel unstable.")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, metrics.compactPadding * 0.4)
            }

            GroupBox(settings.language == .zhHans ? "应用更新" : "App Updates") {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    Toggle(
                        settings.language == .zhHans ? "自动检查并安装更新（实验）" : "Auto-check and install updates (experimental)",
                        isOn: $settings.autoCheckAndInstallUpdates
                    )
                    .appFont(.body, metrics: metrics)

                    Text(settings.language == .zhHans
                         ? "启用后会在启动时自动检查仓库最新稳定版（非 pre-release），若存在 app.zip 更新包则自动安装。"
                         : "When enabled, the app checks the latest stable (non-pre-release) version on startup and auto-installs when app.zip is available.")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, metrics.compactPadding * 0.4)
            }

            GroupBox(settings.language == .zhHans ? "AI 静态模型" : "AI Static Model") {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    Toggle(
                        settings.language == .zhHans ? "使用随机森林模型预测（WIP，重点参考）" : "Use Random-Forest Model Prediction (WIP, High Weight)",
                        isOn: $settings.useRandomForestPrediction
                    )
                    .appFont(.body, metrics: metrics)

                    Text(settings.language == .zhHans
                         ? "启用后会在静态分析、全盘扫描、Benchmark 中调用 Python 模型输出并参与综合评分。"
                         : "When enabled, static analysis/full-disk scan/benchmark will invoke the Python model and merge its output into final scoring.")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)

                    Text(settings.language == .zhHans
                         ? "提示：该模型仍在测试中，可能导致预测结果偏激进。"
                         : "Note: this model is still in testing and may produce more aggressive predictions.")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.orange)

                    Text(randomForestStatusLine)
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                .padding(.top, metrics.compactPadding * 0.4)
            }

            GroupBox(settings.language == .zhHans ? "日志设置" : "Logging") {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    HStack(spacing: metrics.rowSpacing) {
                        Text(settings.language == .zhHans ? "日志等级" : "Log Level")
                            .appFont(.body, metrics: metrics)
                        Picker("", selection: $settings.diagnosticsLogLevel) {
                            ForEach(LogLevel.allCases, id: \.self) { level in
                                Text(logLevelName(level)).tag(level)
                            }
                        }
                        .labelsHidden()
                        .frame(maxWidth: 220)
                    }

                    Stepper(
                        value: $settings.diagnosticsLogMaxEntries,
                        in: 200...20000,
                        step: 100
                    ) {
                        Text(settings.language == .zhHans
                             ? "最大日志条数：\(settings.diagnosticsLogMaxEntries)"
                             : "Max log entries: \(settings.diagnosticsLogMaxEntries)")
                            .appFont(.body, metrics: metrics)
                    }

                    HStack(spacing: metrics.rowSpacing) {
                        Button(settings.language == .zhHans ? "导出日志" : "Export Logs") {
                            viewModel.exportDiagnostics(includeDebug: settings.diagnosticsLogLevel == .debug)
                        }
                        .buttonStyle(.bordered)

                        Button(settings.language == .zhHans ? "清空内存日志" : "Clear In-memory Logs") {
                            DiagnosticsLogService.shared.clear()
                        }
                        .buttonStyle(.bordered)
                    }
                }
                .padding(.top, metrics.compactPadding * 0.4)
            }

            GroupBox(Localizer.text("welcome.permissionHealth", language: settings.language)) {
                VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                    ForEach(permissionItems) { item in
                        HStack(alignment: .top, spacing: metrics.rowSpacing) {
                            Image(systemName: statusSymbol(item.status))
                                .foregroundStyle(statusColor(item.status))
                                .frame(width: metrics.scaled(16))
                                .appFont(.body, metrics: metrics)

                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(item.title)
                                        .appFont(.body, metrics: metrics)
                                    Text(statusLabel(item.status))
                                        .appFont(.caption, metrics: metrics)
                                        .foregroundStyle(statusColor(item.status))
                                }
                                Text(item.impact)
                                    .appFont(.caption, metrics: metrics)
                                    .foregroundStyle(.secondary)
                            }

                            Spacer()

                            if item.status == .notGranted {
                                Button(Localizer.text("welcome.permissionAction", language: settings.language)) {
                                    PermissionGuidanceService.performAction(item.action)
                                    refreshPermissionItems(withDelay: true)
                                }
                                .buttonStyle(.bordered)
                                .frame(minHeight: metrics.controlHeight)
                            }
                        }
                    }

                    Text(Localizer.text("settings.permissionsOnlyWhenMissing", language: settings.language))
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 4)
            }

            Text(Localizer.text("settings.experimental", language: settings.language))
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.orange)
        }
    }

    private var aboutSection: some View {
        GroupBox(settings.language == .zhHans ? "关于与发布信息" : "About & Release Notes") {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 4) {
                    Text(settings.language == .zhHans ? "版本：" : "Version: ")
                        .appFont(.footnote, metrics: metrics)
                    Text(appVersionText)
                        .appFont(.footnote, metrics: metrics)
                        .fontWeight(.semibold)
                }

                Text(settings.language == .zhHans ? "更新日志（v1）：静态分析、受限动态观察、风险解释、历史记录、报告导出、Benchmark 评测。" : "Changelog (v1): static analysis, restricted dynamic observation, risk explanation, history, report export, benchmark evaluation.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                Text(settings.language == .zhHans ? "隐私说明：默认本地分析，不上传样本到云端；若后续引入联网能力会单独告知。" : "Privacy: analysis is local by default, no sample upload. Any future cloud feature will be explicitly disclosed.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                Divider()
                    .padding(.vertical, 2)

                Link(destination: updateManager.repositoryURL) {
                    Text(settings.language == .zhHans
                         ? "项目仓库：\(updateManager.repositoryURL.absoluteString)"
                         : "Repository: \(updateManager.repositoryURL.absoluteString)")
                        .appFont(.footnote, metrics: metrics)
                }

                HStack(spacing: metrics.rowSpacing) {
                    Button(settings.language == .zhHans ? "检查更新" : "Check for Updates") {
                        updateManager.triggerManualUpdateCheck()
                    }
                    .buttonStyle(.bordered)
                    .disabled(updateManager.isChecking || updateManager.isInstalling)

                    Button(settings.language == .zhHans ? "安装更新" : "Install Update") {
                        updateManager.triggerManualInstallIfAvailable()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!updateManager.updateAvailable || updateManager.isChecking || updateManager.isInstalling)
                }

                Text(updateManager.statusMessage)
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 4)
        }
    }

    private var developerSection: some View {
        GroupBox(settings.language == .zhHans ? "开发者模式（内部）" : "Developer Mode (Internal)") {
            VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                Text(settings.language == .zhHans
                     ? "Internal • Benchmark Tools • Developer Only。仅供内部评测验证使用。"
                     : "Internal • Benchmark Tools • Developer Only. Internal evaluation only.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                Toggle(
                    settings.language == .zhHans ? "启用开发者模式" : "Enable Developer Mode",
                    isOn: Binding(
                        get: { settings.developerModeEnabled },
                        set: { settings.setDeveloperModeEnabled($0) }
                    )
                )
                .appFont(.body, metrics: metrics)

                if settings.developerModeEnabled {
                    Divider()
                    DeveloperBenchmarkPanelView(settings: settings, viewModel: viewModel, metrics: metrics)
                } else {
                    Text(settings.language == .zhHans
                         ? "启用后将显示 Benchmark / Evaluation / Regression 工具面板。"
                         : "Enable to reveal Benchmark / Evaluation / Regression tools.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.top, 4)
        }
    }

    private var appVersionText: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "1.0.0beta1"
        let build = info?["CFBundleVersion"] as? String ?? "1"
        return "\(version) (\(build))"
    }

    private func refreshPermissionItems(withDelay: Bool) {
        if withDelay {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                permissionItems = PermissionGuidanceService.permissionHealthItems(
                    language: settings.language,
                    includeAccessibility: false,
                    includeAutomation: false
                )
            }
            return
        }
        permissionItems = PermissionGuidanceService.permissionHealthItems(
            language: settings.language,
            includeAccessibility: false,
            includeAutomation: false
        )
    }

    private func statusSymbol(_ status: PermissionHealthStatus) -> String {
        switch status {
        case .granted:
            return "checkmark.circle.fill"
        case .notGranted:
            return "xmark.circle.fill"
        case .unknown:
            return "questionmark.circle.fill"
        }
    }

    private func statusColor(_ status: PermissionHealthStatus) -> Color {
        switch status {
        case .granted:
            return .green
        case .notGranted:
            return .orange
        case .unknown:
            return .secondary
        }
    }

    private func statusLabel(_ status: PermissionHealthStatus) -> String {
        switch status {
        case .granted:
            return Localizer.text("welcome.permissionGrantedMark", language: settings.language)
        case .notGranted:
            return Localizer.text("welcome.permissionMissingMark", language: settings.language)
        case .unknown:
            return Localizer.text("welcome.permissionUnknownMark", language: settings.language)
        }
    }

    private func logLevelName(_ level: LogLevel) -> String {
        switch (level, settings.language) {
        case (.debug, .zhHans):
            return "调试"
        case (.info, .zhHans):
            return "信息"
        case (.warning, .zhHans):
            return "警告"
        case (.error, .zhHans):
            return "错误"
        case (.debug, .en):
            return "Debug"
        case (.info, .en):
            return "Info"
        case (.warning, .en):
            return "Warning"
        case (.error, .en):
            return "Error"
        }
    }

    private var randomForestStatusLine: String {
        let candidates = RandomForestModelService.shared.modelCandidates()
        if candidates.isEmpty {
            return settings.language == .zhHans
                ? "当前未检测到可用 .joblib（请到“配置文件”页上传核心文件）。"
                : "No .joblib model found (upload one in Config Profiles)."
        }
        if candidates.count == 1, let only = candidates.first {
            return settings.language == .zhHans
                ? "当前模型：\(only.lastPathComponent)"
                : "Active model: \(only.lastPathComponent)"
        }
        return settings.language == .zhHans
            ? "检测到 \(candidates.count) 个 .joblib。脚本会报错，请仅保留一个。"
            : "Detected \(candidates.count) .joblib files. Keep only one to avoid runtime errors."
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: CGFloat(uiFontScale))
    }
}
