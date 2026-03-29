import SwiftUI
import AppKit
import UniformTypeIdentifiers

@MainActor
private enum AppIconStore {
    static let cache = NSCache<NSString, NSImage>()

    static func icon(for appPath: String) -> NSImage {
        let key = appPath as NSString
        if let cached = cache.object(forKey: key) {
            return cached
        }
        let icon = NSWorkspace.shared.icon(forFile: appPath)
        cache.setObject(icon, forKey: key)
        return icon
    }
}

struct AppLauncherView: View {
    @ObservedObject var settings: AppSettingsStore
    @Environment(\.appFontScale) private var appFontScale

    @State private var appList: [LaunchableAppInfo] = []
    @State private var searchText = ""
    @State private var presetMap: [String: AppLaunchPreset] = [:]
    @State private var selectedApp: LaunchableAppInfo?
    @State private var editingPreset: AppLaunchPreset?
    @State private var noticeText: String?
    @State private var isLoadingApps = false
    @State private var hasLoadedOnce = false
    @State private var launchingAppPaths: Set<String> = []
    @State private var relaunchPrompt: RelaunchPromptContext?

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            HStack(spacing: metrics.compactPadding) {
                Text(settings.language == .zhHans ? "启动 App" : "Launch App")
                    .appFont(.headline, metrics: metrics)
                Spacer()

                Button(settings.language == .zhHans ? "导入 App" : "Import App") {
                    importCustomApps()
                }
                .buttonStyle(.bordered)
                .appFont(.body, metrics: metrics)

                Button(settings.language == .zhHans ? "刷新列表" : "Refresh") {
                    reloadApps(forceRefresh: true)
                }
                .buttonStyle(.bordered)
                .appFont(.body, metrics: metrics)
            }

            if let noticeText {
                Text(noticeText)
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: metrics.compactPadding) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                    .font(.system(size: metrics.scaled(13), weight: .regular))

                TextField(
                    settings.language == .zhHans ? "搜索 App 名称 / Bundle ID / 路径" : "Search app name / bundle ID / path",
                    text: $searchText
                )
                .textFieldStyle(.plain)
                .appFont(.body, metrics: metrics)

                if !searchText.isEmpty {
                    Button {
                        searchText = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                            .font(.system(size: metrics.scaled(13), weight: .regular))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, metrics.compactPadding)
            .padding(.vertical, metrics.compactPadding * 0.65)
            .appGlassPanel(metrics: metrics, interactive: true)

            if isLoadingApps {
                HStack(spacing: metrics.rowSpacing) {
                    ProgressView()
                        .controlSize(.small)
                    Text(settings.language == .zhHans ? "正在扫描 App..." : "Scanning apps...")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
            }

            List {
                if filteredAppList.isEmpty {
                    Text(settings.language == .zhHans ? "没有匹配的 App" : "No matching apps")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, metrics.compactPadding)
                        .listRowSeparator(.hidden)
                }

                ForEach(filteredAppList) { app in
                    appCard(for: app)
                        .listRowInsets(
                            EdgeInsets(
                                top: metrics.compactPadding * 0.4,
                                leading: 0,
                                bottom: metrics.compactPadding * 0.4,
                                trailing: 0
                            )
                        )
                        .listRowSeparator(.hidden)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
        }
        .onAppear {
            guard !hasLoadedOnce else { return }
            hasLoadedOnce = true
            reloadApps(forceRefresh: false)
        }
        .sheet(item: $selectedApp) { app in
            AppPresetEditorSheet(
                settings: settings,
                app: app,
                preset: editingPreset ?? AppLaunchPreset.default(for: app),
                onSave: { preset in
                    var saved = preset
                    saved.updatedAt = Date()
                    AppLaunchService.shared.savePreset(saved)
                    presetMap[app.appPath] = saved

                    let configuredDylibs = AppLaunchService.shared.configuredDylibPaths(for: saved)
                    let resolvedDylibs = AppLaunchService.shared.resolveDylibPaths(for: saved)
                    ConfigProfileService.shared.appendOrUpdateAppRule(
                        bundleIdentifier: app.bundleIdentifier,
                        dylibPaths: configuredDylibs
                    )
                    DiagnosticsLogService.shared.log(
                        .info,
                        category: "app.launch.preset",
                        "Saved preset for \(app.bundleIdentifier), configured=\(configuredDylibs.count), resolved=\(resolvedDylibs.count)"
                    )
                    noticeText = settings.language == .zhHans
                        ? "已保存 \(app.displayName) 的启动预设。"
                        : "Saved launch preset for \(app.displayName)."
                },
                onPersist: { preset in
                    do {
                        try AppLaunchService.shared.persistPresetIntoApp(preset)
                        DiagnosticsLogService.shared.log(
                            .warning,
                            category: "app.launch.persist",
                            "Persisted launch preset into app bundle: \(preset.appPath)"
                        )
                        noticeText = settings.language == .zhHans
                            ? "已将预设持久化到目标 App（可在面板里一键还原）。"
                            : "Preset has been persisted into the target app (reversible from this panel)."
                    } catch {
                        DiagnosticsLogService.shared.log(
                            .error,
                            category: "app.launch.persist",
                            "Persist failed: \(error.localizedDescription)"
                        )
                        noticeText = settings.language == .zhHans
                            ? "持久化失败：\(error.localizedDescription)"
                            : "Persist failed: \(error.localizedDescription)"
                    }
                },
                onRestore: {
                    do {
                        try AppLaunchService.shared.restorePersistedApp(appPath: app.appPath)
                        DiagnosticsLogService.shared.log(
                            .info,
                            category: "app.launch.persist",
                            "Restored app executable: \(app.appPath)"
                        )
                        noticeText = settings.language == .zhHans
                            ? "已还原目标 App 到未注入状态。"
                            : "Restored target app to clean non-injected state."
                    } catch {
                        DiagnosticsLogService.shared.log(
                            .error,
                            category: "app.launch.persist",
                            "Restore failed: \(error.localizedDescription)"
                        )
                        noticeText = settings.language == .zhHans
                            ? "还原失败：\(error.localizedDescription)"
                            : "Restore failed: \(error.localizedDescription)"
                    }
                }
            )
        }
        .alert(item: $relaunchPrompt) { prompt in
            Alert(
                title: Text(settings.language == .zhHans ? "App 已在运行" : "App Is Already Running"),
                message: Text(
                    settings.language == .zhHans
                        ? "\(prompt.app.displayName) 当前在后台运行（PID \(prompt.runningPID ?? -1)）。是否终止当前进程并按当前注入配置重新启动？"
                        : "\(prompt.app.displayName) is already running (PID \(prompt.runningPID ?? -1)). Terminate it and relaunch with current injected configuration?"
                ),
                primaryButton: .destructive(Text(settings.language == .zhHans ? "终止并重启" : "Terminate & Relaunch")) {
                    relaunchWithTermination(prompt)
                },
                secondaryButton: .cancel(Text(settings.language == .zhHans ? "取消" : "Cancel"))
            )
        }
    }

    private func appCard(for app: LaunchableAppInfo) -> some View {
        let preset = presetMap[app.appPath] ?? AppLaunchService.shared.preset(for: app)
        let persisted = AppLaunchService.shared.isAppPersisted(appPath: app.appPath)
        let isLaunching = launchingAppPaths.contains(app.appPath) || AppLaunchService.shared.isLaunchInProgress(appPath: app.appPath)

        return HStack(spacing: metrics.compactPadding) {
            Image(nsImage: AppIconStore.icon(for: app.appPath))
                .resizable()
                .frame(width: metrics.scaled(38), height: metrics.scaled(38))
                .cornerRadius(metrics.scaled(9))

            VStack(alignment: .leading, spacing: metrics.scaled(3)) {
                Text(app.displayName)
                    .appFont(.body, metrics: metrics)
                    .fontWeight(.semibold)
                    .lineLimit(2)
                    .truncationMode(.tail)

                Text(app.bundleIdentifier)
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)

                if let preset {
                    Text(presetSummary(preset))
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }

                if persisted {
                    Text(settings.language == .zhHans ? "已持久化注入（可还原）" : "Persisted injection active (restorable)")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.orange)
                        .lineLimit(1)
                }
            }

            Spacer(minLength: metrics.scaled(8))

            Button(isLaunching ? (settings.language == .zhHans ? "启动中..." : "Launching...") : (settings.language == .zhHans ? "启动" : "Launch")) {
                launch(app: app)
            }
            .appPrimaryButtonStyle()
            .disabled(isLaunching)
            .appFont(.body, metrics: metrics)

            Button {
                selectedApp = app
                editingPreset = presetMap[app.appPath] ?? AppLaunchService.shared.preset(for: app) ?? AppLaunchPreset.default(for: app)
            } label: {
                Image(systemName: "gearshape")
                    .font(.system(size: metrics.scaled(15), weight: .medium))
            }
            .buttonStyle(.bordered)
        }
        .padding(metrics.compactPadding)
        .frame(minHeight: metrics.scaled(80), alignment: .leading)
        .appGlassPanel(metrics: metrics, interactive: true)
    }

    private func presetSummary(_ preset: AppLaunchPreset) -> String {
        if preset.useSandboxExec {
            return settings.language == .zhHans ? "Sandbox 隔离启动（sandbox-exec）" : "Sandbox-isolated launch (sandbox-exec)"
        }
        if preset.useSafeMode, !preset.useCustomMode {
            return settings.language == .zhHans ? "安全模式：sandbox_prompt_full.dylib" : "Safe mode: sandbox_prompt_full.dylib"
        }
        if preset.useCustomMode {
            let builtIn = preset.selectedOptions.map { $0.dylibName }
            let total = builtIn.count + preset.customDylibPaths.count
            return settings.language == .zhHans
                ? "自定义注入：\(total) 个 dylib"
                : "Custom injection: \(total) dylibs"
        }
        return settings.language == .zhHans ? "普通启动（不注入）" : "Normal launch (no injection)"
    }

    private var filteredAppList: [LaunchableAppInfo] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return appList }
        return appList.filter { app in
            app.displayName.localizedCaseInsensitiveContains(query)
                || app.bundleIdentifier.localizedCaseInsensitiveContains(query)
                || app.appPath.localizedCaseInsensitiveContains(query)
        }
    }

    private func reloadApps(forceRefresh: Bool) {
        guard !isLoadingApps else { return }
        isLoadingApps = true

        Task.detached(priority: .userInitiated) {
            let apps = AppLaunchService.shared.scanCommonAppDirectories(forceRefresh: forceRefresh)
            let presets = AppLaunchService.shared.loadPresets()
            let map = Dictionary(uniqueKeysWithValues: presets.map { ($0.appPath, $0) })

            await MainActor.run {
                self.appList = apps
                self.presetMap = map
                self.isLoadingApps = false
                self.noticeText = self.settings.language == .zhHans
                    ? "已扫描到 \(apps.count) 个 App。"
                    : "Scanned \(apps.count) apps."
                DiagnosticsLogService.shared.log(.info, category: "app.launch.scan", "Scanned installed apps count=\(apps.count)")
            }
        }
    }

    private func importCustomApps() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowedContentTypes = [.applicationBundle]
        panel.title = settings.language == .zhHans ? "选择要导入的 App" : "Choose apps to import"
        panel.prompt = settings.language == .zhHans ? "导入" : "Import"

        panel.begin { response in
            guard response == .OK else { return }
            let imported = AppLaunchService.shared.importCustomApps(urls: panel.urls)
            reloadApps(forceRefresh: true)
            noticeText = settings.language == .zhHans
                ? "已导入 \(imported.count) 个 App。"
                : "Imported \(imported.count) apps."
            DiagnosticsLogService.shared.log(.info, category: "app.launch.import", "Imported apps count=\(imported.count)")
        }
    }

    private func launch(app: LaunchableAppInfo) {
        let launchPreset = presetMap[app.appPath] ?? AppLaunchService.shared.preset(for: app) ?? AppLaunchPreset.default(for: app)
        guard !launchingAppPaths.contains(app.appPath) else { return }
        launchingAppPaths.insert(app.appPath)

        Task.detached(priority: .userInitiated) {
            let launch = AppLaunchService.shared.launch(app: app, preset: launchPreset)
            await MainActor.run {
                launchingAppPaths.remove(app.appPath)
                if launch.launchSucceeded {
                    DiagnosticsLogService.shared.log(
                        .info,
                        category: "app.launch",
                        "Launched app \(app.bundleIdentifier) pid=\(launch.mainPID ?? -1) mode=\(launch.launchMode)"
                    )
                    noticeText = settings.language == .zhHans
                        ? "已启动 \(app.displayName) (PID \(launch.mainPID ?? -1))"
                        : "Launched \(app.displayName) (PID \(launch.mainPID ?? -1))"
                } else {
                    if shouldPromptTerminateAndRelaunch(for: launch, preset: launchPreset) {
                        relaunchPrompt = RelaunchPromptContext(
                            app: app,
                            preset: launchPreset,
                            runningPID: launch.mainPID
                        )
                        noticeText = settings.language == .zhHans
                            ? "\(app.displayName) 已在运行，等待你确认是否终止并重启。"
                            : "\(app.displayName) is already running. Waiting for your confirmation to terminate and relaunch."
                        return
                    }

                    DiagnosticsLogService.shared.log(
                        .error,
                        category: "app.launch",
                        "Launch failed for \(app.bundleIdentifier): \(launch.warning ?? "unknown")"
                    )
                    noticeText = settings.language == .zhHans
                        ? "启动失败：\(launch.warning ?? "未知错误")"
                        : "Launch failed: \(launch.warning ?? "unknown error")"
                }
            }
        }
    }

    private func shouldPromptTerminateAndRelaunch(for result: DylibInjectedLaunchResult, preset: AppLaunchPreset) -> Bool {
        guard !result.launchSucceeded else { return false }
        guard result.mainPID != nil else { return false }
        let usesSpecialLaunch = preset.useSandboxExec || !AppLaunchService.shared.resolveDylibPaths(for: preset).isEmpty
        guard usesSpecialLaunch else { return false }
        let warning = result.warning?.lowercased() ?? ""
        return warning.contains("already running")
    }

    private func relaunchWithTermination(_ prompt: RelaunchPromptContext) {
        guard !launchingAppPaths.contains(prompt.app.appPath) else { return }
        launchingAppPaths.insert(prompt.app.appPath)

        Task.detached(priority: .userInitiated) {
            let result = AppLaunchService.shared.relaunchAfterTerminatingRunningApp(
                app: prompt.app,
                preset: prompt.preset
            )

            await MainActor.run {
                launchingAppPaths.remove(prompt.app.appPath)
                if result.launchSucceeded {
                    DiagnosticsLogService.shared.log(
                        .warning,
                        category: "app.launch",
                        "Terminated and relaunched \(prompt.app.bundleIdentifier) pid=\(result.mainPID ?? -1)"
                    )
                    noticeText = settings.language == .zhHans
                        ? "已终止旧进程并重新启动 \(prompt.app.displayName) (PID \(result.mainPID ?? -1))"
                        : "Terminated previous process and relaunched \(prompt.app.displayName) (PID \(result.mainPID ?? -1))"
                } else {
                    DiagnosticsLogService.shared.log(
                        .error,
                        category: "app.launch",
                        "Terminate-and-relaunch failed for \(prompt.app.bundleIdentifier): \(result.warning ?? "unknown")"
                    )
                    noticeText = settings.language == .zhHans
                        ? "终止并重启失败：\(result.warning ?? "未知错误")"
                        : "Terminate/relaunch failed: \(result.warning ?? "unknown error")"
                }
            }
        }
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: appFontScale)
    }
}

private struct RelaunchPromptContext: Identifiable {
    let id = UUID()
    let app: LaunchableAppInfo
    let preset: AppLaunchPreset
    let runningPID: Int?
}

private struct AppPresetEditorSheet: View {
    @ObservedObject var settings: AppSettingsStore
    let app: LaunchableAppInfo
    @State var preset: AppLaunchPreset

    var onSave: (AppLaunchPreset) -> Void
    var onPersist: (AppLaunchPreset) -> Void
    var onRestore: () -> Void

    @State private var confirmPersist = false
    @Environment(\.dismiss) private var dismiss
    @Environment(\.appFontScale) private var appFontScale

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            HStack {
                Text(settings.language == .zhHans ? "App 启动配置" : "App Launch Settings")
                    .appFont(.headline, metrics: metrics)
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: metrics.scaled(19), weight: .medium))
                }
                .buttonStyle(.plain)
            }

            Text("\(app.displayName)  •  \(app.bundleIdentifier)")
                .appFont(.caption, metrics: metrics)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)

            Toggle(
                settings.language == .zhHans
                    ? "启用安全模式启动（sandbox_prompt_full.dylib）"
                    : "Enable safe mode launch (sandbox_prompt_full.dylib)",
                isOn: Binding(
                    get: { preset.useSafeMode },
                    set: { newValue in
                        preset.useSafeMode = newValue
                        if newValue {
                            preset.useCustomMode = false
                            preset.useSandboxExec = false
                        }
                    }
                )
            )
            .appFont(.body, metrics: metrics)

            Toggle(
                settings.language == .zhHans
                    ? "启用 sandbox-exec 隔离启动（与安全模式二选一）"
                    : "Enable sandbox-exec isolated launch (mutually exclusive with safe mode)",
                isOn: Binding(
                    get: { preset.useSandboxExec },
                    set: { newValue in
                        preset.useSandboxExec = newValue
                        if newValue {
                            preset.useSafeMode = false
                            preset.useCustomMode = false
                        }
                    }
                )
            )
            .appFont(.body, metrics: metrics)

            Toggle(
                settings.language == .zhHans
                    ? "自定义注入（勾选后关闭安全模式）"
                    : "Custom injection (disables safe mode)",
                isOn: Binding(
                    get: { preset.useCustomMode },
                    set: { newValue in
                        preset.useCustomMode = newValue
                        if newValue {
                            preset.useSafeMode = false
                            preset.useSandboxExec = false
                        }
                    }
                )
            )
            .appFont(.body, metrics: metrics)

            if preset.useCustomMode {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: metrics.rowSpacing * 0.8) {
                        ForEach(AppLaunchOption.allCases) { option in
                            Toggle(option.title(language: settings.language), isOn: Binding(
                                get: { preset.selectedOptions.contains(option) },
                                set: { newValue in
                                    if newValue {
                                        if !preset.selectedOptions.contains(option) {
                                            preset.selectedOptions.append(option)
                                        }
                                    } else {
                                        preset.selectedOptions.removeAll { $0 == option }
                                    }
                                }
                            ))
                            .appFont(.footnote, metrics: metrics)
                        }
                    }
                }
                .frame(maxHeight: metrics.scaled(220))

                HStack(spacing: metrics.compactPadding) {
                    Button(settings.language == .zhHans ? "导入动态运行库" : "Import Dylib") {
                        let panel = NSOpenPanel()
                        panel.allowsMultipleSelection = true
                        panel.canChooseDirectories = false
                        panel.canChooseFiles = true
                        if let dylibType = UTType(filenameExtension: "dylib") {
                            panel.allowedContentTypes = [dylibType]
                        }
                        panel.title = settings.language == .zhHans ? "选择自定义 .dylib 文件" : "Select custom .dylib files"
                        panel.prompt = settings.language == .zhHans ? "导入" : "Import"
                        panel.begin { response in
                            guard response == .OK else { return }
                            let paths = panel.urls.map { $0.path }
                            for path in paths where !preset.customDylibPaths.contains(path) {
                                preset.customDylibPaths.append(path)
                            }
                        }
                    }
                    .buttonStyle(.bordered)
                    .appFont(.body, metrics: metrics)

                    Spacer()
                }

                if !preset.customDylibPaths.isEmpty {
                    VStack(alignment: .leading, spacing: metrics.scaled(4)) {
                        Text(settings.language == .zhHans ? "已导入的自定义 dylib" : "Imported custom dylibs")
                            .appFont(.caption, metrics: metrics)
                            .foregroundStyle(.secondary)
                        ForEach(preset.customDylibPaths, id: \.self) { path in
                            Text(path)
                                .appFont(.footnote, metrics: metrics)
                                .textSelection(.enabled)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                }
            }

            Spacer()

            HStack(spacing: 10) {
                Button(settings.language == .zhHans ? "还原 App" : "Restore App") {
                    onRestore()
                }
                .buttonStyle(.bordered)
                .appFont(.body, metrics: metrics)

                Spacer()

                Button(settings.language == .zhHans ? "将选项持久化到 App" : "Persist options to App") {
                    confirmPersist = true
                }
                .buttonStyle(.bordered)
                .tint(.gray)
                .appFont(.body, metrics: metrics)

                Button(settings.language == .zhHans ? "保存" : "Save") {
                    onSave(preset)
                    dismiss()
                }
                .appPrimaryButtonStyle()
                .appFont(.body, metrics: metrics)
            }
        }
        .padding(metrics.cardPadding)
        .frame(minWidth: 640, minHeight: 540, alignment: .topLeading)
        .appFont(.body, metrics: metrics)
        .alert(
            settings.language == .zhHans ? "确认修改目标 App" : "Confirm Target App Modification",
            isPresented: $confirmPersist
        ) {
            Button(settings.language == .zhHans ? "取消" : "Cancel", role: .cancel) {}
            Button(settings.language == .zhHans ? "确认持久化" : "Confirm Persist", role: .destructive) {
                onPersist(preset)
            }
        } message: {
            Text(
                settings.language == .zhHans
                    ? "该操作会改写目标 App 的可执行文件并可能破坏代码签名。可通过“还原 App”一键回滚。确认继续？"
                    : "This operation rewrites the target app executable and may break code signing. It is reversible via 'Restore App'. Continue?"
            )
        }
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: appFontScale)
    }
}
