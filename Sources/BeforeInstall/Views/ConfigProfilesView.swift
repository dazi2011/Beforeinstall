import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct ConfigProfilesView: View {
    @ObservedObject var settings: AppSettingsStore
    @Environment(\.appFontScale) private var appFontScale

    @State private var profiles: [ConfigProfileSummary] = []
    @State private var activeProfileID: String = "default"
    @State private var contentText: String = ""
    @State private var statusText: String?

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            HStack(spacing: metrics.compactPadding) {
                Text(settings.language == .zhHans ? "配置文件" : "Config Profiles")
                    .appFont(.headline, metrics: metrics)
                Spacer()

                Button(settings.language == .zhHans ? "上传配置文件" : "Upload Config File") {
                    uploadProfile()
                }
                .buttonStyle(.bordered)
                .appFont(.body, metrics: metrics)

                Button(settings.language == .zhHans ? "上传 joblib 核心" : "Upload joblib Core") {
                    uploadJoblibCore()
                }
                .buttonStyle(.bordered)
                .appFont(.body, metrics: metrics)

                Button(settings.language == .zhHans ? "刷新" : "Refresh") {
                    reloadProfiles()
                }
                .buttonStyle(.bordered)
                .appFont(.body, metrics: metrics)
            }

            HStack(spacing: metrics.compactPadding) {
                Text(settings.language == .zhHans ? "当前配置" : "Active Profile")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                Picker("", selection: $activeProfileID) {
                    ForEach(profiles) { profile in
                        Text(profile.name).tag(profile.id)
                    }
                }
                .labelsHidden()
                .frame(maxWidth: 260)
                .onChange(of: activeProfileID) { newValue in
                    ConfigProfileService.shared.setActiveProfileID(newValue)
                    loadActiveProfileContent()
                    DiagnosticsLogService.shared.log(.info, category: "config.profile", "Switched active profile to \(newValue)")
                }

                Button(settings.language == .zhHans ? "应用全局设置" : "Apply Global Settings") {
                    ConfigProfileService.shared.applyGlobalsOfActiveProfile(to: settings)
                    DiagnosticsLogService.shared.log(.info, category: "config.profile", "Applied global settings from active profile")
                    statusText = settings.language == .zhHans ? "已将配置文件中的 global 设置应用到 App。" : "Applied [global] settings to app."
                }
                .buttonStyle(.bordered)
                .appFont(.body, metrics: metrics)

                Button(settings.language == .zhHans ? "在访达中显示" : "Show in Finder") {
                    revealActiveProfileInFinder()
                }
                .buttonStyle(.bordered)
                .appFont(.body, metrics: metrics)

                Button(settings.language == .zhHans ? "保存并应用" : "Save & Apply") {
                    do {
                        try ConfigProfileService.shared.saveProfileContent(profileID: activeProfileID, content: contentText)
                        ConfigProfileService.shared.applyGlobalsOfActiveProfile(to: settings)
                        DiagnosticsLogService.shared.log(.info, category: "config.profile", "Saved profile \(activeProfileID)")
                        statusText = settings.language == .zhHans ? "配置已保存并应用。" : "Profile saved and applied."
                        reloadProfiles()
                    } catch {
                        DiagnosticsLogService.shared.log(.error, category: "config.profile", "Profile save failed: \(error.localizedDescription)")
                        statusText = settings.language == .zhHans ? "保存失败：\(error.localizedDescription)" : "Save failed: \(error.localizedDescription)"
                    }
                }
                .appPrimaryButtonStyle()
                .appFont(.body, metrics: metrics)
            }

            if let statusText {
                Text(statusText)
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }

            GroupBox(settings.language == .zhHans ? "随机森林核心模型" : "Random-Forest Core Model") {
                VStack(alignment: .leading, spacing: 6) {
                    Text(activeModelStatusText)
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    Text(settings.language == .zhHans
                         ? "上传后会替换运行目录中的 .joblib 核心文件；若存在多个 .joblib，Python 侧会拒绝预测。"
                         : "Uploading replaces the runtime .joblib core file. If multiple .joblib files exist, Python prediction will fail.")
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 4)
            }

            GroupBox(settings.language == .zhHans ? "配置内容" : "Profile Content") {
                TextEditor(text: $contentText)
                    .appFont(.monospacedBody, metrics: metrics)
                    .frame(minHeight: metrics.scaled(360))
                    .padding(metrics.compactPadding)
                    .appGlassPanel(metrics: metrics, interactive: true, cornerRadius: metrics.scaled(14))
                    .padding(.top, 6)
            }
            .appFont(.body, metrics: metrics)

            GroupBox(settings.language == .zhHans ? "语法说明" : "Syntax") {
                VStack(alignment: .leading, spacing: 6) {
                    Text(settings.language == .zhHans
                         ? "全局段： [global]，使用 key=value 映射 App 菜单设置。"
                         : "Global block: [global], use key=value to map app menu settings.")
                    Text(settings.language == .zhHans
                         ? "规则段： [rules]，除 APP 外每行 TYPE,value,notice|ignore。"
                         : "Rule block: [rules], each line is TYPE,value,notice|ignore except APP.")
                    Text(settings.language == .zhHans
                         ? "支持：RULE / RULE-FILE / RULE-HASH / RULE-URL / RULE-IP / RULE-REGEXP / RULE-PATH-PREFIX / APP。APP 行格式为 APP,bundle.id,/path/a.dylib&&/path/b.dylib。"
                         : "Supported: RULE / RULE-FILE / RULE-HASH / RULE-URL / RULE-IP / RULE-REGEXP / RULE-PATH-PREFIX / APP. APP line format: APP,bundle.id,/path/a.dylib&&/path/b.dylib.")
                    Text(settings.language == .zhHans
                         ? "覆盖冲突策略：按命中粒度合并；同粒度冲突优先级为 规则类型精度 > 行号（更靠上） > ignore。"
                         : "Conflict strategy: hit-level merge; precedence is rule specificity > line order (top) > ignore.")
                    Text(settings.language == .zhHans
                         ? "默认规则为 RULE-FILE,<统一威胁规则文件路径>,notice。"
                         : "Default rule: RULE-FILE,<unified threat profile path>,notice.")
                }
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 4)
            }
            .appFont(.body, metrics: metrics)
        }
        .appFont(.body, metrics: metrics)
        .onAppear {
            ConfigProfileService.shared.ensureDefaultProfileExists(ruleFilePath: ThreatIntelDictionaryManager.shared.activeRuleFileURL().path)
            reloadProfiles()
            activeProfileID = ConfigProfileService.shared.activeProfileID()
            loadActiveProfileContent()
        }
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: appFontScale)
    }

    private func reloadProfiles() {
        profiles = ConfigProfileService.shared.listProfiles()
        if !profiles.contains(where: { $0.id == activeProfileID }) {
            activeProfileID = ConfigProfileService.shared.activeProfileID()
        }
    }

    private func loadActiveProfileContent() {
        contentText = ConfigProfileService.shared.loadProfileContent(profileID: activeProfileID)
        if contentText.isEmpty, activeProfileID == "default" {
            ConfigProfileService.shared.ensureDefaultProfileExists(ruleFilePath: ThreatIntelDictionaryManager.shared.activeRuleFileURL().path)
            contentText = ConfigProfileService.shared.loadProfileContent(profileID: activeProfileID)
        }
    }

    private func uploadProfile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.title = settings.language == .zhHans ? "选择配置文件" : "Select profile file"
        panel.prompt = settings.language == .zhHans ? "上传" : "Upload"

        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            do {
                let imported = try ConfigProfileService.shared.importProfile(from: url)
                activeProfileID = imported.id
                ConfigProfileService.shared.setActiveProfileID(imported.id)
                reloadProfiles()
                loadActiveProfileContent()
                DiagnosticsLogService.shared.log(.info, category: "config.profile", "Imported profile \(imported.id)")
                statusText = settings.language == .zhHans ? "已导入配置：\(imported.name)" : "Imported profile: \(imported.name)"
            } catch {
                DiagnosticsLogService.shared.log(.error, category: "config.profile", "Import profile failed: \(error.localizedDescription)")
                statusText = settings.language == .zhHans ? "导入失败：\(error.localizedDescription)" : "Import failed: \(error.localizedDescription)"
            }
        }
    }

    private func revealActiveProfileInFinder() {
        guard let profile = profiles.first(where: { $0.id == activeProfileID }) else { return }
        let url = URL(fileURLWithPath: profile.filePath)
        NSWorkspace.shared.activateFileViewerSelecting([url])
        DiagnosticsLogService.shared.log(.info, category: "config.profile", "Revealed profile in Finder: \(profile.filePath)")
    }

    private var activeModelStatusText: String {
        let candidates = RandomForestModelService.shared.modelCandidates()
        if candidates.isEmpty {
            return settings.language == .zhHans
                ? "当前未检测到 .joblib 核心文件。"
                : "No runtime .joblib core file detected."
        }
        if candidates.count == 1, let model = candidates.first {
            return settings.language == .zhHans
                ? "当前核心：\(model.path)"
                : "Current core: \(model.path)"
        }
        let joined = candidates.map(\.lastPathComponent).joined(separator: ", ")
        return settings.language == .zhHans
            ? "检测到多个核心（\(candidates.count)）：\(joined)"
            : "Multiple cores detected (\(candidates.count)): \(joined)"
    }

    private func uploadJoblibCore() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowedContentTypes = [UTType(filenameExtension: "joblib") ?? .data]
        panel.title = settings.language == .zhHans ? "选择 joblib 模型文件" : "Select joblib model file"
        panel.prompt = settings.language == .zhHans ? "替换核心" : "Replace Core"

        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            do {
                let destination = try RandomForestModelService.shared.replaceModel(with: url)
                DiagnosticsLogService.shared.log(.info, category: "config.model", "Replaced RandomForest model: \(destination.path)")
                statusText = settings.language == .zhHans
                    ? "已替换核心模型：\(destination.lastPathComponent)"
                    : "Core model replaced: \(destination.lastPathComponent)"
            } catch {
                DiagnosticsLogService.shared.log(.error, category: "config.model", "Replace RandomForest model failed: \(error.localizedDescription)")
                statusText = settings.language == .zhHans
                    ? "替换核心失败：\(error.localizedDescription)"
                    : "Replace core failed: \(error.localizedDescription)"
            }
        }
    }
}
