import Foundation

@MainActor
final class AppSettingsStore: ObservableObject {
    @Published var language: AppLanguage {
        didSet {
            guard oldValue != language else { return }
            defaults.set(language.rawValue, forKey: Keys.language)
            syncDefaultProfileGlobals()
        }
    }

    @Published var allowNonAppDynamicExecution: Bool {
        didSet {
            guard oldValue != allowNonAppDynamicExecution else { return }
            defaults.set(allowNonAppDynamicExecution, forKey: Keys.allowNonAppDynamicExecution)
            syncDefaultProfileGlobals()
        }
    }

    @Published var defaultDurationSeconds: Int {
        didSet {
            let normalized = normalizedDuration(defaultDurationSeconds)
            guard oldValue != defaultDurationSeconds else { return }
            defaults.set(normalized, forKey: Keys.defaultDuration)
        }
    }

    @Published var showWelcomeOnLaunch: Bool {
        didSet {
            guard oldValue != showWelcomeOnLaunch else { return }
            defaults.set(showWelcomeOnLaunch, forKey: Keys.showWelcomeOnLaunch)
            syncDefaultProfileGlobals()
        }
    }

    @Published var showDynamicSafetyPrompt: Bool {
        didSet {
            guard oldValue != showDynamicSafetyPrompt else { return }
            defaults.set(showDynamicSafetyPrompt, forKey: Keys.showDynamicSafetyPrompt)
            syncDefaultProfileGlobals()
        }
    }

    @Published var preferBackgroundAppLaunch: Bool {
        didSet {
            guard oldValue != preferBackgroundAppLaunch else { return }
            defaults.set(preferBackgroundAppLaunch, forKey: Keys.preferBackgroundAppLaunch)
            syncDefaultProfileGlobals()
        }
    }

    @Published var appearance: AppAppearance {
        didSet {
            guard oldValue != appearance else { return }
            defaults.set(appearance.rawValue, forKey: Keys.appearance)
        }
    }

    @Published var diagnosticsLogLevel: LogLevel {
        didSet {
            guard oldValue != diagnosticsLogLevel else { return }
            defaults.set(diagnosticsLogLevel.rawValue, forKey: Keys.diagnosticsLogLevel)
            DiagnosticsLogService.shared.updateConfiguration(
                minLevel: diagnosticsLogLevel,
                maxEntries: diagnosticsLogMaxEntries
            )
            syncDefaultProfileGlobals()
        }
    }

    @Published var diagnosticsLogMaxEntries: Int {
        didSet {
            let normalized = min(max(diagnosticsLogMaxEntries, 200), 20000)
            guard oldValue != diagnosticsLogMaxEntries else { return }
            defaults.set(normalized, forKey: Keys.diagnosticsLogMaxEntries)
            DiagnosticsLogService.shared.updateConfiguration(
                minLevel: diagnosticsLogLevel,
                maxEntries: normalized
            )
            syncDefaultProfileGlobals()
        }
    }

    @Published var scoringProfile: ScoringProfile {
        didSet {
            guard oldValue != scoringProfile else { return }
            defaults.set(scoringProfile.rawValue, forKey: Keys.scoringProfile)
            syncDefaultProfileGlobals()
        }
    }

    @Published var useRandomForestPrediction: Bool {
        didSet {
            guard oldValue != useRandomForestPrediction else { return }
            defaults.set(useRandomForestPrediction, forKey: Keys.useRandomForestPrediction)
            syncDefaultProfileGlobals()
        }
    }

    @Published var fullDiskScanMaxConcurrency: Int {
        didSet {
            let normalized = Self.normalizedFullDiskScanConcurrencyValue(fullDiskScanMaxConcurrency)
            if normalized != fullDiskScanMaxConcurrency {
                fullDiskScanMaxConcurrency = normalized
                return
            }
            guard oldValue != fullDiskScanMaxConcurrency else { return }
            defaults.set(normalized, forKey: Keys.fullDiskScanMaxConcurrency)
            syncDefaultProfileGlobals()
        }
    }

    @Published var autoCheckAndInstallUpdates: Bool {
        didSet {
            guard oldValue != autoCheckAndInstallUpdates else { return }
            defaults.set(autoCheckAndInstallUpdates, forKey: Keys.autoCheckAndInstallUpdates)
            syncDefaultProfileGlobals()
        }
    }

    @Published var developerModeEnabled: Bool {
        didSet {
            guard oldValue != developerModeEnabled else { return }
            defaults.set(developerModeEnabled, forKey: Keys.developerModeEnabled)
        }
    }

    @Published var benchmarkRootPath: String {
        didSet {
            let normalized = benchmarkRootPath.trimmingCharacters(in: .whitespacesAndNewlines)
            guard oldValue != benchmarkRootPath else { return }
            defaults.set(normalized, forKey: Keys.benchmarkRootPath)
        }
    }

    private(set) var hasCompletedFirstLaunchWelcome: Bool {
        didSet {
            guard oldValue != hasCompletedFirstLaunchWelcome else { return }
            defaults.set(hasCompletedFirstLaunchWelcome, forKey: Keys.hasCompletedFirstLaunchWelcome)
        }
    }

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults

        let languageRaw = defaults.string(forKey: Keys.language)
        language = AppLanguage(rawValue: languageRaw ?? "") ?? .zhHans

        allowNonAppDynamicExecution = defaults.bool(forKey: Keys.allowNonAppDynamicExecution)

        let duration = defaults.object(forKey: Keys.defaultDuration) as? Int ?? 20
        defaultDurationSeconds = max(5, min(duration, 120))

        if defaults.object(forKey: Keys.showWelcomeOnLaunch) == nil {
            showWelcomeOnLaunch = true
        } else {
            showWelcomeOnLaunch = defaults.bool(forKey: Keys.showWelcomeOnLaunch)
        }

        if defaults.object(forKey: Keys.showDynamicSafetyPrompt) == nil {
            showDynamicSafetyPrompt = true
        } else {
            showDynamicSafetyPrompt = defaults.bool(forKey: Keys.showDynamicSafetyPrompt)
        }

        if defaults.object(forKey: Keys.preferBackgroundAppLaunch) == nil {
            preferBackgroundAppLaunch = true
        } else {
            preferBackgroundAppLaunch = defaults.bool(forKey: Keys.preferBackgroundAppLaunch)
        }

        let appearanceRaw = defaults.string(forKey: Keys.appearance)
        appearance = AppAppearance(rawValue: appearanceRaw ?? "") ?? .system

        let logLevelRaw = defaults.string(forKey: Keys.diagnosticsLogLevel)
        diagnosticsLogLevel = LogLevel(rawValue: logLevelRaw ?? "") ?? .info
        let defaultMaxEntries = defaults.object(forKey: Keys.diagnosticsLogMaxEntries) as? Int ?? 3000
        diagnosticsLogMaxEntries = min(max(defaultMaxEntries, 200), 20000)

        let scoringRaw = defaults.string(forKey: Keys.scoringProfile)
        scoringProfile = ScoringProfile(rawValue: scoringRaw ?? "") ?? .balanced

        if defaults.object(forKey: Keys.useRandomForestPrediction) == nil {
            useRandomForestPrediction = false
        } else {
            useRandomForestPrediction = defaults.bool(forKey: Keys.useRandomForestPrediction)
        }

        let configuredConcurrency = defaults.object(forKey: Keys.fullDiskScanMaxConcurrency) as? Int ?? 6
        fullDiskScanMaxConcurrency = Self.normalizedFullDiskScanConcurrencyValue(configuredConcurrency)

        if defaults.object(forKey: Keys.autoCheckAndInstallUpdates) == nil {
            autoCheckAndInstallUpdates = false
        } else {
            autoCheckAndInstallUpdates = defaults.bool(forKey: Keys.autoCheckAndInstallUpdates)
        }

        if defaults.object(forKey: Keys.developerModeEnabled) == nil {
            developerModeEnabled = DeveloperModePolicy.shouldEnableDeveloperModeByDefault
        } else {
            developerModeEnabled = defaults.bool(forKey: Keys.developerModeEnabled)
        }

        benchmarkRootPath = defaults.string(forKey: Keys.benchmarkRootPath) ?? ""
        hasCompletedFirstLaunchWelcome = defaults.bool(forKey: Keys.hasCompletedFirstLaunchWelcome)

        DiagnosticsLogService.shared.updateConfiguration(
            minLevel: diagnosticsLogLevel,
            maxEntries: diagnosticsLogMaxEntries
        )
        Task.detached(priority: .utility) {
            if let ruleFile = try? ThreatIntelDictionaryManager.shared.ensureRuleFileReady() {
                ConfigProfileService.shared.ensureDefaultProfileExists(ruleFilePath: ruleFile.path)
            }
            try? RandomForestModelService.shared.ensureRuntimeAssetsReady()
        }
    }

    func normalizedDuration(_ value: Int) -> Int {
        max(5, min(value, 120))
    }

    func normalizedFullDiskScanConcurrency(_ value: Int) -> Int {
        Self.normalizedFullDiskScanConcurrencyValue(value)
    }

    private static func normalizedFullDiskScanConcurrencyValue(_ value: Int) -> Int {
        max(1, min(value, 16))
    }

    func normalizeDuration(_ value: Int) {
        defaultDurationSeconds = normalizedDuration(value)
    }

    var threatProfilePath: String {
        ThreatIntelDictionaryManager.shared.activeRuleFileURL().path
    }

    private func syncDefaultProfileGlobals() {
        ConfigProfileService.shared.syncDefaultProfileGlobals(from: self)
    }

    var developerEntryAvailable: Bool {
        true
    }

    func setDeveloperModeEnabled(_ enabled: Bool) {
        developerModeEnabled = enabled
    }

    func disableDeveloperMode() {
        developerModeEnabled = false
    }

    func shouldPresentWelcomeOnStartup() -> Bool {
        !hasCompletedFirstLaunchWelcome
    }

    func markWelcomeShownAtLeastOnce() {
        hasCompletedFirstLaunchWelcome = true
    }

    func updateBenchmarkRootURL(_ url: URL) {
        benchmarkRootPath = url.standardizedFileURL.path
        do {
            let bookmark = try url.bookmarkData(options: [.withSecurityScope], includingResourceValuesForKeys: nil, relativeTo: nil)
            defaults.set(bookmark, forKey: Keys.benchmarkRootBookmark)
        } catch {
            defaults.removeObject(forKey: Keys.benchmarkRootBookmark)
        }
    }

    func resolveBenchmarkRootURL() -> URL? {
        guard let bookmark = defaults.data(forKey: Keys.benchmarkRootBookmark) else {
            let path = benchmarkRootPath.trimmingCharacters(in: .whitespacesAndNewlines)
            return path.isEmpty ? nil : URL(fileURLWithPath: path)
        }

        var isStale = false
        if let resolved = try? URL(
            resolvingBookmarkData: bookmark,
            options: [.withSecurityScope],
            relativeTo: nil,
            bookmarkDataIsStale: &isStale
        ) {
            if isStale {
                updateBenchmarkRootURL(resolved)
            }
            return resolved
        }

        let path = benchmarkRootPath.trimmingCharacters(in: .whitespacesAndNewlines)
        return path.isEmpty ? nil : URL(fileURLWithPath: path)
    }

    private enum Keys {
        static let language = "beforeinstall.language"
        static let allowNonAppDynamicExecution = "beforeinstall.allowNonAppDynamicExecution"
        static let defaultDuration = "beforeinstall.dynamicDuration"
        static let showWelcomeOnLaunch = "beforeinstall.showWelcomeOnLaunch"
        static let showDynamicSafetyPrompt = "beforeinstall.showDynamicSafetyPrompt"
        static let preferBackgroundAppLaunch = "beforeinstall.preferBackgroundAppLaunch"
        static let appearance = "beforeinstall.appearance"
        static let diagnosticsLogLevel = "beforeinstall.diagnosticsLogLevel"
        static let diagnosticsLogMaxEntries = "beforeinstall.diagnosticsLogMaxEntries"
        static let scoringProfile = "beforeinstall.scoringProfile"
        static let useRandomForestPrediction = "beforeinstall.useRandomForestPrediction"
        static let fullDiskScanMaxConcurrency = "beforeinstall.fullDiskScanMaxConcurrency"
        static let autoCheckAndInstallUpdates = "beforeinstall.autoCheckAndInstallUpdates"
        static let developerModeEnabled = "beforeinstall.developerModeEnabled"
        static let benchmarkRootPath = "beforeinstall.benchmarkRootPath"
        static let benchmarkRootBookmark = "beforeinstall.benchmarkRootBookmark"
        static let hasCompletedFirstLaunchWelcome = "beforeinstall.hasCompletedFirstLaunchWelcome"
    }
}
