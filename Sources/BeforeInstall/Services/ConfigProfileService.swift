import Foundation

final class ConfigProfileService: @unchecked Sendable {
    static let shared = ConfigProfileService()

    private let fileManager = FileManager.default
    private let activeProfileDefaultsKey = "beforeinstall.activeConfigProfileID"

    private init() {}

    func ensureDefaultProfileExists(ruleFilePath: String) {
        let defaultURL = profileURL(for: defaultProfileID)
        guard !fileManager.fileExists(atPath: defaultURL.path) else { return }

        let globals = defaultGlobals()
        let rules = [
            ConfigRule(type: .ruleFile, value: ruleFilePath, action: .notice, lineNumber: 1)
        ]
        let text = renderProfile(globals: globals, rules: rules)
        try? writeProfileContent(text, to: defaultURL)
    }

    func listProfiles() -> [ConfigProfileSummary] {
        let directory = profilesDirectoryURL()
        guard let files = try? fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }

        let summaries = files
            .filter { $0.pathExtension == profileExtension }
            .map { url -> ConfigProfileSummary in
                let id = url.deletingPathExtension().lastPathComponent
                let updated = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                return ConfigProfileSummary(id: id, name: id, filePath: url.path, updatedAt: updated)
            }
            .sorted { $0.updatedAt > $1.updatedAt }

        if summaries.contains(where: { $0.id == defaultProfileID }) {
            return summaries
        }

        // If profile folder exists but default profile is missing, recreate it.
        ensureDefaultProfileExists(ruleFilePath: ThreatIntelDictionaryManager.shared.activeRuleFileURL().path)
        return listProfiles()
    }

    func importProfile(from sourceURL: URL) throws -> ConfigProfileSummary {
        let sanitizedName = sourceURL.deletingPathExtension().lastPathComponent
            .replacingOccurrences(of: " ", with: "-")
            .lowercased()
        let id = sanitizedName.isEmpty ? "profile-\(Int(Date().timeIntervalSince1970))" : sanitizedName
        let destination = profileURL(for: uniqueProfileID(from: id))
        try fileManager.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        try fileManager.copyItem(at: sourceURL, to: destination)

        return ConfigProfileSummary(
            id: destination.deletingPathExtension().lastPathComponent,
            name: destination.deletingPathExtension().lastPathComponent,
            filePath: destination.path,
            updatedAt: Date()
        )
    }

    func activeProfileID() -> String {
        UserDefaults.standard.string(forKey: activeProfileDefaultsKey) ?? defaultProfileID
    }

    func setActiveProfileID(_ profileID: String) {
        UserDefaults.standard.set(profileID, forKey: activeProfileDefaultsKey)
    }

    func loadProfileContent(profileID: String) -> String {
        let url = profileURL(for: profileID)
        return (try? String(contentsOf: url, encoding: .utf8)) ?? ""
    }

    func saveProfileContent(profileID: String, content: String) throws {
        let url = profileURL(for: profileID)
        try writeProfileContent(content, to: url)
    }

    func parseProfile(text: String) -> ParsedConfigProfile {
        var globals: [String: String] = [:]
        var rules: [ConfigRule] = []

        enum Section {
            case none
            case global
            case rules
        }

        var section: Section = .none

        for (index, rawLine) in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated() {
            let lineNumber = index + 1
            let line = String(rawLine).trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") {
                continue
            }

            let lowered = line.lowercased()
            if lowered == "[global]" {
                section = .global
                continue
            }
            if lowered == "[rules]" {
                section = .rules
                continue
            }

            switch section {
            case .global:
                let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
                guard parts.count == 2 else { continue }
                let key = parts[0].trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                let value = parts[1].trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                if !key.isEmpty {
                    globals[key] = value
                }
            case .rules:
                let parts = line.split(separator: ",", omittingEmptySubsequences: false).map {
                    $0.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                }
                guard parts.count >= 2 else { continue }

                let rawType = parts[0].uppercased()
                guard let ruleType = ConfigRuleType(rawValue: rawType) else { continue }

                if ruleType == .app {
                    if parts.count >= 3,
                       let trailingAction = ConfigRuleAction(rawValue: parts.last?.lowercased() ?? "")
                    {
                        let value = parts.dropFirst().dropLast().joined(separator: ",")
                        rules.append(
                            ConfigRule(
                                type: ruleType,
                                value: value,
                                action: trailingAction,
                                lineNumber: lineNumber
                            )
                        )
                    } else {
                        let value = parts.dropFirst().joined(separator: ",")
                        rules.append(
                            ConfigRule(
                                type: ruleType,
                                value: value,
                                action: .notice,
                                lineNumber: lineNumber
                            )
                        )
                    }
                    continue
                }

                guard parts.count >= 3 else { continue }
                let actionRaw = parts.last?.lowercased() ?? "notice"
                let action = ConfigRuleAction(rawValue: actionRaw) ?? .notice
                let value = parts.dropFirst().dropLast().joined(separator: ",")

                rules.append(
                    ConfigRule(
                        type: ruleType,
                        value: value,
                        action: action,
                        lineNumber: lineNumber
                    )
                )
            case .none:
                continue
            }
        }

        return ParsedConfigProfile(globals: globals, rules: rules)
    }

    func loadParsedProfile(profileID: String) -> ParsedConfigProfile {
        parseProfile(text: loadProfileContent(profileID: profileID))
    }

    func loadActiveParsedProfile() -> ParsedConfigProfile {
        loadParsedProfile(profileID: activeProfileID())
    }

    @MainActor
    func applyGlobalsOfActiveProfile(to settings: AppSettingsStore) {
        let parsed = loadActiveParsedProfile()
        applyGlobals(parsed.globals, to: settings)
    }

    @MainActor
    func syncDefaultProfileGlobals(from settings: AppSettingsStore) {
        let defaultRuleFilePath = ThreatIntelDictionaryManager.shared.activeRuleFileURL().path
        ensureDefaultProfileExists(ruleFilePath: defaultRuleFilePath)
        let defaultID = defaultProfileID
        let parsed = loadParsedProfile(profileID: defaultID)
        var rules = parsed.rules
        if !rules.contains(where: { $0.type == .ruleFile }) {
            rules.insert(
                ConfigRule(type: .ruleFile, value: defaultRuleFilePath, action: .notice, lineNumber: 1),
                at: 0
            )
        }
        let globals = defaultGlobals(overrides: [
            "language": settings.language.rawValue,
            "showDynamicSafetyPrompt": String(settings.showDynamicSafetyPrompt),
            "preferBackgroundAppLaunch": String(settings.preferBackgroundAppLaunch),
            "allowNonAppDynamicExecution": String(settings.allowNonAppDynamicExecution),
            "diagnosticsLogLevel": settings.diagnosticsLogLevel.rawValue,
            "diagnosticsLogMaxEntries": String(settings.diagnosticsLogMaxEntries),
            "scoringProfile": settings.scoringProfile.rawValue,
            "useRandomForestPrediction": String(settings.useRandomForestPrediction),
            "fullDiskScanMaxConcurrency": String(settings.fullDiskScanMaxConcurrency),
            "autoCheckAndInstallUpdates": String(settings.autoCheckAndInstallUpdates),
            "showWelcomeOnLaunch": String(settings.showWelcomeOnLaunch)
        ])
        let rebuilt = renderProfile(globals: globals, rules: rules)
        try? saveProfileContent(profileID: defaultID, content: rebuilt)
    }

    func appendOrUpdateAppRule(bundleIdentifier: String, dylibPaths: [String]) {
        let profileID = activeProfileID()
        let parsed = loadParsedProfile(profileID: profileID)
        var rules = parsed.rules

        rules.removeAll { rule in
            guard rule.type == .app else { return false }
            let head = rule.value.split(separator: ",", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
            return head == bundleIdentifier
        }
        guard !dylibPaths.isEmpty else {
            let rebuilt = renderProfile(globals: parsed.globals, rules: rules)
            try? saveProfileContent(profileID: profileID, content: rebuilt)
            return
        }

        let appValue = "\(bundleIdentifier),\(dylibPaths.joined(separator: "&&"))"
        rules.insert(
            ConfigRule(type: .app, value: appValue, action: .notice, lineNumber: 0),
            at: 0
        )

        let rebuilt = renderProfile(globals: parsed.globals, rules: rules)
        try? saveProfileContent(profileID: profileID, content: rebuilt)
    }

    func upsertPathPrefixRules(
        paths: [String],
        action: ConfigRuleAction,
        profileID: String? = nil
    ) {
        let targetProfileID = profileID ?? activeProfileID()
        let parsed = loadParsedProfile(profileID: targetProfileID)
        var rules = parsed.rules

        var normalized: [String] = []
        var seen = Set<String>()
        for raw in paths {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let expanded = (trimmed as NSString).expandingTildeInPath
            let standardized = URL(fileURLWithPath: expanded).standardizedFileURL.path
            guard !seen.contains(standardized) else { continue }
            seen.insert(standardized)
            normalized.append(standardized)
        }
        guard !normalized.isEmpty else { return }

        for path in normalized {
            let exists = rules.contains { rule in
                guard rule.type == .rulePathPrefix, rule.action == action else { return false }
                let existing = URL(fileURLWithPath: (rule.value as NSString).expandingTildeInPath).standardizedFileURL.path
                return existing == path
            }
            if exists { continue }
            rules.append(
                ConfigRule(
                    type: .rulePathPrefix,
                    value: path,
                    action: action,
                    lineNumber: 0
                )
            )
        }

        let rebuilt = renderProfile(globals: parsed.globals, rules: rules)
        try? saveProfileContent(profileID: targetProfileID, content: rebuilt)
    }

    @MainActor
    private func applyGlobals(_ globals: [String: String], to settings: AppSettingsStore) {
        for (key, value) in globals {
            switch key {
            case "language":
                if let language = AppLanguage(rawValue: value) {
                    settings.language = language
                }
            case "showDynamicSafetyPrompt":
                settings.showDynamicSafetyPrompt = parseBool(value, fallback: settings.showDynamicSafetyPrompt)
            case "preferBackgroundAppLaunch":
                settings.preferBackgroundAppLaunch = parseBool(value, fallback: settings.preferBackgroundAppLaunch)
            case "allowNonAppDynamicExecution":
                settings.allowNonAppDynamicExecution = parseBool(value, fallback: settings.allowNonAppDynamicExecution)
            case "diagnosticsLogLevel":
                if let level = LogLevel(rawValue: value) {
                    settings.diagnosticsLogLevel = level
                }
            case "diagnosticsLogMaxEntries":
                if let count = Int(value) {
                    settings.diagnosticsLogMaxEntries = count
                }
            case "scoringProfile":
                if let profile = ScoringProfile(rawValue: value) {
                    settings.scoringProfile = profile
                }
            case "useRandomForestPrediction":
                settings.useRandomForestPrediction = parseBool(value, fallback: settings.useRandomForestPrediction)
            case "fullDiskScanMaxConcurrency":
                if let concurrency = Int(value) {
                    settings.fullDiskScanMaxConcurrency = settings.normalizedFullDiskScanConcurrency(concurrency)
                }
            case "autoCheckAndInstallUpdates":
                settings.autoCheckAndInstallUpdates = parseBool(value, fallback: settings.autoCheckAndInstallUpdates)
            case "showWelcomeOnLaunch":
                settings.showWelcomeOnLaunch = parseBool(value, fallback: settings.showWelcomeOnLaunch)
            default:
                continue
            }
        }
    }

    private func defaultGlobals(overrides: [String: String] = [:]) -> [String: String] {
        var globals: [String: String] = [
            "language": "zhHans",
            "showDynamicSafetyPrompt": "true",
            "preferBackgroundAppLaunch": "true",
            "allowNonAppDynamicExecution": "false",
            "diagnosticsLogLevel": "info",
            "diagnosticsLogMaxEntries": "3000",
            "scoringProfile": "balanced",
            "useRandomForestPrediction": "false",
            "fullDiskScanMaxConcurrency": "6",
            "autoCheckAndInstallUpdates": "false",
            "showWelcomeOnLaunch": "true"
        ]

        for (k, v) in overrides {
            globals[k] = v
        }
        return globals
    }

    private func renderProfile(globals: [String: String], rules: [ConfigRule]) -> String {
        var lines: [String] = []
        lines.append("# BeforeInstall profile")
        lines.append("# RULE format: TYPE,value,notice|ignore")
        lines.append("# APP format: APP,bundle.id,/path/a.dylib&&/path/b.dylib")
        lines.append("# RULE-PATH-PREFIX format: RULE-PATH-PREFIX,/path/prefix,notice|ignore")
        lines.append("[global]")

        for key in globals.keys.sorted() {
            lines.append("\(key)=\(globals[key] ?? "")")
        }

        lines.append("")
        lines.append("[rules]")

        for rule in rules {
            if rule.type == .app {
                lines.append("\(rule.type.rawValue),\(rule.value)")
            } else {
                lines.append("\(rule.type.rawValue),\(rule.value),\(rule.action.rawValue)")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    private func parseBool(_ raw: String, fallback: Bool) -> Bool {
        switch raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "1", "true", "yes", "on":
            return true
        case "0", "false", "no", "off":
            return false
        default:
            return fallback
        }
    }

    private func uniqueProfileID(from base: String) -> String {
        let directory = profilesDirectoryURL()
        var candidate = base
        var index = 1
        while fileManager.fileExists(atPath: directory.appendingPathComponent("\(candidate).\(profileExtension)").path) {
            index += 1
            candidate = "\(base)-\(index)"
        }
        return candidate
    }

    private func writeProfileContent(_ content: String, to url: URL) throws {
        try fileManager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard let data = content.data(using: .utf8) else {
            throw NSError(domain: "BeforeInstall.ConfigProfile", code: 11, userInfo: [NSLocalizedDescriptionKey: "Profile content encoding failed"])
        }
        try data.write(to: url, options: .atomic)
    }

    private func profilesDirectoryURL() -> URL {
        let base = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/BeforeInstall", isDirectory: true)
        let directory = base.appendingPathComponent("Profiles", isDirectory: true)
        if !fileManager.fileExists(atPath: directory.path) {
            try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        return directory
    }

    private func profileURL(for profileID: String) -> URL {
        profilesDirectoryURL().appendingPathComponent("\(profileID).\(profileExtension)", isDirectory: false)
    }

    private let defaultProfileID = "default"
    private let profileExtension = "beforeconfig"
}
