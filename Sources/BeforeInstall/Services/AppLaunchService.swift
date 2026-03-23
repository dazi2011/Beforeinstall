import Foundation
import AppKit

final class AppLaunchService: @unchecked Sendable {
    static let shared = AppLaunchService()

    private let fileManager = FileManager.default
    private let injectionService = DylibInjectionService()
    private let stateQueue = DispatchQueue(label: "beforeinstall.app-launch.state", qos: .userInitiated)
    private let importedAppPathsDefaultsKey = "beforeinstall.launcher.importedAppPaths"
    private var cachedScanResult: [LaunchableAppInfo] = []
    private var cachedScanAt: Date?
    private var launchingAppPaths: Set<String> = []
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()
    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    private init() {}

    func scanCommonAppDirectories(maxCount: Int = 500, forceRefresh: Bool = false) -> [LaunchableAppInfo] {
        if !forceRefresh,
           let cached = stateQueue.sync(execute: { () -> [LaunchableAppInfo]? in
               guard let cachedScanAt else { return nil }
               if Date().timeIntervalSince(cachedScanAt) <= 20 {
                   return cachedScanResult
               }
               return nil
           })
        {
            return cached
        }

        let roots = [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            URL(fileURLWithPath: "/Applications/Utilities", isDirectory: true),
            URL(fileURLWithPath: "/System/Applications", isDirectory: true),
            URL(fileURLWithPath: "/System/Applications/Utilities", isDirectory: true),
            fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Applications", isDirectory: true)
        ]

        var apps: [LaunchableAppInfo] = []
        var seenPaths = Set<String>()

        for root in roots where fileManager.fileExists(atPath: root.path) {
            guard let enumerator = fileManager.enumerator(
                at: root,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles],
                errorHandler: nil
            ) else {
                continue
            }

            for case let item as URL in enumerator {
                if item.pathExtension.lowercased() == "app" {
                    enumerator.skipDescendants()
                    let standardized = item.standardizedFileURL.path
                    guard !seenPaths.contains(standardized) else { continue }
                    seenPaths.insert(standardized)
                    if let appInfo = appInfo(appURL: item) {
                        apps.append(appInfo)
                    }
                }

                if apps.count >= maxCount {
                    var merged = apps
                    for path in importedAppPaths() {
                        guard !seenPaths.contains(path) else { continue }
                        if let custom = appInfo(appURL: URL(fileURLWithPath: path)) {
                            merged.append(custom)
                        }
                    }
                    let sorted = merged.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
                    stateQueue.sync {
                        cachedScanResult = sorted
                        cachedScanAt = Date()
                    }
                    return sorted
                }
            }
        }

        for path in importedAppPaths() {
            guard !seenPaths.contains(path) else { continue }
            if let custom = appInfo(appURL: URL(fileURLWithPath: path)) {
                apps.append(custom)
            }
        }

        let sorted = apps.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
        stateQueue.sync {
            cachedScanResult = sorted
            cachedScanAt = Date()
        }
        return sorted
    }

    func loadPresets() -> [AppLaunchPreset] {
        guard let data = try? Data(contentsOf: presetStorageURL()),
              let presets = try? decoder.decode([AppLaunchPreset].self, from: data)
        else {
            return []
        }
        return presets.sorted { $0.updatedAt > $1.updatedAt }
    }

    func preset(for app: LaunchableAppInfo) -> AppLaunchPreset? {
        if let stored = loadPresets().first(where: { $0.appPath == app.appPath || $0.bundleIdentifier == app.bundleIdentifier }) {
            return stored
        }
        return presetFromActiveProfile(for: app)
    }

    func savePreset(_ preset: AppLaunchPreset) {
        var presets = loadPresets()
        presets.removeAll { $0.appPath == preset.appPath || $0.bundleIdentifier == preset.bundleIdentifier }
        presets.insert(preset, at: 0)

        let parent = presetStorageURL().deletingLastPathComponent()
        try? fileManager.createDirectory(at: parent, withIntermediateDirectories: true)
        guard let data = try? encoder.encode(presets) else { return }
        try? data.write(to: presetStorageURL(), options: .atomic)
        invalidateScanCache()
    }

    func launch(app: LaunchableAppInfo, preset: AppLaunchPreset?) -> DylibInjectedLaunchResult {
        guard beginLaunch(appPath: app.appPath) else {
            return DylibInjectedLaunchResult(
                launchSucceeded: false,
                process: nil,
                mainPID: nil,
                launchMode: "launch_rejected",
                warning: "Launch already in progress for this app.",
                dylibPaths: []
            )
        }
        defer { endLaunch(appPath: app.appPath) }

        let resolvedPreset = preset ?? AppLaunchPreset.default(for: app)
        let appURL = URL(fileURLWithPath: app.appPath)
        let dylibPaths = resolveDylibPaths(for: resolvedPreset)
        let launchMode = resolvedPreset.useSandboxExec ? "sandbox_exec" : "dyld_insert_libraries"

        if let existing = runningApplication(for: app) {
            if dylibPaths.isEmpty && !resolvedPreset.useSandboxExec {
                _ = existing.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])
                return DylibInjectedLaunchResult(
                    launchSucceeded: true,
                    process: nil,
                    mainPID: Int(existing.processIdentifier),
                    launchMode: "activate_existing",
                    warning: nil,
                    dylibPaths: []
                )
            }
            return DylibInjectedLaunchResult(
                launchSucceeded: false,
                process: nil,
                mainPID: Int(existing.processIdentifier),
                launchMode: launchMode,
                warning: "Target app is already running. Quit it first before injected launch.",
                dylibPaths: dylibPaths
            )
        }

        if resolvedPreset.useSandboxExec {
            return launchViaSandboxExec(appURL: appURL)
        }

        let launch = injectionService.launchAppWithInjection(
            appURL: appURL,
            environment: ProcessInfo.processInfo.environment,
            dylibPaths: dylibPaths,
            workingDirectory: nil
        )

        return launch
    }

    func relaunchAfterTerminatingRunningApp(app: LaunchableAppInfo, preset: AppLaunchPreset?) -> DylibInjectedLaunchResult {
        guard beginLaunch(appPath: app.appPath) else {
            return DylibInjectedLaunchResult(
                launchSucceeded: false,
                process: nil,
                mainPID: nil,
                launchMode: "launch_rejected",
                warning: "Launch already in progress for this app.",
                dylibPaths: []
            )
        }
        defer { endLaunch(appPath: app.appPath) }

        let resolvedPreset = preset ?? AppLaunchPreset.default(for: app)
        let appURL = URL(fileURLWithPath: app.appPath)
        let dylibPaths = resolveDylibPaths(for: resolvedPreset)
        let launchMode = resolvedPreset.useSandboxExec ? "sandbox_exec" : "dyld_insert_libraries"

        if let existing = runningApplication(for: app) {
            if !terminate(runningApplication: existing) || !waitUntilAppStopsRunning(app, timeout: 5.5) {
                return DylibInjectedLaunchResult(
                    launchSucceeded: false,
                    process: nil,
                    mainPID: Int(existing.processIdentifier),
                    launchMode: launchMode,
                    warning: "Failed to terminate existing app instance before relaunch.",
                    dylibPaths: dylibPaths
                )
            }
        }

        if resolvedPreset.useSandboxExec {
            return launchViaSandboxExec(appURL: appURL)
        }

        return injectionService.launchAppWithInjection(
            appURL: appURL,
            environment: ProcessInfo.processInfo.environment,
            dylibPaths: dylibPaths,
            workingDirectory: nil
        )
    }

    func persistPresetIntoApp(_ preset: AppLaunchPreset) throws {
        let appURL = URL(fileURLWithPath: preset.appPath)
        guard let executableURL = injectionService.appExecutableURL(appURL: appURL) else {
            throw NSError(domain: "BeforeInstall.Persist", code: 1, userInfo: [NSLocalizedDescriptionKey: "App executable not found"])
        }

        let dylibPaths = resolveDylibPaths(for: preset)
        guard !dylibPaths.isEmpty else {
            throw NSError(domain: "BeforeInstall.Persist", code: 2, userInfo: [NSLocalizedDescriptionKey: "No dylib selected for persistence"])
        }

        let backupURL = executableURL.deletingLastPathComponent().appendingPathComponent(executableURL.lastPathComponent + ".beforeinstall.orig")

        if !fileManager.fileExists(atPath: backupURL.path) {
            try fileManager.moveItem(at: executableURL, to: backupURL)
        }

        let dyldValue = dylibPaths.joined(separator: ":")
        let backupName = backupURL.lastPathComponent
        let wrapper = """
        #!/bin/zsh
        DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"
        export DYLD_INSERT_LIBRARIES='\(escapeSingleQuotes(dyldValue))'
        exec \"$DIR/\(backupName)\" \"$@\"
        """

        guard let wrapperData = wrapper.data(using: .utf8) else {
            throw NSError(domain: "BeforeInstall.Persist", code: 5, userInfo: [NSLocalizedDescriptionKey: "Wrapper script encoding failed"])
        }
        try wrapperData.write(to: executableURL, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executableURL.path)

        let marker = persistedMarkerURL(for: executableURL)
        let markerObject: [String: String] = [
            "appPath": preset.appPath,
            "bundleIdentifier": preset.bundleIdentifier,
            "dyldInsertLibraries": dyldValue,
            "backupExecutable": backupURL.path,
            "updatedAt": ISO8601DateFormatter().string(from: Date())
        ]
        let markerData = try JSONSerialization.data(withJSONObject: markerObject, options: [.prettyPrinted, .sortedKeys])
        try markerData.write(to: marker, options: .atomic)

    }

    func restorePersistedApp(appPath: String) throws {
        let appURL = URL(fileURLWithPath: appPath)
        guard let executableURL = injectionService.appExecutableURL(appURL: appURL) else {
            throw NSError(domain: "BeforeInstall.Persist", code: 3, userInfo: [NSLocalizedDescriptionKey: "App executable not found"])
        }

        let backupURL = executableURL.deletingLastPathComponent().appendingPathComponent(executableURL.lastPathComponent + ".beforeinstall.orig")
        guard fileManager.fileExists(atPath: backupURL.path) else {
            throw NSError(domain: "BeforeInstall.Persist", code: 4, userInfo: [NSLocalizedDescriptionKey: "No backup executable found"])
        }

        if fileManager.fileExists(atPath: executableURL.path) {
            try fileManager.removeItem(at: executableURL)
        }
        try fileManager.moveItem(at: backupURL, to: executableURL)

        let marker = persistedMarkerURL(for: executableURL)
        if fileManager.fileExists(atPath: marker.path) {
            try? fileManager.removeItem(at: marker)
        }

    }

    func isAppPersisted(appPath: String) -> Bool {
        let appURL = URL(fileURLWithPath: appPath)
        guard let executableURL = injectionService.appExecutableURL(appURL: appURL) else { return false }
        let backupURL = executableURL.deletingLastPathComponent().appendingPathComponent(executableURL.lastPathComponent + ".beforeinstall.orig")
        return fileManager.fileExists(atPath: backupURL.path)
    }

    func resolveDylibPaths(for preset: AppLaunchPreset) -> [String] {
        configuredDylibPaths(for: preset)
            .filter { fileManager.fileExists(atPath: $0) }
            .uniquePreservingOrder()
    }

    func configuredDylibPaths(for preset: AppLaunchPreset) -> [String] {
        var paths: [String] = []

        if preset.useSandboxExec {
            return []
        }

        if preset.useSafeMode, !preset.useCustomMode {
            if let safeMode = bundledOrFallbackPath(named: BuiltInDylib.sandboxPromptFull.rawValue) {
                paths.append(safeMode)
            }
            return paths.uniquePreservingOrder()
        }

        if preset.useCustomMode {
            for option in preset.selectedOptions {
                if let path = bundledOrFallbackPath(named: option.dylibName) {
                    paths.append(path)
                }
            }
            let custom = preset.customDylibPaths
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            paths.append(contentsOf: custom)
        }

        return paths.uniquePreservingOrder()
    }

    private func presetFromActiveProfile(for app: LaunchableAppInfo) -> AppLaunchPreset? {
        let parsed = ConfigProfileService.shared.loadActiveParsedProfile()
        guard let appRule = parsed.rules.first(where: { rule in
            guard rule.type == .app else { return false }
            let firstToken = rule.value.split(separator: ",", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
            return firstToken == app.bundleIdentifier
        }) else {
            return nil
        }

        let parts = appRule.value.split(separator: ",", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        let dylibPart = parts.count == 2 ? parts[1] : parts[0]
        let dylibs = dylibPart
            .components(separatedBy: "&&")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        return AppLaunchPreset(
            id: UUID(),
            appPath: app.appPath,
            bundleIdentifier: app.bundleIdentifier,
            useSafeMode: false,
            useSandboxExec: false,
            useCustomMode: true,
            selectedOptions: [],
            customDylibPaths: dylibs,
            updatedAt: Date()
        )
    }

    private func launchViaSandboxExec(appURL: URL) -> DylibInjectedLaunchResult {
        guard let executableURL = injectionService.appExecutableURL(appURL: appURL) else {
            return DylibInjectedLaunchResult(
                launchSucceeded: false,
                process: nil,
                mainPID: nil,
                launchMode: "sandbox_exec",
                warning: "App executable not found in bundle.",
                dylibPaths: []
            )
        }

        let profile = """
        (version 1)
        (allow default)
        (deny file-write*
            (regex #"^/Users/[^/]+/Library/(LaunchAgents|LaunchDaemons)/")
            (subpath "/Library/LaunchAgents")
            (subpath "/Library/LaunchDaemons")
        )
        """

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        process.arguments = ["-p", profile, executableURL.path]
        process.environment = ProcessInfo.processInfo.environment
        process.currentDirectoryURL = executableURL.deletingLastPathComponent()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            return DylibInjectedLaunchResult(
                launchSucceeded: true,
                process: process,
                mainPID: Int(process.processIdentifier),
                launchMode: "sandbox_exec",
                warning: nil,
                dylibPaths: []
            )
        } catch {
            return DylibInjectedLaunchResult(
                launchSucceeded: false,
                process: nil,
                mainPID: nil,
                launchMode: "sandbox_exec",
                warning: "sandbox-exec launch failed: \(error.localizedDescription)",
                dylibPaths: []
            )
        }
    }

    func appInfo(appURL: URL) -> LaunchableAppInfo? {
        let standardized = appURL.standardizedFileURL
        guard standardized.pathExtension.lowercased() == "app" else { return nil }
        guard fileManager.fileExists(atPath: standardized.path) else { return nil }

        let infoURL = standardized.appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: infoURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        else {
            return LaunchableAppInfo(
                appPath: standardized.path,
                displayName: standardized.deletingPathExtension().lastPathComponent,
                bundleIdentifier: "unknown.bundle.id"
            )
        }

        let bundleID = (plist["CFBundleIdentifier"] as? String) ?? "unknown.bundle.id"
        let name = (plist["CFBundleDisplayName"] as? String)
            ?? (plist["CFBundleName"] as? String)
            ?? standardized.deletingPathExtension().lastPathComponent

        return LaunchableAppInfo(appPath: standardized.path, displayName: name, bundleIdentifier: bundleID)
    }

    func importCustomApps(urls: [URL]) -> [LaunchableAppInfo] {
        let existing = Set(importedAppPaths())
        var merged = existing
        var importedInfos: [LaunchableAppInfo] = []

        for url in urls {
            let standardized = url.standardizedFileURL
            let appPath: String
            if standardized.pathExtension.lowercased() == "app" {
                appPath = standardized.path
            } else if standardized.hasDirectoryPath {
                // Finder may return app bundle as directory.
                appPath = standardized.path
            } else {
                continue
            }

            guard appPath.lowercased().hasSuffix(".app") else { continue }
            guard fileManager.fileExists(atPath: appPath) else { continue }

            merged.insert(appPath)
            if let info = appInfo(appURL: URL(fileURLWithPath: appPath)) {
                importedInfos.append(info)
            }
        }

        saveImportedAppPaths(Array(merged))
        invalidateScanCache()
        return importedInfos
    }

    func removeImportedApp(path: String) {
        var existing = Set(importedAppPaths())
        existing.remove(path)
        saveImportedAppPaths(Array(existing))
        invalidateScanCache()
    }

    func isLaunchInProgress(appPath: String) -> Bool {
        stateQueue.sync { launchingAppPaths.contains(appPath) }
    }

    func invalidateScanCache() {
        stateQueue.sync {
            cachedScanResult = []
            cachedScanAt = nil
        }
    }

    private func presetStorageURL() -> URL {
        let base = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/BeforeInstall", isDirectory: true)
        return base.appendingPathComponent("app-launch-presets.json", isDirectory: false)
    }

    private func persistedMarkerURL(for executableURL: URL) -> URL {
        executableURL.deletingLastPathComponent().appendingPathComponent(".beforeinstall-persist.json", isDirectory: false)
    }

    private func escapeSingleQuotes(_ value: String) -> String {
        value.replacingOccurrences(of: "'", with: "'\\''")
    }

    private func importedAppPaths() -> [String] {
        (UserDefaults.standard.array(forKey: importedAppPathsDefaultsKey) as? [String] ?? [])
            .map { URL(fileURLWithPath: $0).standardizedFileURL.path }
            .filter { $0.lowercased().hasSuffix(".app") && fileManager.fileExists(atPath: $0) }
    }

    private func saveImportedAppPaths(_ paths: [String]) {
        let normalized = paths
            .map { URL(fileURLWithPath: $0).standardizedFileURL.path }
            .filter { $0.lowercased().hasSuffix(".app") && fileManager.fileExists(atPath: $0) }
            .uniquePreservingOrder()
        UserDefaults.standard.set(normalized, forKey: importedAppPathsDefaultsKey)
    }

    private func beginLaunch(appPath: String) -> Bool {
        stateQueue.sync {
            if launchingAppPaths.contains(appPath) {
                return false
            }
            launchingAppPaths.insert(appPath)
            return true
        }
    }

    private func endLaunch(appPath: String) {
        _ = stateQueue.sync {
            launchingAppPaths.remove(appPath)
        }
    }

    private func runningApplication(for app: LaunchableAppInfo) -> NSRunningApplication? {
        if app.bundleIdentifier != "unknown.bundle.id",
           let match = NSRunningApplication.runningApplications(withBundleIdentifier: app.bundleIdentifier).first
        {
            return match
        }

        return NSWorkspace.shared.runningApplications.first { running in
            running.bundleURL?.standardizedFileURL.path == app.appPath
        }
    }

    private func bundledOrFallbackPath(named dylibName: String) -> String? {
        if let resolved = injectionService.bundledDylibURL(named: dylibName)?.path {
            return resolved
        }

        var candidates: [String] = []
        if let resourceURL = Bundle.main.resourceURL?.standardizedFileURL.path {
            candidates.append("\(resourceURL)/Dylibs/\(dylibName)")
            candidates.append("\(resourceURL)/\(dylibName)")
        }

        let cwd = URL(fileURLWithPath: fileManager.currentDirectoryPath, isDirectory: true).standardizedFileURL.path
        candidates.append("\(cwd)/Resources/Dylibs/\(dylibName)")
        candidates.append("\(cwd)/Resources/\(dylibName)")

        return candidates.first
    }

    private func terminate(runningApplication: NSRunningApplication) -> Bool {
        if runningApplication.isTerminated {
            return true
        }

        _ = runningApplication.terminate()
        let softDeadline = Date().addingTimeInterval(2.2)
        while Date() < softDeadline {
            if runningApplication.isTerminated {
                return true
            }
            Thread.sleep(forTimeInterval: 0.1)
        }

        _ = runningApplication.forceTerminate()
        let hardDeadline = Date().addingTimeInterval(2.8)
        while Date() < hardDeadline {
            if runningApplication.isTerminated {
                return true
            }
            Thread.sleep(forTimeInterval: 0.1)
        }

        return runningApplication.isTerminated
    }

    private func waitUntilAppStopsRunning(_ app: LaunchableAppInfo, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if runningApplication(for: app) == nil {
                return true
            }
            Thread.sleep(forTimeInterval: 0.12)
        }
        return runningApplication(for: app) == nil
    }
}
