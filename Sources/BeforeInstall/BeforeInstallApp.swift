import SwiftUI
import AppKit
import Foundation

final class BeforeInstallAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // 某些调试环境下窗口不会自动前置，主动激活避免“已运行但无可见窗口”。
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

@main
struct BeforeInstallApp: App {
    @NSApplicationDelegateAdaptor(BeforeInstallAppDelegate.self) private var appDelegate

    @StateObject private var settings: AppSettingsStore
    @StateObject private var viewModel: AnalysisViewModel
    @StateObject private var updateManager: AppUpdateManager
    @State private var isWelcomePresented = false
    @AppStorage("uiFontScale") private var uiFontScale = 1.0

    init() {
        let sharedSettings = AppSettingsStore()
        let sharedUpdateManager = AppUpdateManager(settings: sharedSettings)
        _settings = StateObject(wrappedValue: sharedSettings)
        _viewModel = StateObject(wrappedValue: AnalysisViewModel(settings: sharedSettings))
        _updateManager = StateObject(wrappedValue: sharedUpdateManager)
    }

    var body: some Scene {
        WindowGroup {
            ContentView(viewModel: viewModel, settings: settings)
                .frame(minWidth: 980, minHeight: 720)
                .preferredColorScheme(preferredColorScheme)
                .environment(\.appFontScale, CGFloat(normalizedFontScale))
                .onAppear {
                    DiagnosticsLogService.shared.log(.info, category: "app.lifecycle", "App launched and main window appeared.")
                    if settings.shouldPresentWelcomeOnStartup() {
                        isWelcomePresented = true
                    }
                    updateManager.scheduleStartupAutoCheckIfNeeded()
                }
                .sheet(isPresented: $isWelcomePresented) {
                    WelcomeView(settings: settings, isPresented: $isWelcomePresented)
                }
        }
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button(Localizer.text("menu.about", language: settings.language)) {
                    NSApp.orderFrontStandardAboutPanel(nil)
                }
            }

            CommandMenu(Localizer.text("menu.help", language: settings.language)) {
                Button(Localizer.text("menu.welcome", language: settings.language)) {
                    isWelcomePresented = true
                }

                Button(settings.language == .zhHans ? "检查更新" : "Check for Updates") {
                    updateManager.triggerManualUpdateCheck()
                }

                Button(Localizer.text("menu.openFullDisk", language: settings.language)) {
                    openPrivacyPane(anchor: "Privacy_AllFiles")
                }
            }
        }

        Settings {
            SettingsView(settings: settings, viewModel: viewModel, updateManager: updateManager)
                .frame(minWidth: 760, minHeight: 560, alignment: .topLeading)
                .preferredColorScheme(preferredColorScheme)
                .environment(\.appFontScale, CGFloat(normalizedFontScale))
                .id("settings-\(settings.appearance.rawValue)-\(settings.language.rawValue)")
        }
    }

    private func openPrivacyPane(anchor: String) {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?\(anchor)") else {
            return
        }
        NSWorkspace.shared.open(url)
    }

    private var preferredColorScheme: ColorScheme? {
        switch settings.appearance {
        case .system:
            return nil
        case .light:
            return .light
        case .dark:
            return .dark
        }
    }

    private var normalizedFontScale: Double {
        min(max(uiFontScale, 0.85), 1.40)
    }
}

private enum AppRepositoryInfo {
    static let owner = "dazi2011"
    static let name = "Beforeinstall"
    static let preferredZipAssetName = "app.zip"

    static var repositoryURL: URL {
        URL(string: "https://github.com/\(owner)/\(name)")!
    }

    static var releasesAPIURL: URL {
        URL(string: "https://api.github.com/repos/\(owner)/\(name)/releases?per_page=20")!
    }
}

private struct GitHubReleaseAsset: Decodable {
    var name: String
    var browserDownloadURL: URL

    private enum CodingKeys: String, CodingKey {
        case name
        case browserDownloadURL = "browser_download_url"
    }
}

private struct GitHubRelease: Decodable {
    var tagName: String
    var name: String?
    var draft: Bool
    var prerelease: Bool
    var publishedAt: Date?
    var assets: [GitHubReleaseAsset]

    private enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case name
        case draft
        case prerelease
        case publishedAt = "published_at"
        case assets
    }
}

private struct ComparableVersion: Comparable {
    var major: Int
    var minor: Int
    var patch: Int
    var prerelease: String?

    init?(raw: String) {
        var cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if cleaned.hasPrefix("v") {
            cleaned.removeFirst()
        }
        if let plusIndex = cleaned.firstIndex(of: "+") {
            cleaned = String(cleaned[..<plusIndex])
        }

        var numericPart = ""
        var suffix = ""
        var switched = false
        for character in cleaned {
            if !switched, character.isNumber || character == "." {
                numericPart.append(character)
            } else {
                switched = true
                suffix.append(character)
            }
        }

        let normalizedNumeric = numericPart.trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let pieces = normalizedNumeric.split(separator: ".").compactMap { Int($0) }
        guard !pieces.isEmpty else { return nil }

        major = pieces.count > 0 ? pieces[0] : 0
        minor = pieces.count > 1 ? pieces[1] : 0
        patch = pieces.count > 2 ? pieces[2] : 0

        let normalizedSuffix = suffix
            .trimmingCharacters(in: CharacterSet(charactersIn: "-._ "))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        prerelease = normalizedSuffix.isEmpty ? nil : normalizedSuffix
    }

    static func < (lhs: ComparableVersion, rhs: ComparableVersion) -> Bool {
        if lhs.major != rhs.major { return lhs.major < rhs.major }
        if lhs.minor != rhs.minor { return lhs.minor < rhs.minor }
        if lhs.patch != rhs.patch { return lhs.patch < rhs.patch }

        switch (lhs.prerelease, rhs.prerelease) {
        case (nil, nil):
            return false
        case (nil, _):
            return false
        case (_, nil):
            return true
        case let (left?, right?):
            return left.compare(right, options: [.numeric, .caseInsensitive]) == .orderedAscending
        }
    }
}

private struct UpdateResolution {
    var release: GitHubRelease
    var asset: GitHubReleaseAsset
    var releaseVersionText: String
    var releaseVersion: ComparableVersion?
    var currentVersionText: String
    var currentVersion: ComparableVersion?
}

private enum AppUpdateError: LocalizedError {
    case noEligibleRelease
    case missingZipAsset
    case invalidResponse
    case cannotDetermineCurrentAppBundle
    case appInstallLocationNotWritable
    case commandFailed(String)
    case noAppBundleInsideZip

    var errorDescription: String? {
        switch self {
        case .noEligibleRelease:
            return "No eligible release found for current update channel."
        case .missingZipAsset:
            return "No eligible release contains app.zip."
        case .invalidResponse:
            return "GitHub API response is invalid."
        case .cannotDetermineCurrentAppBundle:
            return "Current app bundle path is unavailable."
        case .appInstallLocationNotWritable:
            return "The app install location is not writable."
        case let .commandFailed(message):
            return "Command failed: \(message)"
        case .noAppBundleInsideZip:
            return "No .app bundle found in downloaded zip."
        }
    }
}

@MainActor
final class AppUpdateManager: ObservableObject {
    @Published var isChecking = false
    @Published var isInstalling = false
    @Published var updateAvailable = false
    @Published var latestReleaseDisplayText: String?
    @Published var statusMessage = ""

    private var latestAssetURL: URL?
    private var latestReleaseVersionText: String?
    private var latestReleaseVersion: ComparableVersion?
    private var hasScheduledStartupCheck = false
    private let settings: AppSettingsStore
    private let defaults: UserDefaults
    private let fileManager = FileManager.default
    private let autoCheckMinInterval: TimeInterval = 6 * 60 * 60

    private enum Keys {
        static let lastAutoUpdateCheckAt = "beforeinstall.lastAutoUpdateCheckAt"
    }

    init(settings: AppSettingsStore, defaults: UserDefaults = .standard) {
        self.settings = settings
        self.defaults = defaults
    }

    var repositoryURL: URL {
        AppRepositoryInfo.repositoryURL
    }

    func scheduleStartupAutoCheckIfNeeded() {
        guard !hasScheduledStartupCheck else { return }
        hasScheduledStartupCheck = true

        guard settings.autoCheckAndInstallUpdates else { return }
        let now = Date()
        let lastChecked = defaults.object(forKey: Keys.lastAutoUpdateCheckAt) as? Date ?? .distantPast
        guard now.timeIntervalSince(lastChecked) >= autoCheckMinInterval else { return }

        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            guard let self else { return }
            await self.checkForUpdates(initiatedManually: false, autoInstallWhenAvailable: true)
        }
    }

    func triggerManualUpdateCheck() {
        Task { [weak self] in
            guard let self else { return }
            await self.checkForUpdates(initiatedManually: true, autoInstallWhenAvailable: false)
        }
    }

    func triggerManualInstallIfAvailable() {
        Task { [weak self] in
            guard let self else { return }
            await self.installLatestUpdateIfAvailable(initiatedManually: true)
        }
    }

    private func checkForUpdates(initiatedManually: Bool, autoInstallWhenAvailable: Bool) async {
        guard !isChecking, !isInstalling else { return }
        isChecking = true
        statusMessage = localized("正在检查更新...", "Checking for updates...")

        defer {
            isChecking = false
        }

        do {
            let resolution = try await resolveLatestRelease(allowPrerelease: settings.enablePrereleaseUpdates)
            defaults.set(Date(), forKey: Keys.lastAutoUpdateCheckAt)

            latestAssetURL = resolution.asset.browserDownloadURL
            latestReleaseVersionText = resolution.releaseVersionText
            latestReleaseVersion = resolution.releaseVersion
            latestReleaseDisplayText = releaseDisplayText(release: resolution.release)

            if let current = resolution.currentVersion, let remote = resolution.releaseVersion {
                updateAvailable = remote > current
            } else if let currentText = ComparableVersion(raw: resolution.currentVersionText),
                      let remoteText = ComparableVersion(raw: resolution.releaseVersionText)
            {
                updateAvailable = remoteText > currentText
            } else {
                updateAvailable = resolution.releaseVersionText != resolution.currentVersionText
            }

            if updateAvailable {
                statusMessage = localized(
                    "发现新版本 \(resolution.releaseVersionText)。",
                    "New version \(resolution.releaseVersionText) is available."
                )
                if autoInstallWhenAvailable {
                    await installLatestUpdateIfAvailable(initiatedManually: false)
                }
            } else if initiatedManually {
                statusMessage = localized("当前已是最新版本。", "You are on the latest version.")
            } else {
                statusMessage = localized("自动检查完成：当前已是最新版本。", "Auto-check finished: already up to date.")
            }
        } catch {
            updateAvailable = false
            let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            statusMessage = localized("检查更新失败：\(message)", "Update check failed: \(message)")
        }
    }

    private func resolveLatestRelease(allowPrerelease: Bool) async throws -> UpdateResolution {
        var request = URLRequest(url: AppRepositoryInfo.releasesAPIURL)
        request.httpMethod = "GET"
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("BeforeInstall/\(currentVersionText())", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, 200..<300 ~= http.statusCode else {
            throw AppUpdateError.invalidResponse
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let releases = try decoder.decode([GitHubRelease].self, from: data)
        let preferredName = AppRepositoryInfo.preferredZipAssetName.lowercased()
        let eligibleReleases = releases.filter { release in
            guard !release.draft else { return false }
            return allowPrerelease || !release.prerelease
        }

        guard !eligibleReleases.isEmpty else {
            throw AppUpdateError.noEligibleRelease
        }

        for release in eligibleReleases {
            let asset = release.assets.first(where: { $0.name.lowercased() == preferredName })
                ?? release.assets.first(where: { $0.name.lowercased().hasSuffix(".zip") })
            guard let asset else { continue }

            let releaseVersionText = normalizedReleaseVersionText(from: release.tagName)
            return UpdateResolution(
                release: release,
                asset: asset,
                releaseVersionText: releaseVersionText,
                releaseVersion: ComparableVersion(raw: releaseVersionText),
                currentVersionText: currentVersionText(),
                currentVersion: ComparableVersion(raw: currentVersionText())
            )
        }

        throw AppUpdateError.missingZipAsset
    }

    private func installLatestUpdateIfAvailable(initiatedManually: Bool) async {
        guard !isInstalling else { return }
        guard updateAvailable, let assetURL = latestAssetURL else {
            if initiatedManually {
                statusMessage = localized("没有可安装的新版本。", "No update available to install.")
            }
            return
        }

        isInstalling = true
        defer {
            isInstalling = false
        }

        do {
            statusMessage = localized("正在下载更新包...", "Downloading update package...")
            let (downloadedURL, _) = try await URLSession.shared.download(from: assetURL)

            let appBundleURL = Bundle.main.bundleURL.standardizedFileURL
            guard appBundleURL.pathExtension.lowercased() == "app" else {
                throw AppUpdateError.cannotDetermineCurrentAppBundle
            }

            let parentPath = appBundleURL.deletingLastPathComponent().path
            guard fileManager.isWritableFile(atPath: parentPath) else {
                throw AppUpdateError.appInstallLocationNotWritable
            }

            let workspace = fileManager.temporaryDirectory.appendingPathComponent("beforeinstall-update-\(UUID().uuidString)")
            try fileManager.createDirectory(at: workspace, withIntermediateDirectories: true)
            let zipURL = workspace.appendingPathComponent("app.zip")
            try fileManager.copyItem(at: downloadedURL, to: zipURL)

            let extractedURL = workspace.appendingPathComponent("extracted", isDirectory: true)
            try fileManager.createDirectory(at: extractedURL, withIntermediateDirectories: true)
            try runCommand(
                executable: "/usr/bin/ditto",
                arguments: ["-x", "-k", zipURL.path, extractedURL.path]
            )

            guard let newAppURL = findFirstAppBundle(in: extractedURL) else {
                throw AppUpdateError.noAppBundleInsideZip
            }

            let scriptURL = workspace.appendingPathComponent("install_update.sh")
            let script = installerScriptContent(
                currentAppURL: appBundleURL,
                newAppURL: newAppURL,
                currentPID: ProcessInfo.processInfo.processIdentifier
            )
            try script.write(to: scriptURL, atomically: true, encoding: .utf8)
            try fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o755)], ofItemAtPath: scriptURL.path)

            let launchCommand = "nohup \(shellQuoted(scriptURL.path)) >/tmp/beforeinstall-updater.log 2>&1 &"
            try runCommand(executable: "/bin/zsh", arguments: ["-lc", launchCommand])

            statusMessage = localized("更新安装已启动，应用将退出并重新打开。", "Installer started. The app will quit and relaunch.")
            NSApp.terminate(nil)
        } catch {
            let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            statusMessage = localized("安装更新失败：\(message)", "Update installation failed: \(message)")
        }
    }

    private func releaseDisplayText(release: GitHubRelease) -> String {
        if let name = release.name, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return name
        }
        return release.tagName
    }

    private func currentVersionText() -> String {
        let info = Bundle.main.infoDictionary
        return (info?["CFBundleShortVersionString"] as? String) ?? "0.0.0"
    }

    private func normalizedReleaseVersionText(from tag: String) -> String {
        let trimmed = tag.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("v") {
            return String(trimmed.dropFirst())
        }
        return trimmed
    }

    private func findFirstAppBundle(in directory: URL) -> URL? {
        if directory.pathExtension.lowercased() == "app" {
            return directory
        }
        guard let enumerator = fileManager.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else {
            return nil
        }

        for case let url as URL in enumerator {
            if url.pathExtension.lowercased() == "app" {
                return url
            }
        }
        return nil
    }

    private func runCommand(executable: String, arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let stderrPipe = Pipe()
        process.standardError = stderrPipe
        process.standardOutput = Pipe()

        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let errorData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            let errorText = String(data: errorData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            throw AppUpdateError.commandFailed(errorText.isEmpty ? "\(executable) failed." : errorText)
        }
    }

    private func installerScriptContent(currentAppURL: URL, newAppURL: URL, currentPID: Int32) -> String {
        let currentPath = shellQuoted(currentAppURL.path)
        let newPath = shellQuoted(newAppURL.path)

        return """
        #!/bin/zsh
        set -e

        CURRENT_APP=\(currentPath)
        NEW_APP=\(newPath)
        CURRENT_PID=\(currentPID)
        BACKUP_APP="${CURRENT_APP}.backup.$(/bin/date +%s)"

        /bin/sleep 1
        while /bin/kill -0 "${CURRENT_PID}" >/dev/null 2>&1; do
          /bin/sleep 1
        done

        if [ -e "${CURRENT_APP}" ]; then
          /bin/mv "${CURRENT_APP}" "${BACKUP_APP}"
        fi

        /usr/bin/ditto "${NEW_APP}" "${CURRENT_APP}"
        /usr/bin/xattr -dr com.apple.quarantine "${CURRENT_APP}" >/dev/null 2>&1 || true
        /usr/bin/open "${CURRENT_APP}"
        """
    }

    private func shellQuoted(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "'", with: "'\\''")
        return "'\(escaped)'"
    }

    private func localized(_ zh: String, _ en: String) -> String {
        settings.language == .zhHans ? zh : en
    }
}
