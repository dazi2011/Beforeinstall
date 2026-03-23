import Foundation

enum BuiltInDylib: String, CaseIterable, Sendable {
    case noAppleScript = "no_applescript.dylib"
    case noAVCapture = "no_avcapture.dylib"
    case noClipboard = "no_clipboard.dylib"
    case noDefaults = "no_defaults.dylib"
    case noFileWrite = "no_file_write.dylib"
    case noKeychain = "no_keychain.dylib"
    case noLaunchd = "no_launchd.dylib"
    case noNetwork = "no_network.dylib"
    case noProcess = "no_process.dylib"
    case noScreenshot = "no_screenshot.dylib"
    case noTerminal = "no_terminal.dylib"
    case noWindow = "no_window.dylib"
    case sandboxPromptFull = "sandbox_prompt_full.dylib"
}

struct DylibInjectedLaunchResult {
    var launchSucceeded: Bool
    var process: Process?
    var mainPID: Int?
    var launchMode: String
    var warning: String?
    var dylibPaths: [String]
}

final class DylibInjectionService {
    private let fileManager = FileManager.default

    func bundledDylibURL(_ dylib: BuiltInDylib) -> URL? {
        bundledDylibURL(named: dylib.rawValue)
    }

    func bundledDylibURL(named dylibName: String) -> URL? {
        if let nested = Bundle.main.url(forResource: dylibName, withExtension: nil, subdirectory: "Dylibs") {
            return nested.standardizedFileURL
        }
        if let root = Bundle.main.url(forResource: dylibName, withExtension: nil) {
            return root.standardizedFileURL
        }

        var candidates: [URL] = []
        if let resourceURL = Bundle.main.resourceURL {
            candidates.append(resourceURL.appendingPathComponent(dylibName))
            candidates.append(resourceURL.appendingPathComponent("Dylibs", isDirectory: true).appendingPathComponent(dylibName))
        }

        let currentDirectory = URL(fileURLWithPath: fileManager.currentDirectoryPath, isDirectory: true)
        candidates.append(currentDirectory.appendingPathComponent("Resources/Dylibs", isDirectory: true).appendingPathComponent(dylibName))
        candidates.append(currentDirectory.appendingPathComponent("Resources", isDirectory: true).appendingPathComponent(dylibName))

        for candidate in candidates.map({ $0.standardizedFileURL }) {
            if fileManager.fileExists(atPath: candidate.path) {
                return candidate
            }
        }

        return nil
    }

    func appExecutableURL(appURL: URL) -> URL? {
        let infoURL = appURL.appendingPathComponent("Contents/Info.plist")
        if let data = try? Data(contentsOf: infoURL),
           let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
           let executableName = plist["CFBundleExecutable"] as? String,
           !executableName.isEmpty
        {
            let executableURL = appURL.appendingPathComponent("Contents/MacOS/\(executableName)")
            if fileManager.fileExists(atPath: executableURL.path) {
                return executableURL
            }
        }

        let macOSDir = appURL.appendingPathComponent("Contents/MacOS", isDirectory: true)
        guard let candidates = try? fileManager.contentsOfDirectory(at: macOSDir, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
            return nil
        }

        return candidates.first(where: { fileManager.isExecutableFile(atPath: $0.path) }) ?? candidates.first
    }

    func launchAppWithInjection(
        appURL: URL,
        environment: [String: String],
        dylibPaths: [String],
        workingDirectory: URL?
    ) -> DylibInjectedLaunchResult {
        let requested = dylibPaths.uniquePreservingOrder()
        let existing = requested.filter { fileManager.fileExists(atPath: $0) }

        if requested.isEmpty {
            return launchViaOpenCommand(appURL: appURL, environment: environment, workingDirectory: workingDirectory)
        }
        if existing.isEmpty {
            return DylibInjectedLaunchResult(
                launchSucceeded: false,
                process: nil,
                mainPID: nil,
                launchMode: "dyld_insert_libraries",
                warning: "No selected dylib could be resolved on disk. Requested paths count=\(requested.count)",
                dylibPaths: requested
            )
        }

        guard let executableURL = appExecutableURL(appURL: appURL) else {
            return DylibInjectedLaunchResult(
                launchSucceeded: false,
                process: nil,
                mainPID: nil,
                launchMode: "dyld_insert_libraries",
                warning: "App executable not found in bundle",
                dylibPaths: requested
            )
        }

        var env = environment
        env["DYLD_INSERT_LIBRARIES"] = existing.joined(separator: ":")

        if env["OS_ACTIVITY_MODE"] == nil {
            env["OS_ACTIVITY_MODE"] = "disable"
        }

        let process = Process()
        process.executableURL = executableURL
        process.arguments = []
        process.environment = env
        process.currentDirectoryURL = workingDirectory ?? executableURL.deletingLastPathComponent()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            return DylibInjectedLaunchResult(
                launchSucceeded: true,
                process: process,
                mainPID: Int(process.processIdentifier),
                launchMode: "dyld_insert_libraries",
                warning: nil,
                dylibPaths: existing
            )
        } catch {
            return DylibInjectedLaunchResult(
                launchSucceeded: false,
                process: nil,
                mainPID: nil,
                launchMode: "dyld_insert_libraries",
                warning: "Failed to launch app executable: \(error.localizedDescription)",
                dylibPaths: existing
            )
        }
    }

    private func launchViaOpenCommand(
        appURL: URL,
        environment: [String: String],
        workingDirectory: URL?
    ) -> DylibInjectedLaunchResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = [appURL.path]
        process.environment = environment
        process.currentDirectoryURL = workingDirectory ?? appURL.deletingLastPathComponent()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            return DylibInjectedLaunchResult(
                launchSucceeded: true,
                process: process,
                mainPID: Int(process.processIdentifier),
                launchMode: "launch_services_open",
                warning: nil,
                dylibPaths: []
            )
        } catch {
            return DylibInjectedLaunchResult(
                launchSucceeded: false,
                process: nil,
                mainPID: nil,
                launchMode: "launch_services_open",
                warning: "Failed to open app via LaunchServices: \(error.localizedDescription)",
                dylibPaths: []
            )
        }
    }
}
