import Foundation
import Darwin

struct IsolatedWorkspace {
    var rootURL: URL
    var homeURL: URL
    var tempURL: URL
}

struct IsolatedRunHandle {
    var workspace: IsolatedWorkspace
    var process: Process?
    var launchDescription: String
    var warning: String?
}

struct ProcessTerminationSnapshot {
    var didExit: Bool
    var wasSignaled: Bool
    var forcedKill: Bool
}

final class IsolatedRunner {
    private let fileManager = FileManager.default
    private let injectionService = DylibInjectionService()

    func prepareWorkspace() throws -> IsolatedWorkspace {
        let base = URL(fileURLWithPath: "/tmp/bf", isDirectory: true)
        try fileManager.createDirectory(at: base, withIntermediateDirectories: true)

        let root = base
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let home = root.appendingPathComponent("home", isDirectory: true)
        let temp = root.appendingPathComponent("tmp", isDirectory: true)

        try fileManager.createDirectory(at: home, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: temp, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: home.appendingPathComponent("Library", isDirectory: true), withIntermediateDirectories: true)
        try fileManager.createDirectory(at: home.appendingPathComponent("Library/Application Support", isDirectory: true), withIntermediateDirectories: true)
        try fileManager.createDirectory(at: home.appendingPathComponent("Library/Preferences", isDirectory: true), withIntermediateDirectories: true)
        try fileManager.createDirectory(at: home.appendingPathComponent("Library/Caches", isDirectory: true), withIntermediateDirectories: true)
        try fileManager.createDirectory(at: home.appendingPathComponent("Library/LaunchAgents", isDirectory: true), withIntermediateDirectories: true)

        return IsolatedWorkspace(rootURL: root, homeURL: home, tempURL: temp)
    }

    func cleanupWorkspace(_ workspace: IsolatedWorkspace?) {
        guard let workspace else { return }
        try? fileManager.removeItem(at: workspace.rootURL)
    }

    func cleanupAllWorkspaces() -> Int {
        let parent = URL(fileURLWithPath: "/tmp/bf", isDirectory: true)
        guard let children = try? fileManager.contentsOfDirectory(at: parent, includingPropertiesForKeys: nil) else {
            return 0
        }

        var removed = 0
        for child in children {
            do {
                try fileManager.removeItem(at: child)
                removed += 1
            } catch {
                continue
            }
        }
        return removed
    }

    func launch(
        fileURL: URL,
        detectedType: SupportedFileType,
        request: AnalysisRequest,
        workspace: IsolatedWorkspace
    ) -> RuntimeLaunchContext {
        switch detectedType {
        case .appBundle:
            return launchApp(fileURL: fileURL, request: request, workspace: workspace)
        case .shellScript, .pythonScript, .javaScript, .appleScript, .machO:
            guard request.allowNonAppDynamicExecution else {
                return RuntimeLaunchContext(
                    result: RuntimeLaunchResult(
                        launchSucceeded: false,
                        mainPID: nil,
                        terminationStatus: nil,
                        terminationReason: nil,
                        warning: "For safety, execution for non-.app bundle files is disabled in settings."
                    ),
                    process: nil,
                    launchResult: nil
                )
            }
            return launchExecutableLike(fileURL: fileURL, workspace: workspace)
        case .dmg, .pkg, .archive, .plist, .dylib, .unknown:
            return RuntimeLaunchContext(
                result: RuntimeLaunchResult(
                    launchSucceeded: false,
                    mainPID: nil,
                    terminationStatus: nil,
                    terminationReason: nil,
                    warning: "This file type is observed in restricted mode without direct execution in v1."
                ),
                process: nil,
                launchResult: nil
            )
        }
    }

    func terminateAndWait(process: Process, timeoutSeconds: TimeInterval = 4) -> ProcessTerminationSnapshot {
        var forcedKill = false

        if process.isRunning {
            process.terminate()
        }

        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.08)
        }

        if process.isRunning {
            process.interrupt()
            let secondDeadline = Date().addingTimeInterval(1.2)
            while process.isRunning && Date() < secondDeadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
        }

        if process.isRunning {
            forcedKill = true
            kill(process.processIdentifier, SIGKILL)
            let killDeadline = Date().addingTimeInterval(0.8)
            while process.isRunning && Date() < killDeadline {
                Thread.sleep(forTimeInterval: 0.03)
            }
        }

        let didExit = !process.isRunning
        // Avoid querying Process terminationReason here to prevent rare NSException
        // race windows reported during interactive stop on some app samples.
        let wasSignaled = forcedKill
        return ProcessTerminationSnapshot(didExit: didExit, wasSignaled: wasSignaled, forcedKill: forcedKill)
    }

    func terminateAndWait(pid: Int32, timeoutSeconds: TimeInterval = 4) -> ProcessTerminationSnapshot {
        var forcedKill = false

        if processExists(pid) {
            kill(pid, SIGTERM)
        }

        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while processExists(pid) && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.08)
        }

        if processExists(pid) {
            kill(pid, SIGINT)
            let secondDeadline = Date().addingTimeInterval(1.2)
            while processExists(pid) && Date() < secondDeadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
        }

        if processExists(pid) {
            forcedKill = true
            kill(pid, SIGKILL)
            let killDeadline = Date().addingTimeInterval(0.8)
            while processExists(pid) && Date() < killDeadline {
                Thread.sleep(forTimeInterval: 0.03)
            }
        }

        let didExit = !processExists(pid)
        return ProcessTerminationSnapshot(didExit: didExit, wasSignaled: forcedKill, forcedKill: forcedKill)
    }

    private func launchApp(fileURL: URL, request: AnalysisRequest, workspace: IsolatedWorkspace) -> RuntimeLaunchContext {
        var notes: [String] = []
        var dylibPaths: [String] = []
        var hideAttempted = false

        if request.preferBackgroundAppLaunch {
            hideAttempted = true
            if let noWindow = injectionService.bundledDylibURL(.noWindow)?.path {
                dylibPaths = [noWindow]
                notes.append("Injected no_window.dylib via DYLD_INSERT_LIBRARIES for hidden-window launch mode.")
            } else {
                notes.append("no_window.dylib not found in bundled resources; fallback to normal executable launch.")
            }
        } else {
            notes.append("Hidden-window launch preference is disabled.")
        }

        if request.depth == .deep {
            notes.append("Deep mode keeps the target app interactive for richer telemetry.")
        }

        let launch = injectionService.launchAppWithInjection(
            appURL: fileURL,
            environment: makeIsolatedEnvironment(workspace: workspace),
            dylibPaths: dylibPaths,
            workingDirectory: workspace.homeURL
        )

        if let warning = launch.warning {
            notes.append(warning)
        }
        if !launch.dylibPaths.isEmpty {
            notes.append("DYLD_INSERT_LIBRARIES=\(launch.dylibPaths.joined(separator: ":"))")
        }

        let launchResult = DynamicLaunchResult(
            launchMode: launch.launchMode,
            launchSucceeded: launch.launchSucceeded,
            hideAttempted: hideAttempted,
            hideSucceeded: hideAttempted ? launch.launchSucceeded : nil,
            appLikelyActivatedForeground: nil,
            appLikelyDisplayedWindow: hideAttempted ? !launch.launchSucceeded : nil,
            interactionRequired: request.depth == .deep,
            notes: notes,
            runningApplicationPID: launch.mainPID
        )

        return RuntimeLaunchContext(
            result: RuntimeLaunchResult(
                launchSucceeded: launch.launchSucceeded,
                mainPID: launch.mainPID,
                terminationStatus: nil,
                terminationReason: launch.warning,
                warning: launch.warning ?? (notes.isEmpty ? nil : notes.joined(separator: " | "))
            ),
            process: launch.process,
            launchResult: launchResult
        )
    }

    private func launchExecutableLike(fileURL: URL, workspace: IsolatedWorkspace) -> RuntimeLaunchContext {
        if isTextScript(fileURL) {
            return launchProcess(executableURL: URL(fileURLWithPath: "/bin/zsh"), arguments: [fileURL.path], workspace: workspace)
        }

        return launchProcess(executableURL: fileURL, arguments: [], workspace: workspace)
    }

    private func launchProcess(executableURL: URL, arguments: [String], workspace: IsolatedWorkspace) -> RuntimeLaunchContext {
        let process = Process()
        process.executableURL = executableURL
        process.arguments = arguments
        // Prevent verbose target logs from flooding the host app console and UI.
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        var env = ProcessInfo.processInfo.environment
        env["HOME"] = workspace.homeURL.path
        env["CFFIXED_USER_HOME"] = workspace.homeURL.path
        env["TMPDIR"] = workspace.tempURL.path + "/"
        env["__CF_USER_TEXT_ENCODING"] = "0x1F5:0x0:0x0"
        process.environment = env
        process.currentDirectoryURL = workspace.homeURL

        do {
            try process.run()
            return RuntimeLaunchContext(
                result: RuntimeLaunchResult(
                    launchSucceeded: true,
                    mainPID: Int(process.processIdentifier),
                    terminationStatus: nil,
                    terminationReason: nil,
                    warning: nil
                ),
                process: process,
                launchResult: nil
            )
        } catch {
            return RuntimeLaunchContext(
                result: RuntimeLaunchResult(
                    launchSucceeded: false,
                    mainPID: nil,
                    terminationStatus: nil,
                    terminationReason: error.localizedDescription,
                    warning: "Failed to launch process: \(error.localizedDescription)"
                ),
                process: nil,
                launchResult: nil
            )
        }
    }

    private func makeIsolatedEnvironment(workspace: IsolatedWorkspace) -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        env["HOME"] = workspace.homeURL.path
        env["CFFIXED_USER_HOME"] = workspace.homeURL.path
        env["TMPDIR"] = workspace.tempURL.path + "/"
        env["__CF_USER_TEXT_ENCODING"] = "0x1F5:0x0:0x0"
        return env
    }

    private func processExists(_ pid: Int32) -> Bool {
        if pid <= 0 { return false }
        if kill(pid, 0) == 0 { return true }
        return errno == EPERM
    }

    private func isTextScript(_ fileURL: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: fileURL) else {
            return false
        }
        defer { try? handle.close() }

        let header = (try? handle.read(upToCount: 64)) ?? Data()
        guard let text = String(data: header, encoding: .utf8) else {
            return false
        }
        return text.hasPrefix("#!")
    }
}
