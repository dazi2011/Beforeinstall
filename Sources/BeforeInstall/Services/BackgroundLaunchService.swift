import Foundation
import AppKit

// This service provides best-effort background app launch.
// It cannot guarantee that every third-party app will stay hidden or avoid foreground activation.
final class BackgroundLaunchService {
    private final class LaunchCallbackBox: @unchecked Sendable {
        var app: NSRunningApplication?
        var error: Error?
    }

    func launchApp(
        appURL: URL,
        environment: [String: String],
        options: BackgroundLaunchOptions
    ) -> DynamicLaunchResult {
        let preFrontPID = MainThreadSync.frontmostPID()
        var notes: [String] = []
        var launchSucceeded = false
        var runningPID: Int?
        var hideAttempted = false
        var hideSucceeded: Bool?
        var likelyActivatedForeground: Bool?
        var likelyDisplayedWindow: Bool?
        var launchEnvironment = environment

        // Best-effort log noise reduction for child apps launched during analysis.
        // Some apps may still emit stderr/os_log messages that cannot be fully suppressed.
        if launchEnvironment["OS_ACTIVITY_MODE"] == nil {
            launchEnvironment["OS_ACTIVITY_MODE"] = "disable"
        }

        let config = NSWorkspace.OpenConfiguration()
        config.activates = !options.preferNonActivatingLaunch
        config.createsNewApplicationInstance = true
        config.addsToRecentItems = false
        config.environment = launchEnvironment

        let semaphore = DispatchSemaphore(value: 0)
        let callbackBox = LaunchCallbackBox()

        MainThreadSync.run {
            NSWorkspace.shared.openApplication(at: appURL, configuration: config) { app, error in
                MainThreadSync.run {
                    callbackBox.app = app
                    callbackBox.error = error
                    semaphore.signal()
                }
            }
        }

        if semaphore.wait(timeout: .now() + 8) == .timedOut {
            notes.append("Background launch timed out waiting for NSWorkspace callback.")
            return DynamicLaunchResult(
                launchMode: options.preferNonActivatingLaunch ? "background_non_activating" : "regular_launch",
                launchSucceeded: false,
                hideAttempted: false,
                hideSucceeded: nil,
                appLikelyActivatedForeground: nil,
                appLikelyDisplayedWindow: nil,
                interactionRequired: true,
                notes: notes,
                runningApplicationPID: nil
            )
        }

        if let launchError = callbackBox.error {
            notes.append("Launch failed: \(launchError.localizedDescription)")
        } else if let launchAppRef = callbackBox.app {
            launchSucceeded = true
            runningPID = Int(launchAppRef.processIdentifier)
        } else {
            notes.append("Launch callback returned neither app handle nor error.")
        }

        if launchSucceeded, let app = callbackBox.app, options.attemptHideAfterLaunch {
            hideAttempted = true
            MainThreadSync.sleep(seconds: 0.25)
            hideSucceeded = MainThreadSync.runWithReturn {
                app.hide()
            }

            if hideSucceeded == true {
                notes.append("hide() reported success.")
            } else {
                notes.append("hide() failed or app refused hiding.")
            }
        }

        if launchSucceeded {
            MainThreadSync.sleep(seconds: 0.35)
            let postFrontPID = MainThreadSync.frontmostPID()
            if let runningPID {
                if let postFrontPID {
                    likelyActivatedForeground = (postFrontPID == runningPID && postFrontPID != preFrontPID)
                } else {
                    likelyActivatedForeground = nil
                }

                if likelyActivatedForeground == true {
                    likelyDisplayedWindow = true
                    notes.append("App likely activated foreground by itself.")
                } else if hideAttempted, hideSucceeded == true {
                    likelyDisplayedWindow = false
                } else if hideAttempted, hideSucceeded == false {
                    likelyDisplayedWindow = true
                } else {
                    likelyDisplayedWindow = nil
                }
            }
        }

        let interactionRequired = (likelyActivatedForeground == true) || (likelyDisplayedWindow == true)
        if interactionRequired {
            notes.append("Interaction may be required; app could not be kept fully in background.")
        }

        return DynamicLaunchResult(
            launchMode: options.preferNonActivatingLaunch ? "background_non_activating" : "regular_launch",
            launchSucceeded: launchSucceeded,
            hideAttempted: hideAttempted,
            hideSucceeded: hideSucceeded,
            appLikelyActivatedForeground: likelyActivatedForeground,
            appLikelyDisplayedWindow: likelyDisplayedWindow,
            interactionRequired: interactionRequired,
            notes: notes,
            runningApplicationPID: runningPID
        )
    }
}

private enum MainThreadSync {
    private final class VoidClosureBox: @unchecked Sendable {
        private let closure: () -> Void
        init(_ closure: @escaping () -> Void) {
            self.closure = closure
        }
        func call() {
            closure()
        }
    }

    private final class ReturnClosureBox<T>: @unchecked Sendable {
        private let closure: () -> T
        init(_ closure: @escaping () -> T) {
            self.closure = closure
        }
        func call() -> T {
            closure()
        }
    }

    static func run(_ block: @escaping () -> Void) {
        if Thread.isMainThread {
            block()
            return
        }
        let box = VoidClosureBox(block)
        DispatchQueue.main.sync {
            box.call()
        }
    }

    static func runWithReturn<T>(_ block: @escaping () -> T) -> T {
        if Thread.isMainThread {
            return block()
        }
        let box = ReturnClosureBox(block)
        return DispatchQueue.main.sync {
            box.call()
        }
    }

    static func frontmostPID() -> Int? {
        runWithReturn {
            NSWorkspace.shared.frontmostApplication.map { Int($0.processIdentifier) }
        }
    }

    static func sleep(seconds: TimeInterval) {
        if seconds <= 0 { return }
        Thread.sleep(forTimeInterval: seconds)
    }
}
