import Foundation
import AppKit
import ApplicationServices

enum PermissionHealthStatus: String, Sendable {
    case granted
    case notGranted
    case unknown
}

enum PermissionAction: Sendable {
    case accessibility
    case fullDisk
    case automation
}

struct PermissionHealthItem: Identifiable, Sendable {
    var id: String
    var title: String
    var impact: String
    var status: PermissionHealthStatus
    var action: PermissionAction
}

@MainActor
enum PermissionGuidanceService {
    private static var automationCachedStatus: PermissionHealthStatus = .unknown

    static func isAccessibilityTrusted() -> Bool {
        let key = "AXTrustedCheckOptionPrompt" as CFString
        let options = [key: false] as CFDictionary
        return AXIsProcessTrustedWithOptions(options) || AXIsProcessTrusted()
    }

    static func requestAccessibilityPrompt() -> Bool {
        let key = "AXTrustedCheckOptionPrompt" as CFString
        let options = [key: true] as CFDictionary
        return AXIsProcessTrustedWithOptions(options)
    }

    static func openFullDiskAccess() {
        openPrivacyPane(anchor: "Privacy_AllFiles")
    }

    static func openAccessibility() {
        openPrivacyPane(anchor: "Privacy_Accessibility")
    }

    static func openAutomation() {
        openPrivacyPane(anchor: "Privacy_Automation")
    }

    static func performAction(_ action: PermissionAction) {
        switch action {
        case .accessibility:
            _ = requestAccessibilityPrompt()
            openAccessibility()
        case .fullDisk:
            openFullDiskAccess()
        case .automation:
            _ = requestAutomationPrompt()
            openAutomation()
        }
    }

    static func permissionHealthItems(
        language: AppLanguage,
        includeAccessibility: Bool = false,
        includeAutomation: Bool = false
    ) -> [PermissionHealthItem] {
        let fullDiskStatus = fullDiskAccessHeuristicStatus()
        var items: [PermissionHealthItem] = []

        if includeAccessibility {
            items.append(
                PermissionHealthItem(
                    id: "accessibility",
                    title: Localizer.text("welcome.permissionAccessibilityTitle", language: language),
                    impact: Localizer.text("welcome.permissionAccessibilityImpact", language: language),
                    status: isAccessibilityTrusted() ? .granted : .notGranted,
                    action: .accessibility
                )
            )
        }

        items.append(
            PermissionHealthItem(
                id: "full_disk",
                title: Localizer.text("welcome.permissionFullDiskTitle", language: language),
                impact: Localizer.text("welcome.permissionFullDiskImpact", language: language),
                status: fullDiskStatus,
                action: .fullDisk
            )
        )

        if includeAutomation {
            items.append(PermissionHealthItem(
                id: "automation",
                title: Localizer.text("welcome.permissionAutomationTitle", language: language),
                impact: Localizer.text("welcome.permissionAutomationImpact", language: language),
                status: automationCachedStatus,
                action: .automation
            ))
        }

        return items
    }

    static func fullDiskAccessStatus() -> PermissionHealthStatus {
        fullDiskAccessHeuristicStatus()
    }

    @discardableResult
    static func requestAutomationPrompt() -> PermissionHealthStatus {
        let status = evaluateAutomationPermission()
        automationCachedStatus = status
        return status
    }

    // macOS does not expose a direct public API for Full Disk Access query.
    // We use a conservative heuristic by probing a known TCC-protected database.
    private static func fullDiskAccessHeuristicStatus() -> PermissionHealthStatus {
        let fileManager = FileManager.default
        let protectedPath = (NSHomeDirectory() as NSString).appendingPathComponent("Library/Application Support/com.apple.TCC/TCC.db")
        guard fileManager.fileExists(atPath: protectedPath) else {
            return .unknown
        }

        if fileManager.isReadableFile(atPath: protectedPath) {
            return .granted
        }
        return .notGranted
    }

    private static func evaluateAutomationPermission() -> PermissionHealthStatus {
        let source = """
        tell application "System Events"
            count processes
        end tell
        """

        guard let script = NSAppleScript(source: source) else {
            return .unknown
        }

        var errorInfo: NSDictionary?
        _ = script.executeAndReturnError(&errorInfo)

        if errorInfo == nil {
            return .granted
        }

        let errorNumber = errorInfo?[NSAppleScript.errorNumber] as? Int ?? 0
        if errorNumber == -1743 || errorNumber == -10004 || errorNumber == -1719 {
            return .notGranted
        }
        return .unknown
    }

    private static func openPrivacyPane(anchor: String) {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?\(anchor)") else {
            return
        }
        NSWorkspace.shared.open(url)
    }
}
