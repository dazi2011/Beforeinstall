import Foundation

enum AppLaunchOption: String, CaseIterable, Codable, Identifiable, Sendable {
    case disableFileWrite
    case disableWindow
    case disableClipboard
    case disableNetwork
    case disableProcess
    case disableTerminal
    case disableAppleScript
    case disableAVCapture
    case disableKeychain
    case disableLaunchd
    case disableDefaults
    case disableScreenshot

    var id: String { rawValue }

    var dylibName: String {
        switch self {
        case .disableFileWrite:
            return BuiltInDylib.noFileWrite.rawValue
        case .disableWindow:
            return BuiltInDylib.noWindow.rawValue
        case .disableClipboard:
            return BuiltInDylib.noClipboard.rawValue
        case .disableNetwork:
            return BuiltInDylib.noNetwork.rawValue
        case .disableProcess:
            return BuiltInDylib.noProcess.rawValue
        case .disableTerminal:
            return BuiltInDylib.noTerminal.rawValue
        case .disableAppleScript:
            return BuiltInDylib.noAppleScript.rawValue
        case .disableAVCapture:
            return BuiltInDylib.noAVCapture.rawValue
        case .disableKeychain:
            return BuiltInDylib.noKeychain.rawValue
        case .disableLaunchd:
            return BuiltInDylib.noLaunchd.rawValue
        case .disableDefaults:
            return BuiltInDylib.noDefaults.rawValue
        case .disableScreenshot:
            return BuiltInDylib.noScreenshot.rawValue
        }
    }

    func title(language: AppLanguage) -> String {
        switch (self, language) {
        case (.disableFileWrite, .zhHans):
            return "禁用文件写入"
        case (.disableWindow, .zhHans):
            return "禁用窗口"
        case (.disableClipboard, .zhHans):
            return "禁用剪贴板"
        case (.disableNetwork, .zhHans):
            return "禁用网络"
        case (.disableProcess, .zhHans):
            return "禁用进程创建"
        case (.disableTerminal, .zhHans):
            return "禁用终端"
        case (.disableAppleScript, .zhHans):
            return "禁用 AppleScript"
        case (.disableAVCapture, .zhHans):
            return "禁用摄像头/麦克风捕获"
        case (.disableKeychain, .zhHans):
            return "禁用钥匙串"
        case (.disableLaunchd, .zhHans):
            return "禁用 Launchd"
        case (.disableDefaults, .zhHans):
            return "禁用 defaults 写入"
        case (.disableScreenshot, .zhHans):
            return "禁用截图"
        case (.disableFileWrite, .en):
            return "Disable File Writes"
        case (.disableWindow, .en):
            return "Disable Window"
        case (.disableClipboard, .en):
            return "Disable Clipboard"
        case (.disableNetwork, .en):
            return "Disable Network"
        case (.disableProcess, .en):
            return "Disable Process Spawn"
        case (.disableTerminal, .en):
            return "Disable Terminal"
        case (.disableAppleScript, .en):
            return "Disable AppleScript"
        case (.disableAVCapture, .en):
            return "Disable AV Capture"
        case (.disableKeychain, .en):
            return "Disable Keychain"
        case (.disableLaunchd, .en):
            return "Disable Launchd"
        case (.disableDefaults, .en):
            return "Disable defaults write"
        case (.disableScreenshot, .en):
            return "Disable Screenshot"
        }
    }
}

struct LaunchableAppInfo: Identifiable, Hashable, Sendable {
    var id: String { appPath }
    var appPath: String
    var displayName: String
    var bundleIdentifier: String
}

struct AppLaunchPreset: Codable, Identifiable, Sendable {
    var id: UUID
    var appPath: String
    var bundleIdentifier: String
    var useSafeMode: Bool
    var useSandboxExec: Bool
    var useCustomMode: Bool
    var selectedOptions: [AppLaunchOption]
    var customDylibPaths: [String]
    var updatedAt: Date

    static func `default`(for app: LaunchableAppInfo) -> AppLaunchPreset {
        AppLaunchPreset(
            id: UUID(),
            appPath: app.appPath,
            bundleIdentifier: app.bundleIdentifier,
            useSafeMode: false,
            useSandboxExec: false,
            useCustomMode: false,
            selectedOptions: [],
            customDylibPaths: [],
            updatedAt: Date()
        )
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case appPath
        case bundleIdentifier
        case useSafeMode
        case useSandboxExec
        case useCustomMode
        case selectedOptions
        case customDylibPaths
        case updatedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        appPath = try container.decode(String.self, forKey: .appPath)
        bundleIdentifier = try container.decode(String.self, forKey: .bundleIdentifier)
        useSafeMode = try container.decodeIfPresent(Bool.self, forKey: .useSafeMode) ?? false
        useSandboxExec = try container.decodeIfPresent(Bool.self, forKey: .useSandboxExec) ?? false
        useCustomMode = try container.decodeIfPresent(Bool.self, forKey: .useCustomMode) ?? false
        selectedOptions = try container.decodeIfPresent([AppLaunchOption].self, forKey: .selectedOptions) ?? []
        customDylibPaths = try container.decodeIfPresent([String].self, forKey: .customDylibPaths) ?? []
        updatedAt = try container.decodeIfPresent(Date.self, forKey: .updatedAt) ?? Date()
    }

    init(
        id: UUID,
        appPath: String,
        bundleIdentifier: String,
        useSafeMode: Bool,
        useSandboxExec: Bool,
        useCustomMode: Bool,
        selectedOptions: [AppLaunchOption],
        customDylibPaths: [String],
        updatedAt: Date
    ) {
        self.id = id
        self.appPath = appPath
        self.bundleIdentifier = bundleIdentifier
        self.useSafeMode = useSafeMode
        self.useSandboxExec = useSandboxExec
        self.useCustomMode = useCustomMode
        self.selectedOptions = selectedOptions
        self.customDylibPaths = customDylibPaths
        self.updatedAt = updatedAt
    }
}

enum ConfigRuleAction: String, Codable, CaseIterable, Sendable {
    case notice
    case ignore
}

enum ConfigRuleType: String, Codable, CaseIterable, Sendable {
    case rule = "RULE"
    case ruleFile = "RULE-FILE"
    case ruleHash = "RULE-HASH"
    case ruleURL = "RULE-URL"
    case ruleIP = "RULE-IP"
    case ruleRegexp = "RULE-REGEXP"
    case rulePathPrefix = "RULE-PATH-PREFIX"
    case app = "APP"
}

struct ConfigRule: Codable, Identifiable, Sendable {
    var id = UUID()
    var type: ConfigRuleType
    var value: String
    var action: ConfigRuleAction
    var lineNumber: Int
}

struct ParsedConfigProfile: Sendable {
    var globals: [String: String]
    var rules: [ConfigRule]
}

struct ConfigProfileSummary: Codable, Identifiable, Sendable {
    var id: String
    var name: String
    var filePath: String
    var updatedAt: Date
}
