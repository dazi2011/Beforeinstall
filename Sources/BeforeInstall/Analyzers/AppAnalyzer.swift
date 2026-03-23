import Foundation

final class AppAnalyzer: StaticAnalyzer {
    let analyzerName = "AppAnalyzer"
    let supportedTypes: Set<SupportedFileType> = [.appBundle]

    private let commandRunner: CommandRunning
    private let scriptAnalyzer: ScriptAnalyzer?
    private let metadataService: FileMetadataService?
    private let fileManager = FileManager.default

    init(
        commandRunner: CommandRunning,
        scriptAnalyzer: ScriptAnalyzer? = nil,
        metadataService: FileMetadataService? = nil
    ) {
        self.commandRunner = commandRunner
        self.scriptAnalyzer = scriptAnalyzer
        self.metadataService = metadataService
    }

    func analyze(fileURL: URL, basicInfo: FileBasicInfo) async -> AnalysisResult {
        var result = AnalysisResult.placeholder(for: basicInfo)

        var appDetails = AppDetails(
            appName: nil,
            bundleIdentifier: nil,
            shortVersion: nil,
            buildVersion: nil,
            helperItems: [],
            loginItems: [],
            embeddedFrameworks: [],
            launchItems: []
        )

        if let infoDict = loadInfoPlist(from: fileURL) {
            appDetails.appName = (infoDict["CFBundleDisplayName"] as? String)
                ?? (infoDict["CFBundleName"] as? String)
                ?? fileURL.deletingPathExtension().lastPathComponent
            appDetails.bundleIdentifier = infoDict["CFBundleIdentifier"] as? String
            appDetails.shortVersion = infoDict["CFBundleShortVersionString"] as? String
            appDetails.buildVersion = infoDict["CFBundleVersion"] as? String
        } else {
            result.warnings.append("读取 Info.plist 失败，部分基础信息无法获取")
        }

        let appSignals = collectAppStructureSignals(appURL: fileURL)
        appDetails.helperItems = appSignals.helpers
        appDetails.loginItems = appSignals.loginItems
        appDetails.embeddedFrameworks = appSignals.frameworks
        appDetails.launchItems = appSignals.launchItems
        result.appDetails = appDetails

        result.persistenceIndicators.append(contentsOf: persistenceDescriptions(from: appSignals))

        switch commandRunner.run(executable: "/usr/bin/codesign", arguments: ["-dv", "--verbose=4", fileURL.path]) {
        case let .success(command):
            result.technicalDetails.append(TechnicalDetail(title: "codesign 详情", content: command.combinedOutput))
            result.signatureInfo = parseSignature(from: command)
            if !command.succeeded {
                result.warnings.append("无法完整读取签名信息：\(command.stderr)")
            }
        case let .failure(error):
            result.signatureInfo = SignatureInfo(
                isSigned: false,
                signerName: nil,
                authorities: [],
                teamIdentifier: nil,
                signingIdentifier: nil,
                notarizationStatus: nil,
                isLikelyNotarized: nil
            )
            result.warnings.append(error.localizedDescription)
        }

        switch commandRunner.run(executable: "/usr/sbin/spctl", arguments: ["-a", "-vv", fileURL.path]) {
        case let .success(command):
            if let signature = result.signatureInfo {
                result.signatureInfo = updateNotarization(signatureInfo: signature, with: command.combinedOutput)
            }
            result.technicalDetails.append(TechnicalDetail(title: "spctl 验证", content: command.combinedOutput))
            // 某些机器上 Gatekeeper 策略会导致非零退出码，不应让整体分析失败。
            if !command.succeeded {
                result.warnings.append("Gatekeeper 校验失败或受系统策略限制：\(command.stderr)")
            }
        case let .failure(error):
            result.warnings.append("执行 spctl 失败：\(error.localizedDescription)")
        }

        switch commandRunner.run(executable: "/usr/bin/codesign", arguments: ["-d", "--entitlements", ":-", fileURL.path]) {
        case let .success(command):
            let sourceText = command.combinedOutput
            if let xml = extractPlistXML(from: sourceText),
               let entitlement = parseEntitlements(xml: xml)
            {
                result.entitlementInfo = entitlement
                result.technicalDetails.append(TechnicalDetail(title: "Entitlements", content: xml))
            } else {
                result.warnings.append("未提取到 Entitlements（可能该应用未声明或无法读取）")
            }
        case let .failure(error):
            result.warnings.append("执行 entitlements 提取失败：\(error.localizedDescription)")
        }

        result.sensitiveCapabilities = detectSensitiveCapabilities(result: result)

        if let scriptAnalyzer, let metadataService {
            let embeddedScripts = collectEmbeddedScriptURLs(appURL: fileURL)
            if !embeddedScripts.isEmpty {
                var aggregatedHits: [ScriptRuleHit] = []
                var scriptSummary: [String] = []

                for scriptURL in embeddedScripts.prefix(20) {
                    let scriptType = SupportedFileType.detect(from: scriptURL)
                    let scriptInfo: FileBasicInfo
                    switch metadataService.basicInfo(for: scriptURL, detectedType: scriptType) {
                    case let .success(info):
                        scriptInfo = info
                    case .failure:
                        scriptInfo = metadataService.makeFallbackInfo(for: scriptURL, detectedType: scriptType)
                    }

                    let scriptResult = await scriptAnalyzer.analyze(fileURL: scriptURL, basicInfo: scriptInfo)
                    if let details = scriptResult.scriptDetails {
                        aggregatedHits.append(contentsOf: details.ruleHits)
                        scriptSummary.append(contentsOf: details.summary)
                    }
                }

                if !aggregatedHits.isEmpty {
                    result.scriptDetails = ScriptAnalysisDetails(
                        scriptType: .shellScript,
                        shebang: nil,
                        lineCount: 0,
                        tokenCount: 0,
                        commandSample: embeddedScripts.prefix(8).map { $0.path.replacingOccurrences(of: fileURL.path + "/", with: "") },
                        summary: scriptSummary.uniquePreservingOrder(),
                        ruleHits: aggregatedHits.unique(by: { "\($0.ruleID)|\($0.lineStart)|\($0.lineEnd)|\($0.matchedContent)" })
                    )
                    result.technicalDetails.append(
                        TechnicalDetail(
                            title: "Embedded Script Signals",
                            content: embeddedScripts.prefix(20).map { $0.path.replacingOccurrences(of: fileURL.path + "/", with: "") }.joined(separator: "\n")
                        )
                    )
                }
            }
        }

        let sipSignals = detectSIPBypassSignals(in: fileURL)
        if !sipSignals.isEmpty {
            result.sensitiveCapabilities.append(contentsOf: sipSignals.map { "SIP signal: \($0)" })
            result.persistenceIndicators.append("Potential SIP bypass related clues found in app bundle content")
            result.warnings.append("High-priority warning: possible SIP bypass related artifacts detected.")
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "SIP bypass keyword scan",
                    content: sipSignals.joined(separator: "\n")
                )
            )
        }

        result.sensitiveCapabilities = result.sensitiveCapabilities.uniquePreservingOrder()
        result.persistenceIndicators = result.persistenceIndicators.uniquePreservingOrder()

        return result
    }

    func analyzeLightweight(fileURL: URL, basicInfo: FileBasicInfo) async -> AnalysisResult {
        var result = AnalysisResult.placeholder(for: basicInfo)

        var appDetails = AppDetails(
            appName: nil,
            bundleIdentifier: nil,
            shortVersion: nil,
            buildVersion: nil,
            helperItems: [],
            loginItems: [],
            embeddedFrameworks: [],
            launchItems: []
        )

        if let infoDict = loadInfoPlist(from: fileURL) {
            appDetails.appName = (infoDict["CFBundleDisplayName"] as? String)
                ?? (infoDict["CFBundleName"] as? String)
                ?? fileURL.deletingPathExtension().lastPathComponent
            appDetails.bundleIdentifier = infoDict["CFBundleIdentifier"] as? String
            appDetails.shortVersion = infoDict["CFBundleShortVersionString"] as? String
            appDetails.buildVersion = infoDict["CFBundleVersion"] as? String
        } else {
            result.warnings.append("Quick probe: Info.plist unavailable.")
        }

        let appSignals = collectAppStructureSignals(appURL: fileURL)
        appDetails.helperItems = appSignals.helpers
        appDetails.loginItems = appSignals.loginItems
        appDetails.embeddedFrameworks = appSignals.frameworks.prefix(6).map { $0 }
        appDetails.launchItems = appSignals.launchItems
        result.appDetails = appDetails
        result.persistenceIndicators.append(contentsOf: persistenceDescriptions(from: appSignals))

        if let executableURL = mainExecutableURL(appURL: fileURL) {
            let executableExists = fileManager.fileExists(atPath: executableURL.path)
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "Quick App Probe",
                    content: [
                        "Main executable: \(executableURL.path)",
                        "Executable exists: \(executableExists)",
                        "Readable: \(fileManager.isReadableFile(atPath: executableURL.path))"
                    ].joined(separator: "\n")
                )
            )
        } else {
            result.warnings.append("Quick probe: main executable path not resolved.")
        }

        // Quick mode intentionally avoids full bundle recursive traversal and heavy signature/entitlements extraction.
        result.warnings.append("Quick probe skipped deep bundle expansion, full codesign/spctl checks, and exhaustive embedded script recursion.")
        result.sensitiveCapabilities = detectSensitiveCapabilities(result: result).uniquePreservingOrder()
        result.persistenceIndicators = result.persistenceIndicators.uniquePreservingOrder()
        return result
    }

    private func loadInfoPlist(from appURL: URL) -> [String: Any]? {
        let plistURL = appURL.appendingPathComponent("Contents/Info.plist")

        guard let data = try? Data(contentsOf: plistURL) else {
            return nil
        }

        guard let rawObject = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let plist = rawObject as? [String: Any]
        else {
            return nil
        }

        return plist
    }

    private func mainExecutableURL(appURL: URL) -> URL? {
        guard let info = loadInfoPlist(from: appURL),
              let executable = info["CFBundleExecutable"] as? String,
              !executable.isEmpty
        else {
            return nil
        }
        let url = appURL.appendingPathComponent("Contents/MacOS/\(executable)")
        return fileManager.fileExists(atPath: url.path) ? url : nil
    }

    private func parseSignature(from command: CommandResult) -> SignatureInfo {
        let output = command.combinedOutput
        let keyValues = parseKeyValueLines(output)

        let authorities = output
            .split(whereSeparator: \ .isNewline)
            .map(String.init)
            .compactMap { line -> String? in
                guard let range = line.range(of: "Authority=") else { return nil }
                return String(line[range.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
            }

        return SignatureInfo(
            isSigned: command.succeeded,
            signerName: authorities.first,
            authorities: authorities,
            teamIdentifier: keyValues["TeamIdentifier"],
            signingIdentifier: keyValues["Identifier"],
            notarizationStatus: nil,
            isLikelyNotarized: nil
        )
    }

    private func updateNotarization(signatureInfo: SignatureInfo, with spctlOutput: String) -> SignatureInfo {
        var updated = signatureInfo

        let lines = spctlOutput.split(whereSeparator: \ .isNewline).map(String.init)
        if let sourceLine = lines.first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("source=") }) {
            updated.notarizationStatus = sourceLine.replacingOccurrences(of: "source=", with: "")
        }

        updated.isLikelyNotarized = spctlOutput.localizedCaseInsensitiveContains("notarized")
        if updated.signerName == nil,
           let originLine = lines.first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("origin=") })
        {
            updated.signerName = originLine.replacingOccurrences(of: "origin=", with: "")
        }

        return updated
    }

    private func parseEntitlements(xml: String) -> EntitlementInfo? {
        guard let data = xml.data(using: .utf8),
              let rawObject = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = rawObject as? [String: Any]
        else {
            return nil
        }

        let entries = dict
            .mapValues { flattenPlistValue($0) }
            .sorted(by: { $0.key < $1.key })

        let hasSandbox = (dict["com.apple.security.app-sandbox"] as? Bool) ?? false

        return EntitlementInfo(hasSandbox: hasSandbox, entries: Dictionary(uniqueKeysWithValues: entries), rawXML: xml)
    }

    private func collectAppStructureSignals(appURL: URL) -> (helpers: [String], loginItems: [String], frameworks: [String], launchItems: [String]) {
        let contentsURL = appURL.appendingPathComponent("Contents")

        let frameworks = listFiles(in: contentsURL.appendingPathComponent("Frameworks"),
                                   allowedExtensions: ["framework"]) // 仅作为结构线索

        let loginItems = listFiles(in: contentsURL.appendingPathComponent("Library/LoginItems"),
                                   allowedExtensions: ["app"])

        let helperCandidates = [
            contentsURL.appendingPathComponent("Library/LaunchServices"),
            contentsURL.appendingPathComponent("Library/Helpers"),
            contentsURL.appendingPathComponent("XPCServices")
        ]

        let helpers = helperCandidates.flatMap {
            listFiles(in: $0, allowedExtensions: ["app", "xpc", ""]) // helper 可能没有扩展名
        }

        let launchCandidates = [
            contentsURL.appendingPathComponent("Library/LaunchAgents"),
            contentsURL.appendingPathComponent("Library/LaunchDaemons")
        ]

        let launchItems = launchCandidates.flatMap {
            listFiles(in: $0, allowedExtensions: ["plist"])
        }

        return (
            helpers: helpers.uniquePreservingOrder(),
            loginItems: loginItems.uniquePreservingOrder(),
            frameworks: frameworks.uniquePreservingOrder(),
            launchItems: launchItems.uniquePreservingOrder()
        )
    }

    private func collectEmbeddedScriptURLs(appURL: URL) -> [URL] {
        let roots = [
            appURL.appendingPathComponent("Contents/Resources"),
            appURL.appendingPathComponent("Contents/MacOS")
        ]

        let allowed = Set(["sh", "command", "py", "js", "mjs", "cjs", "applescript", "scpt"])
        var scripts: [URL] = []

        for root in roots where fileManager.fileExists(atPath: root.path) {
            guard let enumerator = fileManager.enumerator(
                at: root,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles],
                errorHandler: nil
            ) else {
                continue
            }

            let baseDepth = root.pathComponents.count
            for case let item as URL in enumerator {
                let depth = item.pathComponents.count - baseDepth
                if depth > 4 {
                    enumerator.skipDescendants()
                    continue
                }

                var isDir: ObjCBool = false
                if fileManager.fileExists(atPath: item.path, isDirectory: &isDir), isDir.boolValue {
                    continue
                }

                if allowed.contains(item.pathExtension.lowercased()) {
                    scripts.append(item)
                }
            }
        }

        return scripts.sorted { $0.path < $1.path }.uniquePreservingOrder()
    }

    private func listFiles(in directory: URL, allowedExtensions: [String]) -> [String] {
        guard fileManager.fileExists(atPath: directory.path),
              let items = try? fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles])
        else {
            return []
        }

        return items.compactMap { item in
            let ext = item.pathExtension.lowercased()
            if allowedExtensions.contains(ext) {
                return item.lastPathComponent
            }
            if allowedExtensions.contains(""), ext.isEmpty {
                return item.lastPathComponent
            }
            return nil
        }
    }

    private func persistenceDescriptions(from signals: (helpers: [String], loginItems: [String], frameworks: [String], launchItems: [String])) -> [String] {
        var descriptions: [String] = []

        if !signals.helpers.isEmpty {
            descriptions.append("包含 helper / XPC 组件（不一定常驻）")
        }
        if !signals.loginItems.isEmpty {
            descriptions.append("包含 Login Item，可能随登录自动运行")
        }
        if !signals.launchItems.isEmpty {
            descriptions.append("包含 LaunchAgent/LaunchDaemon 线索")
        }

        return descriptions.uniquePreservingOrder()
    }

    private func detectSensitiveCapabilities(result: AnalysisResult) -> [String] {
        var capabilities: [String] = []

        if let entitlementInfo = result.entitlementInfo {
            let keys = entitlementInfo.entries.keys

            if keys.contains(where: { $0.hasPrefix("com.apple.security.files") }) {
                capabilities.append("请求文件系统相关权限")
            }

            if keys.contains("com.apple.security.network.client") || keys.contains("com.apple.security.network.server") {
                capabilities.append("请求网络通信能力")
            }

            if keys.contains("com.apple.security.automation.apple-events") {
                capabilities.append("可通过 Apple Events 控制其他应用")
            }

            if keys.contains(where: { $0.hasPrefix("com.apple.security.personal-information") }) {
                capabilities.append("请求个人信息数据访问能力")
            }

            if !entitlementInfo.hasSandbox {
                capabilities.append("未声明 App Sandbox")
            }
        } else {
            capabilities.append("未获取到 Entitlements，权限边界不可完全判断")
        }

        if !(result.appDetails?.loginItems.isEmpty ?? true) || !(result.appDetails?.helperItems.isEmpty ?? true) {
            capabilities.append("存在常驻组件线索（helper/login item）")
        }

        if !(result.appDetails?.embeddedFrameworks.isEmpty ?? true) {
            capabilities.append("包含嵌入式框架组件")
        }

        return capabilities.uniquePreservingOrder()
    }

    private func detectSIPBypassSignals(in appURL: URL) -> [String] {
        let scanTargets = [
            appURL.appendingPathComponent("Contents/MacOS").path,
            appURL.appendingPathComponent("Contents/Resources").path,
            appURL.appendingPathComponent("Contents/Library").path
        ]

        let keywords = [
            "csrutil disable",
            "authenticated-root disable",
            "amfi_get_out_of_my_way",
            "nvram boot-args",
            "mount -uw /",
            "system integrity protection",
            "launchdaemon"
        ]

        var hits: [String] = []
        for target in scanTargets {
            guard fileManager.fileExists(atPath: target) else { continue }
            let listCommand = "/usr/bin/find \(shellEscape(target)) -type f 2>/dev/null | /usr/bin/head -n 30"
            guard case let .success(filesResult) = commandRunner.runShell(listCommand) else { continue }
            let files = filesResult.stdout.split(whereSeparator: \.isNewline).map(String.init)
            for file in files {
                if let attrs = try? fileManager.attributesOfItem(atPath: file),
                   let size = attrs[.size] as? NSNumber,
                   size.int64Value > 20 * 1024 * 1024
                {
                    continue
                }

                let command = "/usr/bin/strings -n 6 \(shellEscape(file)) 2>/dev/null | /usr/bin/head -n 300"
                guard case let .success(output) = commandRunner.runShell(command) else { continue }
                let text = output.stdout.lowercased()
                for keyword in keywords where text.contains(keyword) {
                    hits.append("\(keyword) @ \(file)")
                }
            }
        }

        return hits.uniquePreservingOrder()
    }

    private func shellEscape(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "'", with: "'\\''")
        return "'\(escaped)'"
    }
}

private extension Array {
    func unique<T: Hashable>(by keyPath: (Element) -> T) -> [Element] {
        var seen = Set<T>()
        return filter { element in
            let key = keyPath(element)
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }
}
