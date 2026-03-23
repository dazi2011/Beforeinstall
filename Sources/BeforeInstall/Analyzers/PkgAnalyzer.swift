import Foundation

final class PkgAnalyzer: StaticAnalyzer {
    let analyzerName = "PkgAnalyzer"
    let supportedTypes: Set<SupportedFileType> = [.pkg]

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

        var pkgDetails = PkgDetails(
            packageIdentifiers: [],
            packageVersion: nil,
            installLocations: [],
            payloadFileSample: [],
            payloadFileCount: nil,
            scripts: [],
            modifiedLocations: []
        )

        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: fileURL.path, isDirectory: &isDirectory), isDirectory.boolValue {
            await analyzePkgFixtureDirectory(fileURL: fileURL, result: &result, pkgDetails: &pkgDetails)
            result.pkgDetails = pkgDetails
            return result
        }

        switch commandRunner.run(executable: "/usr/sbin/pkgutil", arguments: ["--check-signature", fileURL.path]) {
        case let .success(command):
            result.technicalDetails.append(TechnicalDetail(title: "pkg 签名检查", content: command.combinedOutput))
            result.signatureInfo = parseSignature(from: command)
            if !command.succeeded {
                result.warnings.append("pkgutil 签名检查命令执行失败：\(command.stderr)")
            }
        case let .failure(error):
            result.warnings.append("执行 pkgutil 失败：\(error.localizedDescription)")
        }

        let tempRoot = fileManager.temporaryDirectory.appendingPathComponent("BeforeInstall-Pkg-\(UUID().uuidString)", isDirectory: true)
        let expandedDirectory = tempRoot.appendingPathComponent("expanded", isDirectory: true)

        do {
            try fileManager.createDirectory(at: expandedDirectory, withIntermediateDirectories: true)
        } catch {
            result.warnings.append("创建临时目录失败：\(error.localizedDescription)")
            result.pkgDetails = pkgDetails
            return result
        }

        defer {
            try? fileManager.removeItem(at: tempRoot)
        }

        switch commandRunner.run(executable: "/usr/sbin/pkgutil", arguments: ["--expand", fileURL.path, expandedDirectory.path]) {
        case let .success(command):
            if !command.succeeded {
                result.warnings.append("安装包展开失败：\(command.stderr)")
            }
            result.technicalDetails.append(TechnicalDetail(title: "pkg 展开输出", content: command.combinedOutput))
        case let .failure(error):
            result.warnings.append("无法展开安装包：\(error.localizedDescription)")
            result.pkgDetails = pkgDetails
            return result
        }

        let packageInfoFiles = findFiles(
            under: expandedDirectory,
            where: { $0.lastPathComponent == "PackageInfo" },
            limit: 30
        )

        for packageInfoURL in packageInfoFiles {
            guard let text = try? String(contentsOf: packageInfoURL, encoding: .utf8) else {
                result.warnings.append("读取 PackageInfo 失败：\(packageInfoURL.path)")
                continue
            }
            let metadata = parsePackageInfo(text: text)
            if let identifier = metadata.identifier {
                pkgDetails.packageIdentifiers.append(identifier)
            }
            if let version = metadata.version, pkgDetails.packageVersion == nil {
                pkgDetails.packageVersion = version
            }
            if let location = metadata.installLocation {
                pkgDetails.installLocations.append(location)
            }
        }

        let scriptNames = ["preinstall", "postinstall", "preupgrade", "postupgrade"]
        let scriptFiles = findFiles(
            under: expandedDirectory,
            where: { scriptNames.contains($0.lastPathComponent.lowercased()) },
            limit: 100
        )

        pkgDetails.scripts = scriptFiles.map { scriptURL in
            InstallScriptInfo(
                scriptPath: scriptURL.path.replacingOccurrences(of: expandedDirectory.path, with: ""),
                scriptType: scriptURL.lastPathComponent.lowercased(),
                snippet: extractScriptSnippet(at: scriptURL)
            )
        }

        await appendScriptSignals(from: scriptFiles, baseRoot: expandedDirectory, result: &result)

        if !pkgDetails.scripts.isEmpty {
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "安装脚本线索",
                    content: pkgDetails.scripts.map { "\($0.scriptType): \($0.scriptPath)" }.joined(separator: "\n")
                )
            )
        }

        let bomFiles = findFiles(
            under: expandedDirectory,
            where: { $0.lastPathComponent.lowercased() == "bom" || $0.pathExtension.lowercased() == "bom" },
            limit: 20
        )

        var allPayloadCount = 0
        var payloadSample: [String] = []

        for bomURL in bomFiles {
            let escapedPath = shellEscape(bomURL.path)
            // 只读取前 N 行作为概览，避免一次性拉取超大 payload 列表。
            switch commandRunner.runShell("/usr/bin/lsbom \(escapedPath) | /usr/bin/head -n 120") {
            case let .success(command):
                let lines = command.stdout
                    .split(whereSeparator: \ .isNewline)
                    .map(String.init)
                    .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }

                if payloadSample.count < 80 {
                    payloadSample.append(contentsOf: lines.prefix(max(0, 80 - payloadSample.count)))
                }
            case let .failure(error):
                result.warnings.append("读取 BOM 失败：\(error.localizedDescription)")
            }

            switch commandRunner.runShell("/usr/bin/lsbom \(escapedPath) | /usr/bin/wc -l") {
            case let .success(countCommand):
                let countText = countCommand.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
                if let count = Int(countText) {
                    allPayloadCount += count
                }
            case let .failure(error):
                result.warnings.append("统计 BOM 文件数失败：\(error.localizedDescription)")
            }
        }

        pkgDetails.payloadFileCount = allPayloadCount == 0 ? nil : allPayloadCount
        pkgDetails.payloadFileSample = payloadSample

        var modifiedLocations = Set(pkgDetails.installLocations)
        for item in payloadSample {
            if let location = normalizeTopLevelLocation(fromPayloadPath: item) {
                modifiedLocations.insert(location)
            }
        }

        pkgDetails.modifiedLocations = Array(modifiedLocations).sorted()
        pkgDetails.packageIdentifiers = pkgDetails.packageIdentifiers.uniquePreservingOrder()
        pkgDetails.installLocations = pkgDetails.installLocations.uniquePreservingOrder()

        if !payloadSample.isEmpty {
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "Payload 文件概览（采样）",
                    content: payloadSample.prefix(80).joined(separator: "\n")
                )
            )
        }

        result.pkgDetails = pkgDetails

        if !pkgDetails.scripts.isEmpty {
            result.sensitiveCapabilities.append("安装包包含 pre/post install 脚本")
        }

        if !pkgDetails.modifiedLocations.isEmpty {
            result.sensitiveCapabilities.append("安装后可能修改路径：\(pkgDetails.modifiedLocations.joined(separator: ", "))")
        }

        return result
    }

    func analyzeLightweight(fileURL: URL, basicInfo: FileBasicInfo) async -> AnalysisResult {
        var result = AnalysisResult.placeholder(for: basicInfo)

        var pkgDetails = PkgDetails(
            packageIdentifiers: [],
            packageVersion: nil,
            installLocations: [],
            payloadFileSample: [],
            payloadFileCount: nil,
            scripts: [],
            modifiedLocations: []
        )

        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: fileURL.path, isDirectory: &isDirectory), isDirectory.boolValue {
            await analyzePkgFixtureDirectoryLightweight(fileURL: fileURL, result: &result, pkgDetails: &pkgDetails)
            result.pkgDetails = pkgDetails
            result.warnings.append("Quick probe skipped full payload traversal for pkg-like directory.")
            return result
        }

        switch commandRunner.run(executable: "/usr/sbin/pkgutil", arguments: ["--check-signature", fileURL.path]) {
        case let .success(command):
            result.signatureInfo = parseSignature(from: command)
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "Quick pkg signature check",
                    content: command.combinedOutput
                )
            )
        case let .failure(error):
            result.warnings.append("Quick pkg signature check failed: \(error.localizedDescription)")
        }

        result.pkgDetails = pkgDetails
        result.warnings.append("Quick probe skipped pkg payload expansion and deep script extraction.")
        return result
    }

    private func parseSignature(from command: CommandResult) -> SignatureInfo {
        let output = command.combinedOutput
        let normalized = output.lowercased()

        let isSigned = normalized.contains("status: signed") || normalized.contains("signed by")
        let signerLine = output
            .split(whereSeparator: \ .isNewline)
            .map(String.init)
            .first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("1.") })
        let signer = signerLine?
            .replacingOccurrences(of: "1.", with: "")
            .trimmingCharacters(in: .whitespaces)

        let authorities = output
            .split(whereSeparator: \ .isNewline)
            .map(String.init)
            .filter { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                return trimmed.hasPrefix("1.") || trimmed.hasPrefix("2.") || trimmed.hasPrefix("3.")
            }
            .map { $0.trimmingCharacters(in: .whitespaces) }

        return SignatureInfo(
            isSigned: isSigned,
            signerName: signer,
            authorities: authorities,
            teamIdentifier: nil,
            signingIdentifier: nil,
            notarizationStatus: nil,
            isLikelyNotarized: nil
        )
    }

    private func findFiles(under root: URL, where predicate: (URL) -> Bool, limit: Int) -> [URL] {
        guard let enumerator = fileManager.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey],
            options: [.skipsHiddenFiles],
            errorHandler: nil
        ) else {
            return []
        }

        var results: [URL] = []

        for case let url as URL in enumerator {
            if predicate(url) {
                results.append(url)
                if results.count >= limit {
                    break
                }
            }
        }

        return results
    }

    private func parsePackageInfo(text: String) -> (identifier: String?, version: String?, installLocation: String?) {
        guard let line = text
            .split(whereSeparator: \ .isNewline)
            .map(String.init)
            .first(where: { $0.contains("<pkg-info") })
        else {
            return (nil, nil, nil)
        }

        return (
            extractAttribute("identifier", from: line),
            extractAttribute("version", from: line),
            extractAttribute("install-location", from: line)
        )
    }

    private func extractAttribute(_ name: String, from line: String) -> String? {
        let pattern = "\(name)=\"([^\"]+)\""
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)),
              let range = Range(match.range(at: 1), in: line)
        else {
            return nil
        }

        return String(line[range])
    }

    private func extractScriptSnippet(at scriptURL: URL) -> String? {
        guard let raw = try? String(contentsOf: scriptURL, encoding: .utf8) else {
            return nil
        }
        let lines = raw
            .split(whereSeparator: \ .isNewline)
            .map(String.init)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        guard !lines.isEmpty else { return nil }
        return lines.prefix(3).joined(separator: "\n")
    }

    private func normalizeTopLevelLocation(fromPayloadPath rawPath: String) -> String? {
        let trimmed = rawPath
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "./", with: "")

        let components = trimmed.split(separator: "/").map(String.init)
        guard let first = components.first, !first.isEmpty else {
            return nil
        }

        return "/\(first)"
    }

    private func shellEscape(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "'", with: "'\\''")
        return "'\(escaped)'"
    }

    private func analyzePkgFixtureDirectory(fileURL: URL, result: inout AnalysisResult, pkgDetails: inout PkgDetails) async {
        let packageInfoURL = fileURL.appendingPathComponent("PackageInfo.json")
        if let data = try? Data(contentsOf: packageInfoURL),
           let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if let identifier = object["identifier"] as? String {
                pkgDetails.packageIdentifiers.append(identifier)
            }
            if let version = object["version"] as? String {
                pkgDetails.packageVersion = version
            }
            if let installLocation = object["install_location"] as? String {
                pkgDetails.installLocations.append(installLocation)
            }
        }

        let scriptsRoot = fileURL.appendingPathComponent("scripts")
        let scriptFiles = findFiles(
            under: scriptsRoot,
            where: { _ in true },
            limit: 80
        ).filter { url in
            let ext = url.pathExtension.lowercased()
            return ["sh", "command", "py", "js", "mjs", "cjs", "applescript", "scpt"].contains(ext)
                || ["preinstall", "postinstall", "preupgrade", "postupgrade"].contains(url.lastPathComponent.lowercased())
        }

        pkgDetails.scripts = scriptFiles.map { scriptURL in
            InstallScriptInfo(
                scriptPath: scriptURL.path.replacingOccurrences(of: fileURL.path, with: ""),
                scriptType: scriptURL.lastPathComponent.lowercased(),
                snippet: extractScriptSnippet(at: scriptURL)
            )
        }
        await appendScriptSignals(from: scriptFiles, baseRoot: fileURL, result: &result)

        let payloadRoot = fileURL.appendingPathComponent("payload")
        let payloadFiles = findFiles(under: payloadRoot, where: { _ in true }, limit: 120)
        pkgDetails.payloadFileSample = payloadFiles.map { $0.path.replacingOccurrences(of: fileURL.path + "/", with: "") }
        pkgDetails.payloadFileCount = payloadFiles.count

        var modifiedLocations = Set<String>(pkgDetails.installLocations)
        for item in pkgDetails.payloadFileSample {
            if let location = normalizeTopLevelLocation(fromPayloadPath: item) {
                modifiedLocations.insert(location)
            }
        }
        pkgDetails.modifiedLocations = Array(modifiedLocations).sorted()

        result.technicalDetails.append(
            TechnicalDetail(
                title: "pkg fixture directory",
                content: [
                    "root=\(fileURL.path)",
                    "scripts=\(pkgDetails.scripts.count)",
                    "payload_sample=\(pkgDetails.payloadFileSample.count)"
                ].joined(separator: "\n")
            )
        )

        if !pkgDetails.scripts.isEmpty {
            result.sensitiveCapabilities.append("安装包包含 pre/post install 脚本")
        }
        if !pkgDetails.modifiedLocations.isEmpty {
            result.sensitiveCapabilities.append("安装后可能修改路径：\(pkgDetails.modifiedLocations.joined(separator: ", "))")
        }
        if pkgDetails.packageIdentifiers.isEmpty {
            result.warnings.append("pkg fixture directory missing package identifier metadata.")
        }
    }

    private func analyzePkgFixtureDirectoryLightweight(fileURL: URL, result: inout AnalysisResult, pkgDetails: inout PkgDetails) async {
        let scriptNames = ["preinstall", "postinstall", "preupgrade", "postupgrade"]
        let scriptFiles = findFiles(
            under: fileURL,
            where: { url in
                let ext = url.pathExtension.lowercased()
                return scriptNames.contains(url.lastPathComponent.lowercased())
                    || ["sh", "command", "py", "js", "mjs", "cjs", "applescript", "scpt"].contains(ext)
            },
            limit: 24
        )

        pkgDetails.scripts = scriptFiles.map { scriptURL in
            InstallScriptInfo(
                scriptPath: scriptURL.path.replacingOccurrences(of: fileURL.path + "/", with: ""),
                scriptType: scriptURL.lastPathComponent.lowercased(),
                snippet: extractScriptSnippet(at: scriptURL)
            )
        }

        if !pkgDetails.scripts.isEmpty {
            result.sensitiveCapabilities.append("pkg fixture contains install script entries")
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "Quick pkg script probe",
                    content: pkgDetails.scripts.map { "\($0.scriptType): \($0.scriptPath)" }.joined(separator: "\n")
                )
            )
        }
    }

    private func appendScriptSignals(from scripts: [URL], baseRoot: URL, result: inout AnalysisResult) async {
        guard let scriptAnalyzer, let metadataService, !scripts.isEmpty else { return }

        var hits: [ScriptRuleHit] = []
        var summaries: [String] = []

        for scriptURL in scripts.prefix(30) {
            let detectedType = SupportedFileType.detect(from: scriptURL)
            let info: FileBasicInfo
            switch metadataService.basicInfo(for: scriptURL, detectedType: detectedType) {
            case let .success(value):
                info = value
            case .failure:
                info = metadataService.makeFallbackInfo(for: scriptURL, detectedType: detectedType)
            }

            let analyzed = await scriptAnalyzer.analyze(fileURL: scriptURL, basicInfo: info)
            if let scriptDetails = analyzed.scriptDetails {
                hits.append(contentsOf: scriptDetails.ruleHits)
                summaries.append(contentsOf: scriptDetails.summary)
            }
        }

        guard !hits.isEmpty else { return }

        result.scriptDetails = ScriptAnalysisDetails(
            scriptType: .shellScript,
            shebang: nil,
            lineCount: 0,
            tokenCount: 0,
            commandSample: scripts.prefix(10).map { $0.path.replacingOccurrences(of: baseRoot.path + "/", with: "") },
            summary: summaries.uniquePreservingOrder(),
            ruleHits: hits.unique(by: { "\($0.ruleID)|\($0.lineStart)|\($0.lineEnd)|\($0.matchedContent)" })
        )
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
