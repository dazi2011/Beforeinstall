import Foundation

final class GenericAnalyzer: StaticAnalyzer {
    let analyzerName = "GenericAnalyzer"
    let supportedTypes: Set<SupportedFileType> = [.unknown]

    private let commandRunner: CommandRunning
    private let fileManager = FileManager.default

    init(commandRunner: CommandRunning) {
        self.commandRunner = commandRunner
    }

    func analyze(fileURL: URL, basicInfo: FileBasicInfo) async -> AnalysisResult {
        var result = AnalysisResult.placeholder(for: basicInfo, request: .default)

        let mimeOutput = commandRunner.run(executable: "/usr/bin/file", arguments: ["-b", "--mime", fileURL.path])
        let typeOutput = commandRunner.run(executable: "/usr/bin/file", arguments: ["-b", fileURL.path])

        let mimeText = (try? mimeOutput.get().stdout) ?? ""
        let typeText = (try? typeOutput.get().stdout) ?? ""

        if !mimeText.isEmpty {
            result.technicalDetails.append(TechnicalDetail(title: "file --mime", content: mimeText))
        }
        if !typeText.isEmpty {
            result.technicalDetails.append(TechnicalDetail(title: "file type", content: typeText))
        }

        var hashValue: String?
        if case let .success(hashCommand) = commandRunner.run(executable: "/usr/bin/shasum", arguments: ["-a", "256", fileURL.path]) {
            hashValue = hashCommand.stdout.split(separator: " ").first.map(String.init)
            result.technicalDetails.append(TechnicalDetail(title: "SHA256", content: hashCommand.stdout))
        }

        if case let .success(xattrCommand) = commandRunner.run(executable: "/usr/bin/xattr", arguments: ["-l", fileURL.path]),
           !xattrCommand.stdout.isEmpty
        {
            result.technicalDetails.append(TechnicalDetail(title: "Extended Attributes", content: xattrCommand.stdout))
        }

        let isExecutable = fileManager.isExecutableFile(atPath: fileURL.path)
        let isLikelyScript = isTextScript(fileURL: fileURL)

        var snippet: String?
        var keywordHits: [String] = []
        var threatIntelHits: [ThreatIntelHit] = ThreatIntelScanner.shared.matchHash(hashValue)

        if isLikelyScript || basicInfo.fileType.isScriptType || basicInfo.fileType == .plist || basicInfo.fileType == .unknown {
            let sample = readTextSample(fileURL: fileURL)
            if let sample, !sample.isEmpty {
                snippet = sample
                result.technicalDetails.append(TechnicalDetail(title: "Text Sample", content: sample))
                let intelHits = ThreatIntelScanner.shared.scanTextContent(sample, sha256: hashValue, maxMatches: 36)
                threatIntelHits.append(contentsOf: intelHits)
                keywordHits = detectSuspiciousKeywords(in: sample, intelHits: intelHits)
            }
        } else {
            if case let .success(stringsResult) = commandRunner.runShell("/usr/bin/strings -n 6 \(shellEscape(fileURL.path)) | /usr/bin/head -n 80"),
               !stringsResult.stdout.isEmpty
            {
                result.technicalDetails.append(TechnicalDetail(title: "strings sample", content: stringsResult.stdout))
                let intelHits = ThreatIntelScanner.shared.scanTextContent(stringsResult.stdout, sha256: hashValue, maxMatches: 30)
                threatIntelHits.append(contentsOf: intelHits)
                keywordHits = detectSuspiciousKeywords(in: stringsResult.stdout, intelHits: intelHits)
            }
        }

        threatIntelHits = threatIntelHits.sorted(by: { lhs, rhs in
            if lhs.scoreDelta == rhs.scoreDelta {
                return lhs.matchedValue < rhs.matchedValue
            }
            return lhs.scoreDelta > rhs.scoreDelta
        })
        var intelSeen = Set<String>()
        threatIntelHits = threatIntelHits.filter { hit in
            let key = "\(hit.category.rawValue)|\(hit.matchedValue)|\(hit.ruleID)"
            if intelSeen.contains(key) {
                return false
            }
            intelSeen.insert(key)
            return true
        }
        if !threatIntelHits.isEmpty {
            let detailLines = threatIntelHits.prefix(40).map { hit in
                "[\(hit.category.rawValue)] +\(hit.scoreDelta) \(hit.matchedValue)"
            }
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "Threat Intel Unified Rule Hits",
                    content: detailLines.joined(separator: "\n")
                )
            )
        }

        let disguised = detectExtensionDisguise(extensionType: basicInfo.fileType, magicText: typeText)

        result.genericDetails = GenericFileDetails(
            fileTypeByMagic: typeText.isEmpty ? nil : typeText,
            mimeType: mimeText.isEmpty ? nil : mimeText,
            sha256: hashValue,
            isExecutable: isExecutable,
            isPossiblyDisguised: disguised,
            scriptSnippet: snippet,
            suspiciousKeywordHits: keywordHits
        )

        if disguised {
            result.warnings.append("File extension does not match detected content type. Potential masquerading detected.")
            result.sensitiveCapabilities.append("Possible disguised file type")
        }

        if isExecutable {
            result.sensitiveCapabilities.append("Executable file")
        }

        if !keywordHits.isEmpty {
            result.sensitiveCapabilities.append("Suspicious keywords: \(keywordHits.joined(separator: ", "))")
        }

        if !threatIntelHits.isEmpty {
            let intelRuleHits = threatIntelHits.prefix(40).map { hit in
                ScriptRuleHit(
                    ruleID: hit.ruleID,
                    title: "Threat Intel \(hit.category.rawValue)",
                    severity: threatIntelSeverity(for: hit.scoreDelta),
                    matchedContent: hit.matchedValue,
                    lineStart: 0,
                    lineEnd: 0,
                    explanation: "Matched unified threat profile section [\(hit.category.rawValue)].",
                    suggestedRiskScoreDelta: hit.scoreDelta
                )
            }

            result.scriptDetails = ScriptAnalysisDetails(
                scriptType: basicInfo.fileType,
                shebang: nil,
                lineCount: 0,
                tokenCount: 0,
                commandSample: [],
                summary: [
                    "Threat intel matched \(threatIntelHits.count) unified rules",
                    "Hash rules are always evaluated for every file"
                ],
                ruleHits: intelRuleHits
            )
        }

        if keywordHits.contains(where: { $0.localizedCaseInsensitiveContains("csrutil") || $0.localizedCaseInsensitiveContains("amfi") }) {
            result.persistenceIndicators.append("Potential SIP bypass related script keywords detected")
            result.warnings.append("High-priority warning: possible SIP bypass workflow signal detected. Manual review required.")
        }

        if result.technicalDetails.isEmpty {
            result.warnings.append("Only basic file metadata is available for this file.")
        }

        return result
    }

    private func readTextSample(fileURL: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: fileURL) else {
            return nil
        }
        defer { try? handle.close() }

        let maxBytes = 256 * 1024
        guard let rawData = try? handle.read(upToCount: maxBytes),
              !rawData.isEmpty
        else {
            return nil
        }

        // 避免把二进制内容误当作文本，降低大文件分析时的卡顿风险。
        let nullByteCount = rawData.reduce(into: 0) { partialResult, byte in
            if byte == 0 { partialResult += 1 }
        }
        if nullByteCount > 16 {
            return nil
        }

        let raw = String(decoding: rawData, as: UTF8.self)
        return raw.split(whereSeparator: \.isNewline)
            .prefix(60)
            .map(String.init)
            .joined(separator: "\n")
    }

    private func isTextScript(fileURL: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: fileURL) else {
            return false
        }
        defer { try? handle.close() }

        let data = (try? handle.read(upToCount: 64)) ?? Data()
        guard let text = String(data: data, encoding: .utf8) else {
            return false
        }
        return text.hasPrefix("#!")
    }

    private func detectSuspiciousKeywords(in text: String, intelHits: [ThreatIntelHit]) -> [String] {
        let lower = text.lowercased()
        let keywords = [
            "launchctl",
            "osascript",
            "curl ",
            "wget ",
            "chmod +x",
            "sudo ",
            "csrutil disable",
            "amfi_get_out_of_my_way",
            "tccutil",
            "defaults write",
            "loginitems",
            "launchagents",
            "launchdaemons",
            "system integrity protection"
        ]
        var hits = keywords.filter { lower.contains($0) }
        hits.append(contentsOf: intelHits.map { "\($0.category.rawValue):\($0.matchedValue)" })
        return hits.uniquePreservingOrder()
    }

    private func threatIntelSeverity(for score: Int) -> ScriptFindingSeverity {
        switch score {
        case 28...:
            return .critical
        case 18...:
            return .high
        case 10...:
            return .medium
        default:
            return .low
        }
    }

    private func detectExtensionDisguise(extensionType: SupportedFileType, magicText: String) -> Bool {
        let lower = magicText.lowercased()

        switch extensionType {
        case .shellScript, .pythonScript, .javaScript, .appleScript:
            return lower.contains("mach-o") || lower.contains("dynamically linked shared library")
        case .plist:
            return lower.contains("mach-o") || lower.contains("elf") || lower.contains("pe32")
        case .archive:
            return lower.contains("mach-o") && !lower.contains("archive")
        case .dylib:
            return !lower.contains("mach-o")
        case .machO:
            return lower.contains("script text")
        default:
            return false
        }
    }

    private func shellEscape(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "'", with: "'\\''")
        return "'\(escaped)'"
    }
}

final class ScriptAnalyzer: StaticAnalyzer {
    let analyzerName = "ScriptAnalyzer"
    let supportedTypes: Set<SupportedFileType> = [.shellScript, .pythonScript, .appleScript, .javaScript]

    private let commandRunner: CommandRunning

    init(commandRunner: CommandRunning) {
        self.commandRunner = commandRunner
    }

    func analyze(fileURL: URL, basicInfo: FileBasicInfo) async -> AnalysisResult {
        var result = AnalysisResult.placeholder(for: basicInfo, request: .default)

        guard let source = readScriptSource(fileURL: fileURL) else {
            result.warnings.append("Script file cannot be decoded as UTF-8 text.")
            return result
        }

        var shaValue: String?
        if case let .success(hashCommand) = commandRunner.run(executable: "/usr/bin/shasum", arguments: ["-a", "256", fileURL.path]) {
            shaValue = hashCommand.stdout.split(separator: " ").first.map(String.init)
            result.technicalDetails.append(TechnicalDetail(title: "SHA256", content: hashCommand.stdout))
        }

        let shebang = source.split(whereSeparator: \.isNewline).first.map(String.init)
        let context = ScriptAnalysisContext(
            scriptType: basicInfo.fileType,
            source: source,
            shebang: shebang
        )

        let engine = ScriptRuleEngine()
        let engineHits = engine.evaluate(context: context)
        let intelHits = buildThreatIntelHits(context: context, sha256: shaValue)
        let hits = dedupeScriptHits(engineHits + intelHits)
        let summary = buildScriptSummary(hits: hits)

        result.scriptDetails = ScriptAnalysisDetails(
            scriptType: basicInfo.fileType,
            shebang: shebang?.hasPrefix("#!") == true ? shebang : nil,
            lineCount: context.lines.count,
            tokenCount: context.tokenCount,
            commandSample: Array(context.lines.prefix(8).map { "[L\($0.number)] \($0.trimmed)" }),
            summary: summary,
            ruleHits: hits
        )

        result.genericDetails = GenericFileDetails(
            fileTypeByMagic: nil,
            mimeType: "text/plain",
            sha256: shaValue,
            isExecutable: FileManager.default.isExecutableFile(atPath: fileURL.path),
            isPossiblyDisguised: false,
            scriptSnippet: context.previewText,
            suspiciousKeywordHits: hits.map { $0.ruleID }
        )

        result.technicalDetails.append(
            TechnicalDetail(
                title: "Script Metadata",
                content: [
                    "Type: \(basicInfo.fileType.rawValue)",
                    "Line count: \(context.lines.count)",
                    "Token count: \(context.tokenCount)",
                    "Shebang: \(context.shebang ?? "-")"
                ].joined(separator: "\n")
            )
        )

        if hits.isEmpty {
            result.plainSummary.append("未发现高风险规则命中")
            result.sensitiveCapabilities.append("No high-risk script rule hit")
        } else {
            result.sensitiveCapabilities.append(contentsOf: summary)
            let criticalOrHigh = hits.filter { $0.severity == .critical || $0.severity == .high }
            if !criticalOrHigh.isEmpty {
                result.warnings.append("Script analyzer detected \(criticalOrHigh.count) high-severity findings.")
            }

            let persistenceHits = hits.filter {
                let id = $0.ruleID.lowercased()
                return id.contains("launchagent")
                    || id.contains("launchdaemon")
                    || id.contains("profile")
                    || id.contains("launchctl")
                    || id.contains("persistence")
            }
            if !persistenceHits.isEmpty {
                result.persistenceIndicators.append("Script persistence behavior detected.")
            }

            let top = hits.prefix(16).map { hit in
                "\(hit.ruleID) [\(hit.severity.rawValue)] L\(hit.lineStart)-\(hit.lineEnd): \(hit.matchedContent)"
            }
            result.technicalDetails.append(
                TechnicalDetail(
                    title: "Script Rule Hits",
                    content: top.joined(separator: "\n")
                )
            )
        }

        result.sensitiveCapabilities = result.sensitiveCapabilities.uniquePreservingOrder()
        result.persistenceIndicators = result.persistenceIndicators.uniquePreservingOrder()
        result.warnings = result.warnings.uniquePreservingOrder()

        return result
    }

    private func buildThreatIntelHits(context: ScriptAnalysisContext, sha256: String?) -> [ScriptRuleHit] {
        var hits: [ScriptRuleHit] = []

        let intelMatches = ThreatIntelScanner.shared.scanTextContent(context.source, sha256: sha256, maxMatches: 64)
        for match in intelMatches {
            let severity: ScriptFindingSeverity
            switch match.scoreDelta {
            case 24...:
                severity = .critical
            case 14...:
                severity = .high
            case 8...:
                severity = .medium
            default:
                severity = .low
            }

            let line = firstMatchedLineNumber(context: context, pattern: match.matchedValue)
            hits.append(
                ScriptRuleHit(
                    ruleID: match.ruleID,
                    title: "Threat Intel \(match.category.rawValue)",
                    severity: severity,
                    matchedContent: match.matchedValue,
                    lineStart: line,
                    lineEnd: line,
                    explanation: "Matched unified threat profile section [\(match.category.rawValue)].",
                    suggestedRiskScoreDelta: match.scoreDelta
                )
            )
        }

        return hits
    }

    private func dedupeScriptHits(_ hits: [ScriptRuleHit]) -> [ScriptRuleHit] {
        var seen = Set<String>()
        return hits.filter { hit in
            let key = "\(hit.ruleID)|\(hit.lineStart)|\(hit.lineEnd)|\(hit.matchedContent)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }

    private func firstMatchedLineNumber(context: ScriptAnalysisContext, pattern: String) -> Int {
        let lower = pattern.lowercased()
        return context.lines.first(where: { $0.lower.contains(lower) })?.number ?? 0
    }

    private func readScriptSource(fileURL: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: fileURL) else {
            return nil
        }
        defer { try? handle.close() }

        let maxBytes = 2 * 1024 * 1024
        guard let data = try? handle.read(upToCount: maxBytes), !data.isEmpty else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func buildScriptSummary(hits: [ScriptRuleHit]) -> [String] {
        if hits.isEmpty {
            return ["未发现高风险规则命中"]
        }

        var summary: [String] = []
        let ids = hits.map(\.ruleID).map { $0.lowercased() }

        if ids.contains(where: { $0.contains("download") || $0.contains("curl") || $0.contains("wget") }) {
            summary.append("检测到远程下载执行链")
        }
        if ids.contains(where: { $0.contains("launch") || $0.contains("profile") || $0.contains("persistence") }) {
            summary.append("检测到持久化行为")
        }
        if ids.contains(where: { $0.contains("base64") || $0.contains("obfuscation") || $0.contains("eval") || $0.contains("exec") }) {
            summary.append("检测到混淆或编码逃逸")
        }
        if summary.isEmpty {
            summary.append("检测到脚本高风险行为特征")
        }
        return summary.uniquePreservingOrder()
    }
}

private struct ScriptAnalysisContext {
    let scriptType: SupportedFileType
    let source: String
    let shebang: String?
    let lines: [ScriptLine]
    let tokenCount: Int
    let previewText: String

    init(scriptType: SupportedFileType, source: String, shebang: String?) {
        self.scriptType = scriptType
        self.source = source
        self.shebang = shebang

        let splitLines = source.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).map(String.init)
        var built: [ScriptLine] = []
        var totalTokens = 0

        for (index, rawLine) in splitLines.enumerated() {
            let lineNumber = index + 1
            let trimmed = rawLine.trimmingCharacters(in: CharacterSet.whitespaces)
            let tokens = ScriptTokenizer.tokenize(trimmed)
            totalTokens += tokens.count
            built.append(
                ScriptLine(
                    number: lineNumber,
                    raw: rawLine,
                    trimmed: trimmed,
                    lower: trimmed.lowercased(),
                    tokens: tokens
                )
            )
        }

        lines = built
        tokenCount = totalTokens
        previewText = built.prefix(40).map(\.trimmed).joined(separator: "\n")
    }
}

private struct ScriptLine {
    let number: Int
    let raw: String
    let trimmed: String
    let lower: String
    let tokens: [String]
}

private enum ScriptTokenizer {
    static func tokenize(_ line: String) -> [String] {
        guard !line.isEmpty else {
            return []
        }

        let pattern = #""[^"]*"|'[^']*'|\S+"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return line.split(whereSeparator: \.isWhitespace).map(String.init)
        }

        let range = NSRange(line.startIndex..<line.endIndex, in: line)
        let matches = regex.matches(in: line, range: range)
        return matches.compactMap { match in
            guard let subrange = Range(match.range, in: line) else {
                return nil
            }
            return String(line[subrange])
        }
    }
}

private struct ScriptRule {
    let id: String
    let title: String
    let severity: ScriptFindingSeverity
    let explanation: String
    let suggestedRiskScoreDelta: Int
    let supportedTypes: Set<SupportedFileType>
    let matcher: (ScriptAnalysisContext) -> [ScriptRuleMatch]
}

private struct ScriptRuleMatch {
    let lineStart: Int
    let lineEnd: Int
    let matchedContent: String
}

private final class ScriptRuleEngine {
    private lazy var rules: [ScriptRule] = buildRules()

    func evaluate(context: ScriptAnalysisContext) -> [ScriptRuleHit] {
        var hits: [ScriptRuleHit] = []

        for rule in rules where rule.supportedTypes.contains(context.scriptType) {
            let matches = rule.matcher(context)
            for match in matches {
                hits.append(
                    ScriptRuleHit(
                        ruleID: rule.id,
                        title: rule.title,
                        severity: rule.severity,
                        matchedContent: summarizeMatch(match.matchedContent),
                        lineStart: match.lineStart,
                        lineEnd: match.lineEnd,
                        explanation: rule.explanation,
                        suggestedRiskScoreDelta: rule.suggestedRiskScoreDelta
                    )
                )
            }
        }

        return dedupe(hits).sorted {
            if $0.severity != $1.severity {
                return severityRank($0.severity) > severityRank($1.severity)
            }
            if $0.lineStart != $1.lineStart {
                return $0.lineStart < $1.lineStart
            }
            return $0.ruleID < $1.ruleID
        }
    }

    private func buildRules() -> [ScriptRule] {
        let shellTypes: Set<SupportedFileType> = [.shellScript]
        let pythonTypes: Set<SupportedFileType> = [.pythonScript]
        let appleTypes: Set<SupportedFileType> = [.appleScript]
        let jsTypes: Set<SupportedFileType> = [.javaScript]

        return [
            ScriptRule(
                id: "shell.curl_pipe_sh",
                title: "curl 下载后直接管道执行",
                severity: .critical,
                explanation: "检测到 curl 输出直接通过管道进入 sh/bash/zsh，属于典型远程代码直接执行链。",
                suggestedRiskScoreDelta: 35,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"curl\b[^\n|]*\|\s*(sh|bash|zsh)\b"#)
                }
            ),
            ScriptRule(
                id: "shell.wget_pipe_sh",
                title: "wget 下载后直接管道执行",
                severity: .critical,
                explanation: "检测到 wget 下载结果直接传递到 shell 执行，绕过落地审计。",
                suggestedRiskScoreDelta: 35,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"wget\b[^\n|]*\|\s*(sh|bash|zsh)\b"#)
                }
            ),
            ScriptRule(
                id: "shell.reverse_tcp",
                title: "反弹 shell 特征",
                severity: .critical,
                explanation: "发现 bash -i >& /dev/tcp 或等价反连写法，常见于远控初始接入脚本。",
                suggestedRiskScoreDelta: 40,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"bash\s+-i.*?/dev/tcp/"#)
                }
            ),
            ScriptRule(
                id: "shell.nc_exec",
                title: "nc -e 远程执行",
                severity: .critical,
                explanation: "检测到 netcat 通过 -e 参数绑定命令执行，属于高风险远程控制行为。",
                suggestedRiskScoreDelta: 38,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"\bnc\b.*\s-e\s"#)
                }
            ),
            ScriptRule(
                id: "shell.launchctl.persistence",
                title: "launchctl 持久化操作",
                severity: .high,
                explanation: "脚本调用 launchctl load/bootstrap，可能用于注册常驻项。",
                suggestedRiskScoreDelta: 20,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"launchctl\s+(load|bootstrap)\b"#)
                }
            ),
            ScriptRule(
                id: "shell.chmod_exec_chain",
                title: "chmod +x 后立即执行",
                severity: .high,
                explanation: "脚本在短窗口内赋予执行权限后立刻执行同一目标，常见于投递落地链路。",
                suggestedRiskScoreDelta: 22,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.detectChmodExecuteChain(context)
                }
            ),
            ScriptRule(
                id: "shell.osascript_shell",
                title: "osascript 内联 shell 执行",
                severity: .high,
                explanation: "发现 osascript -e 中调用 shell 命令，常用于绕过简单命令审计。",
                suggestedRiskScoreDelta: 18,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"osascript\b.*-e.*(do shell script|sh -c|bash -c|zsh -c)"#)
                }
            ),
            ScriptRule(
                id: "shell.mktemp_download_exec",
                title: "mktemp + 下载 + 执行链",
                severity: .critical,
                explanation: "检测到临时目录生成、远程下载与执行组合链路，具备典型投递行为。",
                suggestedRiskScoreDelta: 30,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.detectMktempDownloadExecuteChain(context)
                }
            ),
            ScriptRule(
                id: "shell.base64_exec",
                title: "base64 解码后执行",
                severity: .high,
                explanation: "发现 base64 解码后直接交给 shell/eval 执行，存在编码逃逸风险。",
                suggestedRiskScoreDelta: 24,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"base64\s+(-d|--decode).*?(\|\s*(sh|bash|zsh)|eval\b)"#)
                }
            ),
            ScriptRule(
                id: "shell.rm_rf_sensitive",
                title: "删除敏感路径",
                severity: .critical,
                explanation: "检测到 rm -rf 指向系统或关键用户路径，破坏性极高。",
                suggestedRiskScoreDelta: 40,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"rm\s+-rf\s+(/(System|Library|private|Users|Applications)|~/(Library|\.))"#)
                }
            ),
            ScriptRule(
                id: "shell.write_launchagent",
                title: "写入 LaunchAgents/LaunchDaemons",
                severity: .critical,
                explanation: "脚本尝试写入 LaunchAgents 或 LaunchDaemons 目录，属于持久化高风险行为。",
                suggestedRiskScoreDelta: 32,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(LaunchAgents|LaunchDaemons).*?(\.plist|>|tee|cat\s*<<|cp\s|mv\s)"#)
                }
            ),
            ScriptRule(
                id: "shell.profile_persistence",
                title: "修改 shell 启动配置",
                severity: .high,
                explanation: "检测到修改 ~/.zshrc 或 ~/.bash_profile 等启动文件，可能实现用户级持久化。",
                suggestedRiskScoreDelta: 18,
                supportedTypes: shellTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(~/.zshrc|~/.bash_profile|~/.bashrc|~/.zprofile)"#)
                }
            ),
            ScriptRule(
                id: "python.os_system",
                title: "os.system 命令执行",
                severity: .high,
                explanation: "Python 脚本调用 os.system 触发 shell 执行，具备命令注入与落地风险。",
                suggestedRiskScoreDelta: 20,
                supportedTypes: pythonTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"\bos\.system\s*\("#)
                }
            ),
            ScriptRule(
                id: "python.subprocess_exec",
                title: "subprocess 外部进程执行",
                severity: .high,
                explanation: "检测到 subprocess.run/call/Popen，脚本可直接拉起外部二进制或 shell。",
                suggestedRiskScoreDelta: 20,
                supportedTypes: pythonTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"\bsubprocess\.(Popen|run|call)\s*\("#)
                }
            ),
            ScriptRule(
                id: "python.eval_exec",
                title: "动态代码执行(eval/exec)",
                severity: .critical,
                explanation: "检测到 eval 或 exec，可能用于动态加载隐藏载荷。",
                suggestedRiskScoreDelta: 32,
                supportedTypes: pythonTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"\b(eval|exec)\s*\("#)
                }
            ),
            ScriptRule(
                id: "python.network_loader",
                title: "网络下载载荷特征",
                severity: .medium,
                explanation: "检测到 requests/urllib/socket 相关代码。需结合执行链条再判定高危。",
                suggestedRiskScoreDelta: 12,
                supportedTypes: pythonTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(requests\.(get|post)|urllib\.request\.(urlopen|urlretrieve)|socket\.)"#)
                }
            ),
            ScriptRule(
                id: "python.obfuscation",
                title: "编码/压缩混淆痕迹",
                severity: .medium,
                explanation: "检测到 base64/marshal/zlib 或 PyInstaller 痕迹，存在代码隐藏风险。",
                suggestedRiskScoreDelta: 14,
                supportedTypes: pythonTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(base64|marshal|zlib|_MEIPASS|pyinstaller)"#)
                }
            ),
            ScriptRule(
                id: "python.persistence_write",
                title: "写入启动项或敏感路径",
                severity: .critical,
                explanation: "检测到 plistlib/open 写入 LaunchAgents/LaunchDaemons 等敏感路径。",
                suggestedRiskScoreDelta: 30,
                supportedTypes: pythonTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(plistlib|open\s*\().*(LaunchAgents|LaunchDaemons|\.zshrc|\.bash_profile)"#)
                }
            ),
            ScriptRule(
                id: "python.ctypes_dylib",
                title: "ctypes 动态库加载",
                severity: .high,
                explanation: "检测到 ctypes 加载动态库，可绕过高层 API 直接调用底层能力。",
                suggestedRiskScoreDelta: 20,
                supportedTypes: pythonTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(ctypes\.(CDLL|PyDLL|cdll\.LoadLibrary)|find_library)"#)
                }
            ),
            ScriptRule(
                id: "python.pty_reverse_shell",
                title: "pty/reverse shell 行为特征",
                severity: .critical,
                explanation: "检测到 pty.spawn 与 socket/subprocess 组合，疑似反弹 shell。",
                suggestedRiskScoreDelta: 35,
                supportedTypes: pythonTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(pty\.spawn|/bin/sh|/bin/bash).*(socket|connect|subprocess)"#)
                }
            ),
            ScriptRule(
                id: "applescript.do_shell_script",
                title: "AppleScript 调用 shell",
                severity: .high,
                explanation: "AppleScript do shell script 可直接执行系统命令。",
                suggestedRiskScoreDelta: 20,
                supportedTypes: appleTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"\bdo shell script\b"#)
                }
            ),
            ScriptRule(
                id: "applescript.terminal_control",
                title: "控制 Terminal 应用",
                severity: .medium,
                explanation: "脚本可驱动 Terminal 执行命令，存在行为链隐藏风险。",
                suggestedRiskScoreDelta: 12,
                supportedTypes: appleTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"tell application\s+"terminal""#)
                }
            ),
            ScriptRule(
                id: "applescript.finder_control",
                title: "控制 Finder 行为",
                severity: .low,
                explanation: "脚本可控制 Finder 进行文件操作，需要结合上下文评估风险。",
                suggestedRiskScoreDelta: 8,
                supportedTypes: appleTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"tell application\s+"finder""#)
                }
            ),
            ScriptRule(
                id: "applescript.permission_page",
                title: "打开系统权限设置页",
                severity: .high,
                explanation: "脚本尝试打开隐私/权限设置页面，可能用于诱导授权。",
                suggestedRiskScoreDelta: 18,
                supportedTypes: appleTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(x-apple\.systempreferences|privacy_accessibility|privacy_allfiles|privacy_automation)"#)
                }
            ),
            ScriptRule(
                id: "applescript.download_execute",
                title: "AppleScript 下载执行链",
                severity: .critical,
                explanation: "在 do shell script 中出现下载并执行命令，风险极高。",
                suggestedRiskScoreDelta: 35,
                supportedTypes: appleTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(do shell script).*(curl|wget).*(\|\s*(sh|bash|zsh)|osascript|python)"#)
                }
            ),
            ScriptRule(
                id: "applescript.social_engineering",
                title: "疑似授权诱导语义",
                severity: .medium,
                explanation: "发现管理员权限或授权提示语义，可能用于社会工程。",
                suggestedRiskScoreDelta: 12,
                supportedTypes: appleTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(administrator privileges|grant|permission|allow access)"#)
                }
            ),
            ScriptRule(
                id: "javascript.child_process",
                title: "Node child_process 执行链",
                severity: .high,
                explanation: "检测到 child_process 模块使用，可直接执行 shell 或二进制命令。",
                suggestedRiskScoreDelta: 22,
                supportedTypes: jsTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"child_process|require\(['"]child_process['"]\)|\b(exec|spawn|execSync)\s*\("#)
                }
            ),
            ScriptRule(
                id: "javascript.eval",
                title: "JavaScript 动态执行(eval)",
                severity: .high,
                explanation: "检测到 eval/Function 构造动态代码执行，存在混淆载荷风险。",
                suggestedRiskScoreDelta: 22,
                supportedTypes: jsTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"\beval\s*\(|\bFunction\s*\("#)
                }
            ),
            ScriptRule(
                id: "javascript.base64_obfuscation",
                title: "Buffer/base64 混淆痕迹",
                severity: .medium,
                explanation: "发现 base64 编码还原逻辑，可能用于隐藏关键执行片段。",
                suggestedRiskScoreDelta: 14,
                supportedTypes: jsTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(Buffer\.from\s*\(.*base64|atob\s*\(|fromCharCode)"#)
                }
            ),
            ScriptRule(
                id: "javascript.network_download_exec",
                title: "网络下载并执行链",
                severity: .critical,
                explanation: "检测到 http/https/fetch 下载内容并联动执行，符合远程载荷特征。",
                suggestedRiskScoreDelta: 34,
                supportedTypes: jsTypes,
                matcher: { context in
                    self.detectJSDownloadExecuteChain(context)
                }
            ),
            ScriptRule(
                id: "javascript.osascript_shell_chain",
                title: "JavaScript 调用 osascript/shell",
                severity: .high,
                explanation: "发现 Node 脚本通过 osascript 或 shell 触发跨语言命令链。",
                suggestedRiskScoreDelta: 24,
                supportedTypes: jsTypes,
                matcher: { context in
                    self.lineRegexMatches(context, pattern: #"(osascript|/bin/sh|/bin/bash|zsh -c)"#)
                }
            )
        ]
    }

    private func lineRegexMatches(_ context: ScriptAnalysisContext, pattern: String) -> [ScriptRuleMatch] {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return []
        }

        var matches: [ScriptRuleMatch] = []
        for line in context.lines where !line.trimmed.isEmpty && !isCommentOnlyLine(line.trimmed) {
            let range = NSRange(line.trimmed.startIndex..<line.trimmed.endIndex, in: line.trimmed)
            if regex.firstMatch(in: line.trimmed, range: range) != nil {
                matches.append(
                    ScriptRuleMatch(
                        lineStart: line.number,
                        lineEnd: line.number,
                        matchedContent: line.trimmed
                    )
                )
            }
        }
        return matches
    }

    private func detectChmodExecuteChain(_ context: ScriptAnalysisContext) -> [ScriptRuleMatch] {
        var hits: [ScriptRuleMatch] = []
        for line in context.lines where line.lower.contains("chmod") && line.lower.contains("+x") {
            let target = extractLastToken(line.tokens)
            let currentIndex = line.number - 1
            let startIndex = min(currentIndex + 1, context.lines.count)
            let endExclusive = min(currentIndex + 4, context.lines.count)
            guard startIndex < endExclusive else { continue }
            let searchSlice = context.lines[startIndex..<endExclusive]

            if let executeLine = searchSlice.first(where: { next in
                guard !next.lower.hasPrefix("#") else { return false }
                if let target, !target.isEmpty {
                    return next.trimmed.contains(target) && !next.lower.contains("chmod")
                }
                return next.trimmed.hasPrefix("./") || next.lower.contains("bash ") || next.lower.contains("sh ")
            }) {
                hits.append(
                    ScriptRuleMatch(
                        lineStart: line.number,
                        lineEnd: executeLine.number,
                        matchedContent: "\(line.trimmed)  =>  \(executeLine.trimmed)"
                    )
                )
            }
        }
        return hits
    }

    private func detectMktempDownloadExecuteChain(_ context: ScriptAnalysisContext) -> [ScriptRuleMatch] {
        let mktempLines = context.lines.filter { $0.lower.contains("mktemp") }
        let downloadLines = context.lines.filter { $0.lower.contains("curl ") || $0.lower.contains("wget ") }
        let executeLines = context.lines.filter {
            $0.lower.contains("sh ") || $0.lower.contains("bash ") || $0.trimmed.hasPrefix("./") || $0.lower.contains("chmod +x")
        }

        guard let mk = mktempLines.first,
              let dl = downloadLines.first(where: { $0.number >= mk.number }),
              let exec = executeLines.first(where: { $0.number >= dl.number })
        else {
            return []
        }

        return [
            ScriptRuleMatch(
                lineStart: mk.number,
                lineEnd: exec.number,
                matchedContent: "\(mk.trimmed)  =>  \(dl.trimmed)  =>  \(exec.trimmed)"
            )
        ]
    }

    private func detectJSDownloadExecuteChain(_ context: ScriptAnalysisContext) -> [ScriptRuleMatch] {
        let downloadLines = context.lines.filter { line in
            line.lower.contains("http.get")
                || line.lower.contains("https.get")
                || line.lower.contains("fetch(")
                || line.lower.contains("axios.")
        }

        guard !downloadLines.isEmpty else { return [] }

        let executionLines = context.lines.filter { line in
            line.lower.contains("child_process")
                || line.lower.contains("exec(")
                || line.lower.contains("execsync(")
                || line.lower.contains("spawn(")
                || line.lower.contains("| sh")
                || line.lower.contains("bash -c")
                || line.lower.contains("zsh -c")
        }

        guard let dl = downloadLines.first else { return [] }
        guard let exec = executionLines.first(where: { $0.number >= dl.number }) else { return [] }

        return [
            ScriptRuleMatch(
                lineStart: dl.number,
                lineEnd: exec.number,
                matchedContent: "\(dl.trimmed)  =>  \(exec.trimmed)"
            )
        ]
    }

    private func extractLastToken(_ tokens: [String]) -> String? {
        tokens.last?.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
    }

    private func isCommentOnlyLine(_ line: String) -> Bool {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return true
        }
        return trimmed.hasPrefix("#")
            || trimmed.hasPrefix("//")
            || trimmed.hasPrefix("/*")
            || trimmed.hasPrefix("*")
    }

    private func summarizeMatch(_ content: String) -> String {
        let trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.count <= 240 {
            return trimmed
        }
        let index = trimmed.index(trimmed.startIndex, offsetBy: 240)
        return String(trimmed[..<index]) + "..."
    }

    private func dedupe(_ hits: [ScriptRuleHit]) -> [ScriptRuleHit] {
        var seen = Set<String>()
        return hits.filter { hit in
            let key = "\(hit.ruleID)|\(hit.lineStart)|\(hit.lineEnd)|\(hit.matchedContent)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }

    private func severityRank(_ severity: ScriptFindingSeverity) -> Int {
        switch severity {
        case .low:
            return 1
        case .medium:
            return 2
        case .high:
            return 3
        case .critical:
            return 4
        }
    }
}
