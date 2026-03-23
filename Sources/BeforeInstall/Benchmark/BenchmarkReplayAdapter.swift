import Foundation

struct BenchmarkReplayAnalysisOutput {
    var detectedType: String
    var score: Int
    var verdict: String
    var findings: [String]
    var riskFindings: [RiskRuleResult]
    var replayDebug: BenchmarkReplayDebugRecord
}

final class BenchmarkReplayAdapter {
    enum ReplayError: LocalizedError {
        case replayFileNotFound(path: String)
        case replayReadFailed(path: String, reason: String)
        case replayDecodeFailed(path: String, reason: String)
        case replayEventMappingFailed(path: String, reason: String)

        var errorDescription: String? {
            switch self {
            case let .replayFileNotFound(path):
                return "Replay file not found: \(path)"
            case let .replayReadFailed(path, reason):
                return "Replay file read failed: \(path) (\(reason))"
            case let .replayDecodeFailed(path, reason):
                return "Replay decode failed: \(path) (\(reason))"
            case let .replayEventMappingFailed(path, reason):
                return "Replay event mapping failed: \(path) (\(reason))"
            }
        }

        var errorCode: BenchmarkRunnerErrorCode {
            switch self {
            case .replayFileNotFound:
                return .replayFileNotFound
            case .replayReadFailed:
                return .replayReadFailed
            case .replayDecodeFailed:
                return .replayDecodeFailed
            case .replayEventMappingFailed:
                return .replayEventMappingFailed
            }
        }
    }

    struct ReplayFailure: Error {
        var replayError: ReplayError
        var debugRecord: BenchmarkReplayDebugRecord
    }

    private let riskEngine: RiskEngine
    private let fileManager = FileManager.default

    init(riskEngine: RiskEngine = RiskEngine()) {
        self.riskEngine = riskEngine
    }

    func analyzeReplaySample(sample: BenchmarkSample, language: AppLanguage) throws -> BenchmarkReplayAnalysisOutput {
        let fileURL = URL(fileURLWithPath: sample.absolutePath).standardizedFileURL
        var debug = BenchmarkReplayDebugRecord(
            sampleID: sample.sampleID,
            relativePath: sample.relativePath,
            resolvedAbsolutePath: fileURL.path,
            fileExists: false,
            fileSizeBytes: nil,
            readSucceeded: false,
            decodeSucceeded: false,
            eventCount: nil,
            mappingSucceeded: false,
            errorCode: nil,
            finalError: nil
        )

        var isDirectory: ObjCBool = false
        let exists = fileManager.fileExists(atPath: fileURL.path, isDirectory: &isDirectory)
        debug.fileExists = exists && !isDirectory.boolValue

        guard debug.fileExists else {
            let error = ReplayError.replayFileNotFound(path: fileURL.path)
            debug.errorCode = error.errorCode
            debug.finalError = error.localizedDescription
            throw ReplayFailure(replayError: error, debugRecord: debug)
        }

        if let attrs = try? fileManager.attributesOfItem(atPath: fileURL.path),
           let fileSize = attrs[.size] as? NSNumber {
            debug.fileSizeBytes = fileSize.int64Value
        }

        let scopeEnabled = fileURL.startAccessingSecurityScopedResource()
        defer {
            if scopeEnabled {
                fileURL.stopAccessingSecurityScopedResource()
            }
        }

        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
            debug.readSucceeded = true
        } catch {
            let replayError = ReplayError.replayReadFailed(path: fileURL.path, reason: error.localizedDescription)
            debug.errorCode = replayError.errorCode
            debug.finalError = replayError.localizedDescription
            throw ReplayFailure(replayError: replayError, debugRecord: debug)
        }

        let replay: ReplayFixture
        do {
            replay = try JSONDecoder().decode(ReplayFixture.self, from: data)
            debug.decodeSucceeded = true
        } catch {
            let replayError = ReplayError.replayDecodeFailed(path: fileURL.path, reason: error.localizedDescription)
            debug.errorCode = replayError.errorCode
            debug.finalError = replayError.localizedDescription
            throw ReplayFailure(replayError: replayError, debugRecord: debug)
        }

        let mappedEvents: [AnalysisEvent]
        do {
            mappedEvents = try replay.events.map { try mapReplayEvent($0) }
            debug.mappingSucceeded = true
            debug.eventCount = mappedEvents.count
        } catch {
            let replayError = ReplayError.replayEventMappingFailed(path: fileURL.path, reason: error.localizedDescription)
            debug.errorCode = replayError.errorCode
            debug.finalError = replayError.localizedDescription
            throw ReplayFailure(replayError: replayError, debugRecord: debug)
        }

        let startTime = mappedEvents.map(\.timestamp).min() ?? Date()
        let endTime = mappedEvents.map(\.timestamp).max()

        let session = DynamicAnalysisSession(
            sessionID: "replay-\(sample.sampleID)",
            samplePath: sample.absolutePath,
            startTime: startTime,
            endTime: endTime,
            events: mappedEvents,
            collectionBoundaries: ["Replay JSON (synthetic event stream)"],
            fallbackSources: ["benchmark/replay"]
        )

        let networkSummary = buildNetworkSummary(from: mappedEvents)
        let dynamicReport = DynamicAnalysisReport(
            overview: DynamicRunOverview(
                status: .completed,
                launchSucceeded: true,
                durationSeconds: max(1, Int((endTime ?? startTime).timeIntervalSince(startTime))),
                actualDuration: max(1, (endTime ?? startTime).timeIntervalSince(startTime)),
                crashed: false,
                mainProcessID: nil,
                hasChildProcesses: mappedEvents.contains(where: { $0.category == .processCreated }),
                hasNetworkActivity: mappedEvents.contains(where: { $0.category == .networkConnect }),
                hasFileWriteActivity: mappedEvents.contains(where: { $0.category == .fileCreated || $0.category == .fileModified }),
                hasPersistenceAttempt: mappedEvents.contains(where: { $0.category == .persistenceAttempt })
            ),
            workspacePath: nil,
            limitationNotes: [
                "Replay analysis uses inert fixture events and does not execute sample code.",
                "This mode validates dynamic scoring logic with deterministic traces."
            ],
            dynamicResults: session,
            sessionLogs: ["Replay fixture decoded: \(sample.relativePath)", "Mapped events: \(mappedEvents.count)"],
            launchResult: nil,
            processObservations: [],
            fileObservations: [],
            networkObservations: [],
            networkRecords: buildNetworkRecords(from: mappedEvents),
            networkSummary: networkSummary,
            fileSystemDiff: buildFileSystemDiff(from: mappedEvents),
            processTreeRoots: [],
            behaviorTimeline: TimelineBuilder().buildLegacyTimeline(events: mappedEvents),
            highRiskChains: buildHighRiskChains(from: mappedEvents),
            suspiciousIndicators: mappedEvents.filter { $0.riskScoreDelta > 0 }.map { "\($0.action) -> \($0.target)" },
            summaryLines: [
                "Replay events: \(mappedEvents.count)",
                "High-risk events: \(session.highRiskEvents.count)"
            ],
            warnings: [],
            failureIssues: []
        )

        let basicInfo = FileBasicInfo(
            fileName: fileURL.lastPathComponent,
            fullPath: sample.absolutePath,
            fileType: .unknown,
            fileSizeBytes: Int64(data.count),
            createdAt: nil,
            modifiedAt: nil
        )

        let request = AnalysisRequest(
            mode: .dynamicOnly,
            depth: .quick,
            dynamicDurationSeconds: 20,
            language: language,
            allowNonAppDynamicExecution: false,
            preferBackgroundAppLaunch: true,
            manualDynamicInteraction: false
        )

        var result = AnalysisResult.placeholder(for: basicInfo, request: request)
        result.analysisMode = .dynamicOnly
        result.analysisDepth = .quick
        result.dynamicResults = session
        result.dynamicReport = dynamicReport
        result.sensitiveCapabilities = dynamicReport.suspiciousIndicators
        result.persistenceIndicators = mappedEvents
            .filter { $0.category == .persistenceAttempt }
            .map { $0.target }
        result.warnings = []

        let evaluation = riskEngine.evaluate(result: result)
        let assessment = riskEngine.toLegacyAssessment(evaluation, language: language)
        result.riskEvaluation = evaluation
        result.riskAssessment = assessment

        let findings = evaluation.allFindings.map { finding in
            let deltaText = finding.scoreDelta > 0 ? "+\(finding.scoreDelta)" : "\(finding.scoreDelta)"
            return "[\(finding.id)] \(finding.title(language: language)) (\(deltaText))"
        }

        return BenchmarkReplayAnalysisOutput(
            detectedType: "jsonReplay",
            score: evaluation.totalScore,
            verdict: evaluation.verdict.rawValue,
            findings: findings,
            riskFindings: evaluation.allFindings,
            replayDebug: debug
        )
    }

    private func mapReplayEvent(_ event: ReplayEvent) throws -> AnalysisEvent {
        let timestamp = parseTimestamp(event.timestamp ?? event.ts) ?? Date()

        if let legacyEvent = event.event?.lowercased(), event.category == nil {
            return mapLegacyEvent(event: event, legacyEvent: legacyEvent, timestamp: timestamp)
        }

        guard let rawCategory = event.category,
              let category = parseCategory(rawCategory)
        else {
            throw ReplayError.replayEventMappingFailed(path: "<memory>", reason: "Missing or unsupported event category")
        }

        let action = event.action ?? event.event ?? rawCategory
        let target = event.target
            ?? event.path
            ?? event.value
            ?? event.dst
            ?? event.src
            ?? event.message
            ?? "unknown"

        return AnalysisEvent(
            timestamp: timestamp,
            category: category,
            processID: event.processID,
            parentProcessID: event.parentProcessID,
            processName: event.processName,
            executablePath: event.executablePath,
            action: action,
            target: target,
            details: event.dictionaryValue,
            riskScoreDelta: event.riskScoreDeltaHint ?? heuristicRiskDelta(category: category, action: action, target: target),
            rawSource: event.rawSource ?? "replay"
        )
    }

    private func mapLegacyEvent(event: ReplayEvent, legacyEvent: String, timestamp: Date) -> AnalysisEvent {
        switch legacyEvent {
        case "file_create":
            return AnalysisEvent(
                timestamp: timestamp,
                category: .fileCreated,
                action: "file_create",
                target: event.path ?? event.value ?? "unknown",
                details: event.dictionaryValue,
                riskScoreDelta: 0,
                rawSource: "replay"
            )
        case "file_copy":
            return AnalysisEvent(
                timestamp: timestamp,
                category: .fileModified,
                action: "file_copy",
                target: event.dst ?? event.path ?? "unknown",
                details: event.dictionaryValue,
                riskScoreDelta: 0,
                rawSource: "replay"
            )
        case "command_preview", "string_artifact":
            return mapStringArtifact(event: event, timestamp: timestamp)
        case "blocked":
            return AnalysisEvent(
                timestamp: timestamp,
                category: .privilegeRelatedAction,
                action: "blocked_by_policy",
                target: event.reason ?? event.message ?? "blocked",
                details: event.dictionaryValue,
                riskScoreDelta: 6,
                rawSource: "replay"
            )
        case "log", "note":
            return AnalysisEvent(
                timestamp: timestamp,
                category: .unknown,
                action: legacyEvent,
                target: event.message ?? event.value ?? "note",
                details: event.dictionaryValue,
                riskScoreDelta: 0,
                rawSource: "replay"
            )
        default:
            return AnalysisEvent(
                timestamp: timestamp,
                category: .unknown,
                action: legacyEvent,
                target: event.value ?? event.path ?? event.message ?? "unknown",
                details: event.dictionaryValue,
                riskScoreDelta: 0,
                rawSource: "replay"
            )
        }
    }

    private func mapStringArtifact(event: ReplayEvent, timestamp: Date) -> AnalysisEvent {
        let content = [event.value, event.message, event.path, event.dst].compactMap { $0 }.joined(separator: " ")
        let lower = content.lowercased()

        if lower.contains("launchctl") || lower.contains("launchagent") || lower.contains("launchdaemon") {
            let target: String
            if let path = event.path, !path.isEmpty {
                target = path
            } else if lower.contains("launchagents") {
                target = content
            } else {
                target = "~/Library/LaunchAgents/com.replay.synthetic.plist"
            }
            return AnalysisEvent(
                timestamp: timestamp,
                category: .persistenceAttempt,
                action: "launch_agent_write_simulated",
                target: target,
                details: event.dictionaryValue,
                riskScoreDelta: 34,
                rawSource: "replay"
            )
        }

        if lower.contains("curl") || lower.contains("wget") || lower.contains("https://") || lower.contains("http://") {
            let action: String
            let delta: Int
            if lower.contains("| sh") || lower.contains("|bash") || lower.contains("exec") {
                action = "mktemp_download_chain"
                delta = 42
            } else {
                action = "download_preview"
                delta = 12
            }
            return AnalysisEvent(
                timestamp: timestamp,
                category: .scriptExecuted,
                action: action,
                target: content,
                details: event.dictionaryValue,
                riskScoreDelta: delta,
                rawSource: "replay"
            )
        }

        if lower.contains("base64") || lower.contains("eval(") || lower.contains("exec(") {
            return AnalysisEvent(
                timestamp: timestamp,
                category: .scriptExecuted,
                action: "base64_decode_execute_chain",
                target: content,
                details: event.dictionaryValue,
                riskScoreDelta: 30,
                rawSource: "replay"
            )
        }

        if lower.contains("osascript") || lower.contains("do shell script") {
            return AnalysisEvent(
                timestamp: timestamp,
                category: .scriptExecuted,
                action: "child_shell_spawned",
                target: content,
                details: event.dictionaryValue,
                riskScoreDelta: 20,
                rawSource: "replay"
            )
        }

        return AnalysisEvent(
            timestamp: timestamp,
            category: .unknown,
            action: event.event ?? "string_artifact",
            target: content.isEmpty ? "artifact" : content,
            details: event.dictionaryValue,
            riskScoreDelta: 0,
            rawSource: "replay"
        )
    }

    private func parseCategory(_ raw: String) -> AnalysisEventCategory? {
        AnalysisEventCategory(rawValue: raw)
    }

    private func heuristicRiskDelta(category: AnalysisEventCategory, action: String, target: String) -> Int {
        let lowerAction = action.lowercased()
        let lowerTarget = target.lowercased()

        if category == .persistenceAttempt {
            return 28
        }
        if lowerTarget.contains("launchagents") || lowerTarget.contains("launchdaemons") {
            return 24
        }
        if lowerAction.contains("download") && (lowerTarget.contains("| sh") || lowerTarget.contains("exec")) {
            return 30
        }
        if lowerAction.contains("download") || category == .networkConnect {
            return 10
        }
        if lowerAction.contains("exec") || lowerAction.contains("spawn") {
            return 12
        }
        return 0
    }

    private func parseTimestamp(_ ts: String?) -> Date? {
        guard let ts, !ts.isEmpty else { return nil }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let parsed = formatter.date(from: ts) {
            return parsed
        }

        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: ts)
    }

    private func buildNetworkSummary(from events: [AnalysisEvent]) -> NetworkSummary? {
        let networkEvents = events.filter { $0.category == .networkConnect || $0.action.contains("download") }
        guard !networkEvents.isEmpty else {
            return nil
        }

        let destinations = networkEvents.map(\.target).uniquePreservingOrder()
        return NetworkSummary(
            totalConnections: networkEvents.count,
            remoteConnections: networkEvents.count,
            uniqueDestinations: destinations,
            uniqueRemoteIPs: [],
            firstConnectionAt: networkEvents.map(\.timestamp).min(),
            highlights: destinations.prefix(3).map { "replay destination: \($0)" },
            collectionNotes: ["Derived from replay fixture events"]
        )
    }

    private func buildNetworkRecords(from events: [AnalysisEvent]) -> [NetworkConnectionRecord] {
        events
            .filter { $0.category == .networkConnect || $0.action.contains("download") }
            .map { event in
                NetworkConnectionRecord(
                    timestamp: event.timestamp,
                    processName: event.processName ?? "replay",
                    processID: event.processID ?? 0,
                    destination: event.target,
                    destinationHost: nil,
                    destinationIP: nil,
                    port: "443",
                    protocolName: "tcp",
                    whetherRemote: true,
                    dnsDomain: nil,
                    sourceAddress: nil,
                    sourcePort: nil,
                    transportState: nil,
                    bytesSent: nil,
                    bytesReceived: nil
                )
            }
    }

    private func buildFileSystemDiff(from events: [AnalysisEvent]) -> FileSystemDiffResult? {
        let fileEvents = events.filter {
            $0.category == .fileCreated || $0.category == .fileModified || $0.category == .fileDeleted || $0.category == .persistenceAttempt
        }
        guard !fileEvents.isEmpty else {
            return nil
        }

        var added: [String] = []
        var modified: [String] = []
        var deleted: [String] = []
        var records: [FileSystemChangeRecord] = []

        for event in fileEvents {
            let lower = event.target.lowercased()
            let sensitive = lower.contains("launchagents") || lower.contains("launchdaemons") || lower.contains(".zshrc") || lower.contains(".bash_profile")

            let type: FileSystemChangeType
            switch event.category {
            case .fileCreated, .persistenceAttempt:
                type = .added
                added.append(event.target)
            case .fileModified:
                type = .modified
                modified.append(event.target)
            case .fileDeleted:
                type = .deleted
                deleted.append(event.target)
            default:
                type = .modified
            }

            records.append(
                FileSystemChangeRecord(
                    path: event.target,
                    changeType: type,
                    fileSize: nil,
                    modifiedTime: event.timestamp,
                    hash: nil,
                    whetherSensitivePath: sensitive,
                    detectedType: .unknown
                )
            )
        }

        return FileSystemDiffResult(
            added: added.uniquePreservingOrder(),
            modified: modified.uniquePreservingOrder(),
            deleted: deleted.uniquePreservingOrder(),
            records: records,
            isIncomplete: false,
            note: "Derived from replay fixture"
        )
    }

    private func buildHighRiskChains(from events: [AnalysisEvent]) -> [String] {
        let risky = events.filter { $0.riskScoreDelta > 0 }
        guard !risky.isEmpty else {
            return []
        }

        var chains: [String] = []
        let actions = risky.map(\.action)
        if actions.contains(where: { $0.contains("download") }) && actions.contains("launch_agent_write_simulated") {
            chains.append("download -> persistence")
        }
        if actions.contains("child_shell_spawned") && actions.contains(where: { $0.contains("download") }) {
            chains.append("script -> shell spawn -> download")
        }
        chains.append(contentsOf: risky.prefix(4).map { "\($0.action) -> \($0.target)" })
        return chains.uniquePreservingOrder()
    }
}

private struct ReplayFixture: Decodable {
    var sampleID: String?
    var replayOnly: Bool?
    var summary: String?
    var events: [ReplayEvent]

    enum CodingKeys: String, CodingKey {
        case sampleID = "sample_id"
        case replayOnly = "replay_only"
        case summary
        case events
    }
}

private struct ReplayEvent: Decodable {
    var timestamp: String?
    var category: String?
    var processID: Int?
    var parentProcessID: Int?
    var processName: String?
    var executablePath: String?
    var action: String?
    var target: String?
    var detailsText: String?
    var riskScoreDeltaHint: Int?
    var rawSource: String?

    var ts: String?
    var event: String?
    var path: String?
    var src: String?
    var dst: String?
    var value: String?
    var message: String?
    var reason: String?

    enum CodingKeys: String, CodingKey {
        case timestamp
        case category
        case processID
        case parentProcessID
        case processName
        case executablePath
        case action
        case target
        case details
        case riskScoreDeltaHint
        case rawSource
        case ts
        case event
        case path
        case src
        case dst
        case value
        case message
        case reason
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        timestamp = try container.decodeIfPresent(String.self, forKey: .timestamp)
        category = try container.decodeIfPresent(String.self, forKey: .category)
        processID = try container.decodeIfPresent(Int.self, forKey: .processID)
        parentProcessID = try container.decodeIfPresent(Int.self, forKey: .parentProcessID)
        processName = try container.decodeIfPresent(String.self, forKey: .processName)
        executablePath = try container.decodeIfPresent(String.self, forKey: .executablePath)
        action = try container.decodeIfPresent(String.self, forKey: .action)
        target = try container.decodeIfPresent(String.self, forKey: .target)
        detailsText = try container.decodeIfPresent(String.self, forKey: .details)
        riskScoreDeltaHint = try container.decodeIfPresent(Int.self, forKey: .riskScoreDeltaHint)
        rawSource = try container.decodeIfPresent(String.self, forKey: .rawSource)

        ts = try container.decodeIfPresent(String.self, forKey: .ts)
        event = try container.decodeIfPresent(String.self, forKey: .event)
        path = try container.decodeIfPresent(String.self, forKey: .path)
        src = try container.decodeIfPresent(String.self, forKey: .src)
        dst = try container.decodeIfPresent(String.self, forKey: .dst)
        value = try container.decodeIfPresent(String.self, forKey: .value)
        message = try container.decodeIfPresent(String.self, forKey: .message)
        reason = try container.decodeIfPresent(String.self, forKey: .reason)
    }

    var dictionaryValue: [String: String] {
        var valueMap: [String: String] = [:]
        if let category { valueMap["category"] = category }
        if let action { valueMap["action"] = action }
        if let target { valueMap["target"] = target }
        if let detailsText { valueMap["details"] = detailsText }
        if let path { valueMap["path"] = path }
        if let src { valueMap["src"] = src }
        if let dst { valueMap["dst"] = dst }
        if let value { valueMap["value"] = value }
        if let message { valueMap["message"] = message }
        if let reason { valueMap["reason"] = reason }
        if let processName { valueMap["processName"] = processName }
        if let executablePath { valueMap["executablePath"] = executablePath }
        if let processID { valueMap["processID"] = String(processID) }
        if let parentProcessID { valueMap["parentProcessID"] = String(parentProcessID) }
        return valueMap
    }
}
