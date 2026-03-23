import Foundation

enum DynamicStatus: String, Codable, Sendable {
    case notRequested
    case skipped
    case completed
    case failed
    case partial
    case interrupted
    case noObservableActivity
}

enum AnalysisEventCategory: String, Codable, CaseIterable, Sendable {
    case processCreated
    case processExited
    case fileCreated
    case fileModified
    case fileDeleted
    case networkConnect
    case persistenceAttempt
    case scriptExecuted
    case privilegeRelatedAction
    case unknown
}

struct AnalysisEvent: Codable, Identifiable, Sendable {
    var id: String
    var timestamp: Date
    var category: AnalysisEventCategory
    var processID: Int?
    var parentProcessID: Int?
    var processName: String?
    var executablePath: String?
    var action: String
    var target: String
    var details: [String: String]
    var riskScoreDelta: Int
    var rawSource: String

    init(
        id: String = UUID().uuidString,
        timestamp: Date = Date(),
        category: AnalysisEventCategory,
        processID: Int? = nil,
        parentProcessID: Int? = nil,
        processName: String? = nil,
        executablePath: String? = nil,
        action: String,
        target: String,
        details: [String: String] = [:],
        riskScoreDelta: Int = 0,
        rawSource: String
    ) {
        self.id = id
        self.timestamp = timestamp
        self.category = category
        self.processID = processID
        self.parentProcessID = parentProcessID
        self.processName = processName
        self.executablePath = executablePath
        self.action = action
        self.target = target
        self.details = details
        self.riskScoreDelta = riskScoreDelta
        self.rawSource = rawSource
    }
}

struct DynamicAnalysisSession: Codable, Sendable {
    var sessionID: String
    var samplePath: String
    var startTime: Date
    var endTime: Date?
    var events: [AnalysisEvent]
    // Collection boundaries are explicit so users can understand current visibility limits.
    var collectionBoundaries: [String]
    // Fallback sources explain where the evidence came from under restricted permissions.
    var fallbackSources: [String]

    var highRiskEvents: [AnalysisEvent] {
        events
            .filter { $0.riskScoreDelta > 0 }
            .sorted { lhs, rhs in
                if lhs.riskScoreDelta == rhs.riskScoreDelta {
                    return lhs.timestamp < rhs.timestamp
                }
                return lhs.riskScoreDelta > rhs.riskScoreDelta
            }
    }
}

struct DynamicRunOverview: Codable, Sendable {
    var status: DynamicStatus
    var launchSucceeded: Bool
    var durationSeconds: Int
    var actualDuration: TimeInterval
    var crashed: Bool
    var mainProcessID: Int?
    var hasChildProcesses: Bool
    var hasNetworkActivity: Bool
    var hasFileWriteActivity: Bool
    var hasPersistenceAttempt: Bool
}

struct ProcessObservation: Codable, Identifiable, Sendable {
    var id = UUID()
    var pid: Int
    var ppid: Int
    var command: String
    var arguments: String
    var executablePath: String?
    var firstSeenAt: Date
    var exitStatus: Int32?
}

struct FileObservation: Codable, Identifiable, Sendable {
    var id = UUID()
    var path: String
    var operation: String
    var isSensitivePath: Bool
    var observedAt: Date?
}

struct NetworkObservation: Codable, Identifiable, Sendable {
    var id = UUID()
    var endpoint: String
    var port: String
    var proto: String
    var count: Int
    var firstSeenAt: Date?
    var lastSeenAt: Date?
}

enum FileSystemChangeType: String, Codable, CaseIterable, Sendable {
    case added
    case modified
    case deleted
}

struct FileSystemChangeRecord: Codable, Identifiable, Sendable {
    var id = UUID()
    var path: String
    var changeType: FileSystemChangeType
    var fileSize: Int64?
    var modifiedTime: Date?
    var hash: String?
    var whetherSensitivePath: Bool
    var detectedType: SupportedFileType
}

struct NetworkConnectionRecord: Codable, Identifiable, Sendable {
    var id = UUID()
    var timestamp: Date
    var processName: String
    var processID: Int
    var destination: String
    var destinationHost: String?
    var destinationIP: String?
    var port: String
    var protocolName: String
    var whetherRemote: Bool
    var dnsDomain: String?
    // Reserved fields for future lower-layer collectors (BPF/endpoint security).
    var sourceAddress: String?
    var sourcePort: String?
    var transportState: String?
    var bytesSent: Int64?
    var bytesReceived: Int64?
}

struct NetworkSummary: Codable, Sendable {
    var totalConnections: Int
    var remoteConnections: Int
    var uniqueDestinations: [String]
    var uniqueRemoteIPs: [String]
    var firstConnectionAt: Date?
    var highlights: [String]
    var collectionNotes: [String]
}

struct FileSystemDiffResult: Codable, Sendable {
    var added: [String]
    var modified: [String]
    var deleted: [String]
    var records: [FileSystemChangeRecord]
    var isIncomplete: Bool
    var note: String?

    enum CodingKeys: String, CodingKey {
        case added
        case modified
        case deleted
        case created
        case records
        case isIncomplete
        case note
    }

    init(
        added: [String],
        modified: [String],
        deleted: [String],
        records: [FileSystemChangeRecord],
        isIncomplete: Bool,
        note: String?
    ) {
        self.added = added
        self.modified = modified
        self.deleted = deleted
        self.records = records
        self.isIncomplete = isIncomplete
        self.note = note
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedAdded = try container.decodeIfPresent([String].self, forKey: .added)
        let legacyCreated = try container.decodeIfPresent([String].self, forKey: .created)
        added = decodedAdded ?? legacyCreated ?? []
        modified = try container.decodeIfPresent([String].self, forKey: .modified) ?? []
        deleted = try container.decodeIfPresent([String].self, forKey: .deleted) ?? []
        records = try container.decodeIfPresent([FileSystemChangeRecord].self, forKey: .records) ?? []
        isIncomplete = try container.decodeIfPresent(Bool.self, forKey: .isIncomplete) ?? false
        note = try container.decodeIfPresent(String.self, forKey: .note)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(added, forKey: .added)
        try container.encode(added, forKey: .created)
        try container.encode(modified, forKey: .modified)
        try container.encode(deleted, forKey: .deleted)
        try container.encode(records, forKey: .records)
        try container.encode(isIncomplete, forKey: .isIncomplete)
        try container.encodeIfPresent(note, forKey: .note)
    }

    var addedRecords: [FileSystemChangeRecord] {
        records.filter { $0.changeType == .added }
    }

    var modifiedRecords: [FileSystemChangeRecord] {
        records.filter { $0.changeType == .modified }
    }

    var deletedRecords: [FileSystemChangeRecord] {
        records.filter { $0.changeType == .deleted }
    }
}

struct ProcessNode: Codable, Identifiable, Sendable {
    var id = UUID()
    var pid: Int
    var ppid: Int
    var command: String
    var executablePath: String?
    var firstSeenAt: Date?
    var children: [ProcessNode]
}

struct BackgroundLaunchOptions: Codable, Sendable {
    var preferNonActivatingLaunch: Bool
    var attemptHideAfterLaunch: Bool
    var allowForegroundFallback: Bool

    static let `default` = BackgroundLaunchOptions(
        preferNonActivatingLaunch: true,
        attemptHideAfterLaunch: true,
        allowForegroundFallback: false
    )
}

struct DynamicLaunchResult: Codable, Sendable {
    var launchMode: String
    var launchSucceeded: Bool
    var hideAttempted: Bool
    var hideSucceeded: Bool?
    var appLikelyActivatedForeground: Bool?
    var appLikelyDisplayedWindow: Bool?
    var interactionRequired: Bool
    var notes: [String]
    var runningApplicationPID: Int?
}

enum BehaviorEventType: String, Codable, Sendable {
    case analysisStarted
    case launchAttempted
    case launchFailed
    case appLaunchStarted
    case appLaunchSucceeded
    case appHideAttempted
    case appHideSucceeded
    case appHideFailed
    case appLikelyActivatedForeground
    case appLikelyDisplayedWindow
    case interactionRequired
    case processStarted
    case childProcessDiscovered
    case helperOrShellDiscovered
    case fileCreated
    case fileModified
    case fileDeleted
    case sensitivePathTouched
    case networkConnection
    case analysisFinished
    case interrupted
    case crashed
    case warning
}

struct BehaviorEvent: Codable, Identifiable, Sendable {
    var id = UUID()
    var timestamp: Date
    var type: BehaviorEventType
    var target: String
    var summary: String
    var isRiskHighlighted: Bool
}

struct DynamicAnalysisReport: Codable, Sendable {
    var overview: DynamicRunOverview
    var workspacePath: String?
    var limitationNotes: [String]
    var dynamicResults: DynamicAnalysisSession?
    var sessionLogs: [String]
    var launchResult: DynamicLaunchResult?
    var processObservations: [ProcessObservation]
    var fileObservations: [FileObservation]
    var networkObservations: [NetworkObservation]
    var networkRecords: [NetworkConnectionRecord]
    var networkSummary: NetworkSummary?
    var fileSystemDiff: FileSystemDiffResult?
    var processTreeRoots: [ProcessNode]
    var behaviorTimeline: [BehaviorEvent]
    var highRiskChains: [String]
    var suspiciousIndicators: [String]
    var summaryLines: [String]
    var warnings: [String]
    var failureIssues: [FailureIssue]

    static func skipped(duration: Int, reason: String) -> DynamicAnalysisReport {
        DynamicAnalysisReport(
            overview: DynamicRunOverview(
                status: .skipped,
                launchSucceeded: false,
                durationSeconds: duration,
                actualDuration: 0,
                crashed: false,
                mainProcessID: nil,
                hasChildProcesses: false,
                hasNetworkActivity: false,
                hasFileWriteActivity: false,
                hasPersistenceAttempt: false
            ),
            workspacePath: nil,
            limitationNotes: [
                "Dynamic analysis in this version is a restricted observation mode, not a full malware sandbox.",
                reason
            ],
            dynamicResults: nil,
            sessionLogs: [],
            launchResult: nil,
            processObservations: [],
            fileObservations: [],
            networkObservations: [],
            networkRecords: [],
            networkSummary: nil,
            fileSystemDiff: nil,
            processTreeRoots: [],
            behaviorTimeline: [],
            highRiskChains: [],
            suspiciousIndicators: [],
            summaryLines: [reason],
            warnings: [reason],
            failureIssues: []
        )
    }
}

extension DynamicAnalysisReport {
    enum CodingKeys: String, CodingKey {
        case overview
        case workspacePath
        case limitationNotes
        case dynamicResults
        case sessionLogs
        case launchResult
        case processObservations
        case fileObservations
        case networkObservations
        case networkRecords
        case networkSummary
        case fileSystemDiff
        case processTreeRoots
        case behaviorTimeline
        case highRiskChains
        case suspiciousIndicators
        case summaryLines
        case warnings
        case failureIssues
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        overview = try container.decode(DynamicRunOverview.self, forKey: .overview)
        workspacePath = try container.decodeIfPresent(String.self, forKey: .workspacePath)
        limitationNotes = try container.decodeIfPresent([String].self, forKey: .limitationNotes) ?? []
        dynamicResults = try container.decodeIfPresent(DynamicAnalysisSession.self, forKey: .dynamicResults)
        sessionLogs = try container.decodeIfPresent([String].self, forKey: .sessionLogs) ?? []
        launchResult = try container.decodeIfPresent(DynamicLaunchResult.self, forKey: .launchResult)
        processObservations = try container.decodeIfPresent([ProcessObservation].self, forKey: .processObservations) ?? []
        fileObservations = try container.decodeIfPresent([FileObservation].self, forKey: .fileObservations) ?? []
        networkObservations = try container.decodeIfPresent([NetworkObservation].self, forKey: .networkObservations) ?? []
        networkRecords = try container.decodeIfPresent([NetworkConnectionRecord].self, forKey: .networkRecords) ?? []
        networkSummary = try container.decodeIfPresent(NetworkSummary.self, forKey: .networkSummary)
        fileSystemDiff = try container.decodeIfPresent(FileSystemDiffResult.self, forKey: .fileSystemDiff)
        processTreeRoots = try container.decodeIfPresent([ProcessNode].self, forKey: .processTreeRoots) ?? []
        behaviorTimeline = try container.decodeIfPresent([BehaviorEvent].self, forKey: .behaviorTimeline) ?? []
        highRiskChains = try container.decodeIfPresent([String].self, forKey: .highRiskChains) ?? []
        suspiciousIndicators = try container.decodeIfPresent([String].self, forKey: .suspiciousIndicators) ?? []
        summaryLines = try container.decodeIfPresent([String].self, forKey: .summaryLines) ?? []
        warnings = try container.decodeIfPresent([String].self, forKey: .warnings) ?? []
        failureIssues = try container.decodeIfPresent([FailureIssue].self, forKey: .failureIssues) ?? []
    }
}

struct RuntimeLaunchResult: Sendable {
    var launchSucceeded: Bool
    var mainPID: Int?
    var terminationStatus: Int32?
    var terminationReason: String?
    var warning: String?
}

struct RuntimeLaunchContext {
    var result: RuntimeLaunchResult
    var process: Process?
    var launchResult: DynamicLaunchResult?
}

struct DynamicProgressEvent: Sendable {
    var message: String
    var timestamp: Date
}

struct ProcessTreeBuilder {
    func build(
        rootProcessID: Int?,
        events: [AnalysisEvent],
        processObservations: [ProcessObservation]
    ) -> [ProcessNode] {
        struct NodeSeed {
            var pid: Int
            var ppid: Int
            var command: String
            var executablePath: String?
            var firstSeenAt: Date?
        }

        var seeds: [Int: NodeSeed] = [:]

        for event in events {
            guard let pid = event.processID else { continue }
            let ppid = event.parentProcessID ?? seeds[pid]?.ppid ?? -1
            let command = event.processName ?? seeds[pid]?.command ?? "pid_\(pid)"
            let firstSeen = minDate(seeds[pid]?.firstSeenAt, event.timestamp)

            seeds[pid] = NodeSeed(
                pid: pid,
                ppid: ppid,
                command: command,
                executablePath: event.executablePath ?? seeds[pid]?.executablePath,
                firstSeenAt: firstSeen
            )
        }

        for process in processObservations {
            let firstSeen = minDate(seeds[process.pid]?.firstSeenAt, process.firstSeenAt)
            seeds[process.pid] = NodeSeed(
                pid: process.pid,
                ppid: process.ppid,
                command: process.command,
                executablePath: process.executablePath ?? seeds[process.pid]?.executablePath,
                firstSeenAt: firstSeen
            )
        }

        guard !seeds.isEmpty else { return [] }

        let groupedChildren = Dictionary(grouping: seeds.values, by: { $0.ppid })
        var building = Set<Int>()

        func makeNode(pid: Int) -> ProcessNode {
            let fallback = NodeSeed(pid: pid, ppid: -1, command: "pid_\(pid)", executablePath: nil, firstSeenAt: nil)
            let seed = seeds[pid] ?? fallback

            if building.contains(pid) {
                return ProcessNode(
                    pid: pid,
                    ppid: seed.ppid,
                    command: seed.command,
                    executablePath: seed.executablePath,
                    firstSeenAt: seed.firstSeenAt,
                    children: []
                )
            }

            building.insert(pid)
            let childrenSeeds = groupedChildren[pid] ?? []
            let children = childrenSeeds
                .map { makeNode(pid: $0.pid) }
                .sorted { $0.pid < $1.pid }
            building.remove(pid)

            return ProcessNode(
                pid: seed.pid,
                ppid: seed.ppid,
                command: seed.command,
                executablePath: seed.executablePath,
                firstSeenAt: seed.firstSeenAt,
                children: children
            )
        }

        var rootPIDs: [Int] = []
        if let rootProcessID, seeds[rootProcessID] != nil {
            rootPIDs.append(rootProcessID)
        }

        let derivedRoots = seeds.values
            .filter { seed in
                seed.ppid <= 0 || seeds[seed.ppid] == nil
            }
            .map(\.pid)
            .sorted()

        rootPIDs.append(contentsOf: derivedRoots)
        rootPIDs = rootPIDs.uniquePreservingOrder()

        return rootPIDs.map { makeNode(pid: $0) }
    }

    private func minDate(_ lhs: Date?, _ rhs: Date?) -> Date? {
        switch (lhs, rhs) {
        case let (l?, r?):
            return min(l, r)
        case let (l?, nil):
            return l
        case let (nil, r?):
            return r
        default:
            return nil
        }
    }
}

struct TimelineBuilder {
    func build(events: [AnalysisEvent], categories: Set<AnalysisEventCategory>? = nil) -> [AnalysisEvent] {
        let filtered = categories.map { allow in
            events.filter { allow.contains($0.category) }
        } ?? events
        return filtered.sorted { $0.timestamp < $1.timestamp }
    }

    func buildLegacyTimeline(events: [AnalysisEvent]) -> [BehaviorEvent] {
        build(events: events).map { event in
            BehaviorEvent(
                timestamp: event.timestamp,
                type: mapLegacyType(event.category),
                target: event.target,
                summary: legacySummary(for: event),
                isRiskHighlighted: event.riskScoreDelta > 0
            )
        }
    }

    private func mapLegacyType(_ category: AnalysisEventCategory) -> BehaviorEventType {
        switch category {
        case .processCreated:
            return .childProcessDiscovered
        case .processExited:
            return .analysisFinished
        case .fileCreated:
            return .fileCreated
        case .fileModified:
            return .fileModified
        case .fileDeleted:
            return .fileDeleted
        case .networkConnect:
            return .networkConnection
        case .persistenceAttempt:
            return .sensitivePathTouched
        case .scriptExecuted:
            return .helperOrShellDiscovered
        case .privilegeRelatedAction:
            return .warning
        case .unknown:
            return .warning
        }
    }

    private func legacySummary(for event: AnalysisEvent) -> String {
        if event.details.isEmpty {
            return event.action
        }
        let details = event.details
            .sorted(by: { $0.key < $1.key })
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: ", ")
        return "\(event.action) (\(details))"
    }
}
