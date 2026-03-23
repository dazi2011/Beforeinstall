import Foundation

enum FullDiskScanMode: String, Codable, CaseIterable, Identifiable, Sendable {
    case quick
    case deep

    var id: String { rawValue }

    func displayName(language: AppLanguage) -> String {
        switch (self, language) {
        case (.quick, .zhHans):
            return "快速扫描"
        case (.deep, .zhHans):
            return "深度扫描"
        case (.quick, .en):
            return "Quick Scan"
        case (.deep, .en):
            return "Deep Scan"
        }
    }
}

enum LocationCategory: String, Codable, CaseIterable, Sendable {
    case applications
    case userApplications
    case downloads
    case desktop
    case documents
    case launchAgents
    case launchDaemons
    case appSupport
    case preferences
    case scripts
    case caches
    case temporary
    case library
    case userHome
    case developer
    case brew
    case externalVolume
    case unknown
}

enum ThreatItemStatus: String, Codable, CaseIterable, Sendable {
    case active
    case quarantined
    case ignored
    case movedToTrash
    case deleted
    case failed
    case restored
}

enum RemediationActionType: String, Codable, CaseIterable, Sendable {
    case quarantine
    case moveToTrash
    case deletePermanently
    case disablePersistence
    case removeLaunchAgent
    case ignore
    case restoreFromQuarantine
}

enum RemediationActionStatus: String, Codable, CaseIterable, Sendable {
    case pending
    case running
    case succeeded
    case failed
    case cancelled
}

enum ThreatSortMode: String, Codable, CaseIterable, Identifiable, Sendable {
    case riskDescending
    case pathAscending
    case timeDescending
    case typeAscending

    var id: String { rawValue }
}

struct ScanScopePathRule: Codable, Hashable, Sendable {
    var prefix: String
    var action: ConfigRuleAction
    var sourceLine: Int
}

struct ScanScopePlan: Codable, Sendable {
    var mode: FullDiskScanMode
    var roots: [String]
    var excludedPathPrefixes: [String]
    var excludedDirectoryNames: [String]
    var excludedExtensions: [String]
    var prioritizedPathPrefixes: [String]
    var includeExternalVolumes: Bool
    var maxCandidates: Int
    var maxDepth: Int
    var maxFileSizeBytes: Int64
    var pathRules: [ScanScopePathRule]
}

struct DiscoveryCandidate: Identifiable, Sendable {
    var id: String { path }
    var path: String
    var displayName: String
    var detectedType: SupportedFileType
    var locationCategory: LocationCategory
    var isExecutable: Bool
    var isDirectory: Bool
    var size: Int64
    var lastModifiedAt: Date?
    var score: Int
    var reasons: [String]
    var escalateToFocusedAnalysis: Bool
    var sourceRoot: String
}

struct ScanSlowAnalysisRecord: Codable, Sendable {
    var path: String
    var displayName: String
    var detectedType: SupportedFileType
    var durationMs: Int
}

struct ScanPerformanceTrace: Codable, Sendable {
    var mode: FullDiskScanMode
    var totalEnumerated: Int
    var totalCandidates: Int
    var totalEscalated: Int
    var totalAnalyzed: Int
    var skippedByPruning: Int
    var skippedByType: Int
    var avgAnalysisDurationMs: Int
    var elapsedTimeMs: Int
    var directoryPruningStats: [String: Int]
    var candidateSelectionStats: [String: Int]
    var stageDurationsMs: [String: Int]
    var slowestAnalyses: [ScanSlowAnalysisRecord]
    var exportedTracePath: String?
}

struct ScanSummary: Codable, Sendable {
    var threatCount: Int
    var criticalCount: Int
    var highCount: Int
    var mediumCount: Int
    var lowCount: Int
    var infoCount: Int
    var persistenceCount: Int
    var quarantinedCount: Int
    var ignoredCount: Int
}

struct ScanSession: Codable, Identifiable, Sendable {
    var id = UUID()
    var sessionID: String
    var mode: FullDiskScanMode
    var startedAt: Date
    var completedAt: Date?
    var rootScopes: [String]
    var totalCandidates: Int
    var analyzedCount: Int
    var skippedCount: Int
    var failedCount: Int
    var summary: ScanSummary
    var threats: [ThreatRecord]
    var inaccessiblePaths: [String]
    var notes: [String]
    var performanceTrace: ScanPerformanceTrace?
}

struct ScanItem: Codable, Identifiable, Sendable {
    var itemID: String
    var path: String
    var displayName: String
    var fileType: SupportedFileType
    var detectedType: SupportedFileType
    var size: Int64
    var hash: String?
    var locationCategory: LocationCategory
    var isExecutable: Bool
    var isDirectorySample: Bool
    var sourceVolume: String
    var lastModifiedAt: Date?

    var id: String { itemID }
}

struct ThreatFinding: Codable, Identifiable, Sendable {
    var id: String { "\(ruleID)-\(title)-\(severity)-\(scoreDelta)" }
    var ruleID: String
    var title: String
    var severity: String
    var scoreDelta: Int
    var category: String
    var explanation: String
    var evidenceSnippet: String
    var technicalDetails: String
}

struct ThreatRecord: Codable, Identifiable, Sendable {
    var threatID: String
    var itemID: String
    var path: String
    var displayName: String
    var detectedType: SupportedFileType
    var score: Int
    var verdict: ScanVerdict
    var riskLevel: RiskLevel
    var summary: String
    var findings: [ThreatFinding]
    var persistenceIndicators: [String]
    var networkIndicators: [String]
    var cleanupRecommendations: [String]
    var canQuarantine: Bool
    var canDelete: Bool
    var canIgnore: Bool
    var canDisablePersistence: Bool
    var isSystemSensitive: Bool
    var requiresExtraConfirmation: Bool
    var status: ThreatItemStatus
    var lastUpdatedAt: Date
    var firstSeenAt: Date

    var id: String { threatID }
}

struct RemediationAction: Codable, Identifiable, Sendable {
    var actionID: String
    var threatID: String
    var actionType: RemediationActionType
    var requiresConfirmation: Bool
    var requiresAdmin: Bool
    var reversible: Bool
    var status: RemediationActionStatus
    var resultMessage: String
    var timestamp: Date

    var id: String { actionID }
}

struct QuarantineRecord: Codable, Identifiable, Sendable {
    var quarantineID: String
    var originalPath: String
    var quarantinePath: String
    var timestamp: Date
    var reason: String
    var originalMetadata: [String: String]
    var hash: String?
    var canRestore: Bool

    var id: String { quarantineID }
}

struct IgnoreRuleRecord: Codable, Identifiable, Sendable {
    var id = UUID()
    var path: String?
    var hash: String?
    var bundleIdentifier: String?
    var ruleID: String?
    var createdAt: Date
}

struct RemediationLogEntry: Codable, Identifiable, Sendable {
    var id = UUID()
    var sessionID: String
    var threatID: String
    var path: String
    var actionType: RemediationActionType
    var status: RemediationActionStatus
    var message: String
    var timestamp: Date
}

struct ThreatFilterState: Codable, Sendable {
    var riskLevels: Set<RiskLevel> = []
    var verdicts: Set<ScanVerdict> = []
    var types: Set<SupportedFileType> = []
    var locations: Set<LocationCategory> = []
    var onlyRemediable: Bool = false
    var onlyPersistenceRelated: Bool = false
    var onlyUnsignedExecutable: Bool = false
}
