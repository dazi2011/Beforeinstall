import Foundation

enum BenchmarkSampleSourceKind: String, Codable, Sendable {
    case file
    case replayJSON
}

enum BenchmarkSampleExecutionStatus: String, Codable, Sendable {
    case pending
    case completed
    case failed
}

enum BenchmarkMismatchReason: String, Codable, Sendable {
    case verdictTooHigh = "verdict_too_high"
    case verdictTooLow = "verdict_too_low"
    case scoreTooHigh = "score_too_high"
    case scoreTooLow = "score_too_low"
    case analysisFailed = "analysis_failed"
    case expectationMissing = "expectation_missing"
}

enum BenchmarkRunnerErrorCode: String, Codable, Sendable {
    case replayFileNotFound = "replay_file_not_found"
    case replayReadFailed = "replay_read_failed"
    case replayDecodeFailed = "replay_decode_failed"
    case replayEventMappingFailed = "replay_event_mapping_failed"
    case analysisFailed = "analysis_failed"
}

struct BenchmarkFindingDelta: Codable, Sendable {
    var ruleID: String
    var severity: String?
    var scoreDelta: Int
    var category: String?
    var explanation: String?
}

struct BenchmarkScoringTraceEntry: Codable, Identifiable, Sendable {
    var id = UUID()
    var sampleID: String
    var detectedType: String? = nil
    var typeScorerUsed: String? = nil
    var baseScore: Int
    var findingDeltas: [BenchmarkFindingDelta]
    var contextAdjustments: [ScoreAdjustmentTrace]? = nil
    var chainBonuses: [ScoreAdjustmentTrace]? = nil
    var scoreCapsApplied: [ScoreCapTrace]? = nil
    var finalScore: Int
    var verdict: String
    var thresholdUsed: String
    var notes: [String]
}

struct BenchmarkFindingsTraceEntry: Codable, Identifiable, Sendable {
    var id = UUID()
    var sampleID: String
    var detectedType: String
    var findings: [StaticFinding]
}

struct BenchmarkScoreCapTraceEntry: Codable, Identifiable, Sendable {
    var id = UUID()
    var sampleID: String
    var detectedType: String
    var caps: [ScoreCapTrace]
}

struct BenchmarkContextTraceEntry: Codable, Identifiable, Sendable {
    var id = UUID()
    var sampleID: String
    var detectedType: String
    var adjustments: [ScoreAdjustmentTrace]
}

struct BenchmarkReplayDebugRecord: Codable, Identifiable, Sendable {
    var id = UUID()
    var sampleID: String
    var relativePath: String
    var resolvedAbsolutePath: String
    var fileExists: Bool
    var fileSizeBytes: Int64?
    var readSucceeded: Bool
    var decodeSucceeded: Bool
    var eventCount: Int?
    var mappingSucceeded: Bool
    var errorCode: BenchmarkRunnerErrorCode?
    var finalError: String?
}

struct BenchmarkDiscoveredSampleRecord: Codable, Sendable {
    var sampleID: String
    var relativePath: String
    var absolutePath: String
    var group: String
    var subtype: String
    var fixtureKind: String?
    var metadataPath: String?
    var isReplay: Bool
    var isDirectorySample: Bool
}

struct BenchmarkScoreRange: Codable, Sendable {
    var min: Int
    var max: Int

    init(min: Int, max: Int) {
        self.min = Swift.min(min, max)
        self.max = Swift.max(min, max)
    }

    init?(array: [Int]) {
        guard array.count == 2 else {
            return nil
        }
        self.min = Swift.min(array[0], array[1])
        self.max = Swift.max(array[0], array[1])
    }

    func contains(score: Int) -> Bool {
        score >= min && score <= max
    }

    var asArray: [Int] {
        [min, max]
    }
}

struct BenchmarkExpectation: Codable, Sendable {
    var expectedVerdict: String?
    var expectedScoreRange: BenchmarkScoreRange?
}

struct BenchmarkSample: Codable, Identifiable, Sendable {
    var sampleID: String
    var absolutePath: String
    var relativePath: String
    var group: String
    var subtype: String
    var fixtureKind: String?
    var metadataPath: String?
    var expectation: BenchmarkExpectation?
    var sourceKind: BenchmarkSampleSourceKind
    var isDirectorySample: Bool

    var id: String { sampleID }

    enum CodingKeys: String, CodingKey {
        case sampleID
        case absolutePath
        case relativePath
        case group
        case subtype
        case fixtureKind
        case metadataPath
        case expectation
        case sourceKind
        case isDirectorySample
    }

    init(
        sampleID: String,
        absolutePath: String,
        relativePath: String,
        group: String,
        subtype: String,
        fixtureKind: String?,
        metadataPath: String?,
        expectation: BenchmarkExpectation?,
        sourceKind: BenchmarkSampleSourceKind,
        isDirectorySample: Bool
    ) {
        self.sampleID = sampleID
        self.absolutePath = absolutePath
        self.relativePath = relativePath
        self.group = group
        self.subtype = subtype
        self.fixtureKind = fixtureKind
        self.metadataPath = metadataPath
        self.expectation = expectation
        self.sourceKind = sourceKind
        self.isDirectorySample = isDirectorySample
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sampleID = try container.decode(String.self, forKey: .sampleID)
        absolutePath = try container.decode(String.self, forKey: .absolutePath)
        relativePath = try container.decode(String.self, forKey: .relativePath)
        group = try container.decode(String.self, forKey: .group)
        subtype = try container.decode(String.self, forKey: .subtype)
        fixtureKind = try container.decodeIfPresent(String.self, forKey: .fixtureKind)
        metadataPath = try container.decodeIfPresent(String.self, forKey: .metadataPath)
        expectation = try container.decodeIfPresent(BenchmarkExpectation.self, forKey: .expectation)
        sourceKind = try container.decodeIfPresent(BenchmarkSampleSourceKind.self, forKey: .sourceKind) ?? .file
        isDirectorySample = try container.decodeIfPresent(Bool.self, forKey: .isDirectorySample) ?? false
    }
}

struct BenchmarkSampleResult: Codable, Identifiable, Sendable {
    var sampleID: String
    var path: String
    var group: String
    var subtype: String?
    var fixtureKind: String?
    var detectedType: String
    var score: Int
    var verdict: String
    var findings: [String]
    var findingDeltas: [BenchmarkFindingDelta]?
    var analysisSummary: String?
    var expectedVerdict: String?
    var expectedScoreRange: BenchmarkScoreRange?
    var matchedVerdict: Bool?
    var matchedScoreRange: Bool?
    var mismatchReason: BenchmarkMismatchReason?
    var analysisDurationMs: Int
    var timestamp: Date
    var status: BenchmarkSampleExecutionStatus
    var errorMessage: String?
    var errorCode: BenchmarkRunnerErrorCode?

    var id: String { sampleID }
}

struct BenchmarkGroupSummary: Codable, Sendable {
    var total: Int
    var analyzed: Int
    var failed: Int
    var avgScore: Double
    var clean: Int
    var suspicious: Int
    var malicious: Int
    var unknown: Int

    enum CodingKeys: String, CodingKey {
        case total
        case analyzed
        case failed
        case avgScore
        case clean
        case suspicious
        case malicious
        case unknown
    }

    enum LegacyCodingKeys: String, CodingKey {
        case completed
    }

    init(
        total: Int,
        analyzed: Int,
        failed: Int,
        avgScore: Double,
        clean: Int,
        suspicious: Int,
        malicious: Int,
        unknown: Int
    ) {
        self.total = total
        self.analyzed = analyzed
        self.failed = failed
        self.avgScore = avgScore
        self.clean = clean
        self.suspicious = suspicious
        self.malicious = malicious
        self.unknown = unknown
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let legacyContainer = try decoder.container(keyedBy: LegacyCodingKeys.self)
        total = try container.decodeIfPresent(Int.self, forKey: .total) ?? 0
        analyzed = try container.decodeIfPresent(Int.self, forKey: .analyzed)
            ?? (try legacyContainer.decodeIfPresent(Int.self, forKey: .completed))
            ?? 0
        failed = try container.decodeIfPresent(Int.self, forKey: .failed) ?? 0
        avgScore = try container.decodeIfPresent(Double.self, forKey: .avgScore) ?? 0
        clean = try container.decodeIfPresent(Int.self, forKey: .clean) ?? 0
        suspicious = try container.decodeIfPresent(Int.self, forKey: .suspicious) ?? 0
        malicious = try container.decodeIfPresent(Int.self, forKey: .malicious) ?? 0
        unknown = try container.decodeIfPresent(Int.self, forKey: .unknown) ?? 0
    }
}

struct BenchmarkSummary: Codable, Sendable {
    var totalSamples: Int
    var analyzedSamples: Int
    var failedSamples: Int
    var effectiveCoverageRate: Double
    var averageScore: Double
    var medianScore: Double

    var cleanCount: Int
    var suspiciousCount: Int
    var maliciousCount: Int
    var unknownCount: Int

    var falsePositiveCount: Int
    var falseNegativeCount: Int
    var falsePositiveRate: Double
    var falseNegativeRate: Double

    var verdictAccuracy: Double
    var scoreRangeMatchRate: Double

    var cleanFalsePositiveRate: Double
    var noisyBenignFalsePositiveRate: Double
    var suspiciousHitRate: Double
    var replayMaliciousDetectionRate: Double
    var replayMaliciousTotal: Int
    var replayMaliciousAnalyzed: Int
    var replayMaliciousFailed: Int
    var replayMaliciousDetected: Int
    var groupAnalyzedRatio: [String: Double]

    var groupStats: [String: BenchmarkGroupSummary]
    var confusionMatrix: [String: [String: Int]]
    var mismatchBreakdown: [String: Int]

    var scoreMonotonicityHints: [String]
    var isScoreMonotonic: Bool

    enum CodingKeys: String, CodingKey {
        case totalSamples
        case analyzedSamples
        case failedSamples
        case effectiveCoverageRate
        case averageScore
        case medianScore
        case cleanCount
        case suspiciousCount
        case maliciousCount
        case unknownCount
        case falsePositiveCount
        case falseNegativeCount
        case falsePositiveRate
        case falseNegativeRate
        case verdictAccuracy
        case scoreRangeMatchRate
        case cleanFalsePositiveRate
        case noisyBenignFalsePositiveRate
        case suspiciousHitRate
        case replayMaliciousDetectionRate
        case replayMaliciousTotal
        case replayMaliciousAnalyzed
        case replayMaliciousFailed
        case replayMaliciousDetected
        case groupAnalyzedRatio
        case groupStats
        case confusionMatrix
        case mismatchBreakdown
        case scoreMonotonicityHints
        case isScoreMonotonic
    }

    enum LegacyCodingKeys: String, CodingKey {
        case completedSamples
    }

    init(
        totalSamples: Int,
        analyzedSamples: Int,
        failedSamples: Int,
        effectiveCoverageRate: Double,
        averageScore: Double,
        medianScore: Double,
        cleanCount: Int,
        suspiciousCount: Int,
        maliciousCount: Int,
        unknownCount: Int,
        falsePositiveCount: Int,
        falseNegativeCount: Int,
        falsePositiveRate: Double,
        falseNegativeRate: Double,
        verdictAccuracy: Double,
        scoreRangeMatchRate: Double,
        cleanFalsePositiveRate: Double,
        noisyBenignFalsePositiveRate: Double,
        suspiciousHitRate: Double,
        replayMaliciousDetectionRate: Double,
        replayMaliciousTotal: Int,
        replayMaliciousAnalyzed: Int,
        replayMaliciousFailed: Int,
        replayMaliciousDetected: Int,
        groupAnalyzedRatio: [String: Double],
        groupStats: [String: BenchmarkGroupSummary],
        confusionMatrix: [String: [String: Int]],
        mismatchBreakdown: [String: Int],
        scoreMonotonicityHints: [String],
        isScoreMonotonic: Bool
    ) {
        self.totalSamples = totalSamples
        self.analyzedSamples = analyzedSamples
        self.failedSamples = failedSamples
        self.effectiveCoverageRate = effectiveCoverageRate
        self.averageScore = averageScore
        self.medianScore = medianScore
        self.cleanCount = cleanCount
        self.suspiciousCount = suspiciousCount
        self.maliciousCount = maliciousCount
        self.unknownCount = unknownCount
        self.falsePositiveCount = falsePositiveCount
        self.falseNegativeCount = falseNegativeCount
        self.falsePositiveRate = falsePositiveRate
        self.falseNegativeRate = falseNegativeRate
        self.verdictAccuracy = verdictAccuracy
        self.scoreRangeMatchRate = scoreRangeMatchRate
        self.cleanFalsePositiveRate = cleanFalsePositiveRate
        self.noisyBenignFalsePositiveRate = noisyBenignFalsePositiveRate
        self.suspiciousHitRate = suspiciousHitRate
        self.replayMaliciousDetectionRate = replayMaliciousDetectionRate
        self.replayMaliciousTotal = replayMaliciousTotal
        self.replayMaliciousAnalyzed = replayMaliciousAnalyzed
        self.replayMaliciousFailed = replayMaliciousFailed
        self.replayMaliciousDetected = replayMaliciousDetected
        self.groupAnalyzedRatio = groupAnalyzedRatio
        self.groupStats = groupStats
        self.confusionMatrix = confusionMatrix
        self.mismatchBreakdown = mismatchBreakdown
        self.scoreMonotonicityHints = scoreMonotonicityHints
        self.isScoreMonotonic = isScoreMonotonic
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let legacyContainer = try decoder.container(keyedBy: LegacyCodingKeys.self)
        totalSamples = try container.decodeIfPresent(Int.self, forKey: .totalSamples) ?? 0
        analyzedSamples = try container.decodeIfPresent(Int.self, forKey: .analyzedSamples)
            ?? (try legacyContainer.decodeIfPresent(Int.self, forKey: .completedSamples))
            ?? 0
        failedSamples = try container.decodeIfPresent(Int.self, forKey: .failedSamples) ?? 0
        effectiveCoverageRate = try container.decodeIfPresent(Double.self, forKey: .effectiveCoverageRate)
            ?? (totalSamples == 0 ? 0 : Double(analyzedSamples) / Double(totalSamples))
        averageScore = try container.decodeIfPresent(Double.self, forKey: .averageScore) ?? 0
        medianScore = try container.decodeIfPresent(Double.self, forKey: .medianScore) ?? 0
        cleanCount = try container.decodeIfPresent(Int.self, forKey: .cleanCount) ?? 0
        suspiciousCount = try container.decodeIfPresent(Int.self, forKey: .suspiciousCount) ?? 0
        maliciousCount = try container.decodeIfPresent(Int.self, forKey: .maliciousCount) ?? 0
        unknownCount = try container.decodeIfPresent(Int.self, forKey: .unknownCount) ?? 0
        falsePositiveCount = try container.decodeIfPresent(Int.self, forKey: .falsePositiveCount) ?? 0
        falseNegativeCount = try container.decodeIfPresent(Int.self, forKey: .falseNegativeCount) ?? 0
        falsePositiveRate = try container.decodeIfPresent(Double.self, forKey: .falsePositiveRate) ?? 0
        falseNegativeRate = try container.decodeIfPresent(Double.self, forKey: .falseNegativeRate) ?? 0
        verdictAccuracy = try container.decodeIfPresent(Double.self, forKey: .verdictAccuracy) ?? 0
        scoreRangeMatchRate = try container.decodeIfPresent(Double.self, forKey: .scoreRangeMatchRate) ?? 0
        cleanFalsePositiveRate = try container.decodeIfPresent(Double.self, forKey: .cleanFalsePositiveRate) ?? 0
        noisyBenignFalsePositiveRate = try container.decodeIfPresent(Double.self, forKey: .noisyBenignFalsePositiveRate) ?? 0
        suspiciousHitRate = try container.decodeIfPresent(Double.self, forKey: .suspiciousHitRate) ?? 0
        replayMaliciousDetectionRate = try container.decodeIfPresent(Double.self, forKey: .replayMaliciousDetectionRate) ?? 0
        replayMaliciousTotal = try container.decodeIfPresent(Int.self, forKey: .replayMaliciousTotal) ?? 0
        replayMaliciousAnalyzed = try container.decodeIfPresent(Int.self, forKey: .replayMaliciousAnalyzed) ?? 0
        replayMaliciousFailed = try container.decodeIfPresent(Int.self, forKey: .replayMaliciousFailed) ?? 0
        replayMaliciousDetected = try container.decodeIfPresent(Int.self, forKey: .replayMaliciousDetected) ?? 0
        groupAnalyzedRatio = try container.decodeIfPresent([String: Double].self, forKey: .groupAnalyzedRatio) ?? [:]
        groupStats = try container.decodeIfPresent([String: BenchmarkGroupSummary].self, forKey: .groupStats) ?? [:]
        confusionMatrix = try container.decodeIfPresent([String: [String: Int]].self, forKey: .confusionMatrix) ?? [:]
        mismatchBreakdown = try container.decodeIfPresent([String: Int].self, forKey: .mismatchBreakdown) ?? [:]
        scoreMonotonicityHints = try container.decodeIfPresent([String].self, forKey: .scoreMonotonicityHints) ?? []
        isScoreMonotonic = try container.decodeIfPresent(Bool.self, forKey: .isScoreMonotonic) ?? true
    }
}

struct BenchmarkRunnerErrorRecord: Codable, Identifiable, Sendable {
    var id = UUID()
    var sampleID: String
    var path: String
    var stage: String
    var errorCode: BenchmarkRunnerErrorCode?
    var message: String
    var details: [String: String]?
    var timestamp: Date
}

struct BenchmarkVerdictChange: Codable, Identifiable, Sendable {
    var id = UUID()
    var sampleID: String
    var group: String
    var previousVerdict: String
    var currentVerdict: String
    var previousScore: Int
    var currentScore: Int
}

struct BenchmarkScoreDelta: Codable, Identifiable, Sendable {
    var id = UUID()
    var sampleID: String
    var group: String
    var previousScore: Int
    var currentScore: Int
    var delta: Int
    var previousVerdict: String
    var currentVerdict: String
}

struct BenchmarkDiffSummary: Codable, Sendable {
    var previousRunID: String?
    var comparedAt: Date
    var addedSamples: [String]
    var removedSamples: [String]
    var scoreIncreasedSamples: [String]
    var scoreDecreasedSamples: [String]
    var verdictChanges: [BenchmarkVerdictChange]
    var newlyRaisedFalsePositives: [String]
    var newlyRaisedFalseNegatives: [String]
    var topScoreChanges: [BenchmarkScoreDelta]
    var notes: [String]

    init(
        previousRunID: String?,
        comparedAt: Date,
        addedSamples: [String],
        removedSamples: [String],
        scoreIncreasedSamples: [String],
        scoreDecreasedSamples: [String],
        verdictChanges: [BenchmarkVerdictChange],
        newlyRaisedFalsePositives: [String],
        newlyRaisedFalseNegatives: [String],
        topScoreChanges: [BenchmarkScoreDelta],
        notes: [String]
    ) {
        self.previousRunID = previousRunID
        self.comparedAt = comparedAt
        self.addedSamples = addedSamples
        self.removedSamples = removedSamples
        self.scoreIncreasedSamples = scoreIncreasedSamples
        self.scoreDecreasedSamples = scoreDecreasedSamples
        self.verdictChanges = verdictChanges
        self.newlyRaisedFalsePositives = newlyRaisedFalsePositives
        self.newlyRaisedFalseNegatives = newlyRaisedFalseNegatives
        self.topScoreChanges = topScoreChanges
        self.notes = notes
    }

    enum CodingKeys: String, CodingKey {
        case previousRunID
        case comparedAt
        case addedSamples
        case removedSamples
        case scoreIncreasedSamples
        case scoreDecreasedSamples
        case verdictChanges
        case newlyRaisedFalsePositives
        case newlyRaisedFalseNegatives
        case topScoreChanges
        case notes
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        previousRunID = try container.decodeIfPresent(String.self, forKey: .previousRunID)
        comparedAt = try container.decodeIfPresent(Date.self, forKey: .comparedAt) ?? Date.distantPast
        addedSamples = try container.decodeIfPresent([String].self, forKey: .addedSamples) ?? []
        removedSamples = try container.decodeIfPresent([String].self, forKey: .removedSamples) ?? []
        scoreIncreasedSamples = try container.decodeIfPresent([String].self, forKey: .scoreIncreasedSamples) ?? []
        scoreDecreasedSamples = try container.decodeIfPresent([String].self, forKey: .scoreDecreasedSamples) ?? []
        verdictChanges = try container.decodeIfPresent([BenchmarkVerdictChange].self, forKey: .verdictChanges) ?? []
        newlyRaisedFalsePositives = try container.decodeIfPresent([String].self, forKey: .newlyRaisedFalsePositives) ?? []
        newlyRaisedFalseNegatives = try container.decodeIfPresent([String].self, forKey: .newlyRaisedFalseNegatives) ?? []
        topScoreChanges = try container.decodeIfPresent([BenchmarkScoreDelta].self, forKey: .topScoreChanges) ?? []
        notes = try container.decodeIfPresent([String].self, forKey: .notes) ?? []
    }
}

struct BenchmarkExportBundle: Codable, Sendable {
    var outputDirectoryPath: String
    var rawResultsPath: String
    var summaryJSONPath: String
    var samplesCSVPath: String
    var summaryMarkdownPath: String
    var errorsJSONPath: String
    var diffJSONPath: String?
    var diffMarkdownPath: String?
    var discoveredSamplesPath: String?
    var scoringTracePath: String?
    var findingsTracePath: String?
    var scoreCapTracePath: String?
    var contextTracePath: String?
    var replayDebugPath: String?
    var latestPointerPath: String?
}

struct BenchmarkRun: Codable, Sendable {
    var schemaVersion: String
    var runID: String
    var benchmarkRootPath: String
    var startedAt: Date
    var finishedAt: Date
    var discoveryWarnings: [String]
    var missingRequiredDirectories: [String]
    var samples: [BenchmarkSample]
    var results: [BenchmarkSampleResult]
    var summary: BenchmarkSummary
    var errors: [BenchmarkRunnerErrorRecord]
    var discoveredSamples: [BenchmarkDiscoveredSampleRecord]?
    var scoringTraces: [BenchmarkScoringTraceEntry]?
    var findingsTraces: [BenchmarkFindingsTraceEntry]?
    var scoreCapTraces: [BenchmarkScoreCapTraceEntry]?
    var contextTraces: [BenchmarkContextTraceEntry]?
    var replayDebug: [BenchmarkReplayDebugRecord]?
    var exportBundle: BenchmarkExportBundle?
    var diffSummary: BenchmarkDiffSummary?
}

struct BenchmarkDiscoveryResult: Sendable {
    var samples: [BenchmarkSample]
    var warnings: [String]
    var missingRequiredDirectories: [String]
}

struct BenchmarkRunExecution: Sendable {
    var run: BenchmarkRun
    var exportBundle: BenchmarkExportBundle
}

struct BenchmarkRunnerProgress: Sendable {
    var totalSamples: Int
    var completedSamples: Int
    var currentSampleID: String?
    var currentPath: String?
    var message: String
}

struct BenchmarkStatisticsSnapshot: Sendable {
    var totalSamples: Int
    var analyzedSamples: Int
    var failedSamples: Int
    var effectiveCoverageRate: Double?
    var cleanCount: Int
    var suspiciousCount: Int
    var maliciousCount: Int
    var unknownCount: Int
    var averageScore: Double
    var medianScore: Double
    var verdictAccuracy: Double?
    var scoreRangeMatchRate: Double?
    var falsePositiveCount: Int?
    var falseNegativeCount: Int?
    var cleanFalsePositiveRate: Double?
    var noisyBenignFalsePositiveRate: Double?
    var suspiciousHitRate: Double?
    var replayMaliciousDetectionRate: Double?

    static let empty = BenchmarkStatisticsSnapshot(
        totalSamples: 0,
        analyzedSamples: 0,
        failedSamples: 0,
        effectiveCoverageRate: nil,
        cleanCount: 0,
        suspiciousCount: 0,
        maliciousCount: 0,
        unknownCount: 0,
        averageScore: 0,
        medianScore: 0,
        verdictAccuracy: nil,
        scoreRangeMatchRate: nil,
        falsePositiveCount: nil,
        falseNegativeCount: nil,
        cleanFalsePositiveRate: nil,
        noisyBenignFalsePositiveRate: nil,
        suspiciousHitRate: nil,
        replayMaliciousDetectionRate: nil
    )
}

struct BenchmarkResultTableRow: Identifiable, Sendable {
    var sampleID: String
    var group: String
    var subtype: String
    var score: Int?
    var verdict: String?
    var expectedVerdict: String?
    var expectedScoreRange: BenchmarkScoreRange?
    var matchedExpectation: Bool?
    var matchedScoreRange: Bool?
    var mismatchReason: BenchmarkMismatchReason?
    var status: BenchmarkSampleExecutionStatus
    var relativePath: String
    var analysisDurationMs: Int?
    var hasFindings: Bool
    var findings: [String]
    var findingDeltas: [BenchmarkFindingDelta]
    var analysisSummary: String?
    var errorMessage: String?
    var errorCode: BenchmarkRunnerErrorCode?
    var notes: [String]

    var id: String { sampleID }
}

enum BenchmarkExportArtifact: String, CaseIterable, Sendable {
    case rawResults
    case summaryMarkdown
    case samplesCSV
    case diffMarkdown
    case scoringTrace
    case findingsTrace
    case scoreCapTrace
    case contextTrace

    var filename: String {
        switch self {
        case .rawResults:
            return "raw_results.json"
        case .summaryMarkdown:
            return "summary.md"
        case .samplesCSV:
            return "samples.csv"
        case .diffMarkdown:
            return "diff.md"
        case .scoringTrace:
            return "scoring_trace.json"
        case .findingsTrace:
            return "findings_trace.json"
        case .scoreCapTrace:
            return "score_cap_trace.json"
        case .contextTrace:
            return "context_trace.json"
        }
    }
}
