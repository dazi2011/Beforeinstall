import Foundation

enum MainBatchSampleStatus: String, Codable, Sendable {
    case completed
    case failed
    case blocked
}

struct MainBatchSampleSummary: Codable, Identifiable, Sendable {
    var id: UUID
    var analyzedAt: Date
    var fileName: String
    var filePath: String
    var fileType: SupportedFileType
    var mode: AnalysisMode
    var status: MainBatchSampleStatus
    var score: Int?
    var verdict: ScanVerdict?
    var riskLevel: RiskLevel?
    var analysisDurationMs: Int?
    var errorMessage: String?
}

struct MainBatchRunRecord: Codable, Identifiable, Sendable {
    var id: UUID
    var runID: String
    var createdAt: Date
    var mode: AnalysisMode
    var depth: AnalysisDepth
    var totalSamples: Int
    var completedSamples: Int
    var failedSamples: Int
    var dynamicManualInteractionEnabled: Bool
    var sampleSummaries: [MainBatchSampleSummary]
}
