import Foundation

struct ExportedReport: Codable, Sendable {
    var schemaVersion: String
    var generatedAt: Date
    var mode: AnalysisMode
    var depth: AnalysisDepth
    var riskLevel: RiskLevel
    var riskScore: Int
    var verdict: ScanVerdict
    var reasoningSummary: String
    var topFindings: [RiskRuleResult]
    var allFindings: [RiskRuleResult]
    var riskReasons: [RiskReason]
    var result: AnalysisResult
    var summary: [String]
    var filesystemDiff: FileSystemDiffResult?
    var networkSummary: NetworkSummary?
    var dynamicStatus: DynamicStatus?
    var dynamicFailureReasons: [FailureIssue]
}
