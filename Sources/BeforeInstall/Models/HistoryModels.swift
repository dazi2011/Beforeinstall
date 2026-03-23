import Foundation

struct AnalysisHistoryRecord: Codable, Identifiable, Sendable {
    var id: UUID
    var createdAt: Date
    var fileName: String
    var filePath: String
    var fileType: SupportedFileType
    var mode: AnalysisMode
    var riskLevel: RiskLevel
    var result: AnalysisResult

    init(result: AnalysisResult) {
        self.id = UUID()
        self.createdAt = result.analyzedAt
        self.fileName = result.basicInfo.fileName
        self.filePath = result.basicInfo.fullPath
        self.fileType = result.basicInfo.fileType
        self.mode = result.analysisMode
        self.riskLevel = result.riskAssessment.level
        self.result = result
    }
}
