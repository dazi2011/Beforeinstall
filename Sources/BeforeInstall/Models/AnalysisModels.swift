import Foundation

enum SupportedFileType: String, Codable, CaseIterable, Sendable {
    case appBundle
    case dmg
    case pkg
    case machO
    case shellScript
    case pythonScript
    case javaScript
    case appleScript
    case archive
    case plist
    case dylib
    case unknown

    var displayName: String {
        switch self {
        case .appBundle: return ".app Bundle"
        case .dmg: return ".dmg Disk Image"
        case .pkg: return ".pkg Installer"
        case .machO: return "Mach-O Binary"
        case .shellScript: return "Shell Script"
        case .pythonScript: return "Python Script"
        case .javaScript: return "JavaScript"
        case .appleScript: return "AppleScript"
        case .archive: return "Archive"
        case .plist: return "Property List"
        case .dylib: return "Dynamic Library"
        case .unknown: return "Unknown"
        }
    }

    func displayName(language: AppLanguage) -> String {
        guard language == .zhHans else { return displayName }
        switch self {
        case .appBundle: return ".app 应用包"
        case .dmg: return ".dmg 磁盘镜像"
        case .pkg: return ".pkg 安装包"
        case .machO: return "Mach-O 可执行文件"
        case .shellScript: return "Shell 脚本"
        case .pythonScript: return "Python 脚本"
        case .javaScript: return "JavaScript 脚本"
        case .appleScript: return "AppleScript 脚本"
        case .archive: return "压缩包"
        case .plist: return "配置清单（plist）"
        case .dylib: return "动态库（dylib）"
        case .unknown: return "未知类型"
        }
    }

    var isPrimaryInstallTarget: Bool {
        self == .appBundle || self == .pkg || self == .dmg
    }

    var isScriptType: Bool {
        switch self {
        case .shellScript, .pythonScript, .javaScript, .appleScript:
            return true
        default:
            return false
        }
    }

    var isExecutableLike: Bool {
        switch self {
        case .appBundle, .machO, .dylib, .shellScript, .pythonScript, .javaScript, .appleScript:
            return true
        default:
            return false
        }
    }

    static func detect(from fileURL: URL) -> SupportedFileType {
        let ext = fileURL.pathExtension.lowercased()
        switch ext {
        case "app": return .appBundle
        case "dmg", "iso": return .dmg
        case "pkg", "mpkg": return .pkg
        case "sh", "zsh", "bash", "command": return .shellScript
        case "py": return .pythonScript
        case "js", "mjs", "cjs": return .javaScript
        case "applescript", "scpt", "scptd": return .appleScript
        case "zip", "tar", "gz", "bz2", "xz", "7z", "rar": return .archive
        case "plist": return .plist
        case "dylib", "so": return .dylib
        case "bin", "out", "exe": return .machO
        default: return .unknown
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)

        if let current = SupportedFileType(rawValue: rawValue) {
            self = current
            return
        }

        switch rawValue {
        case "app": self = .appBundle
        case "script": self = .shellScript
        case "binary": self = .machO
        case "document": self = .unknown
        case "image": self = .unknown
        default: self = .unknown
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

enum RiskLevel: String, Codable, Sendable {
    case info
    case low
    case medium
    case high
    case critical

    var displayName: String {
        switch self {
        case .info: return "Info"
        case .low: return "Low"
        case .medium: return "Medium"
        case .high: return "High"
        case .critical: return "Critical"
        }
    }

    func displayName(language: AppLanguage) -> String {
        guard language == .zhHans else { return displayName }
        switch self {
        case .info: return "提示"
        case .low: return "低"
        case .medium: return "中"
        case .high: return "高"
        case .critical: return "严重"
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        if let current = RiskLevel(rawValue: rawValue) {
            self = current
            return
        }

        switch rawValue.lowercased() {
        case "severe":
            self = .critical
        case "warn", "warning":
            self = .info
        default:
            self = .medium
        }
    }
}

enum AnalysisMode: String, Codable, CaseIterable, Identifiable, Sendable {
    case staticOnly
    case dynamicOnly
    case combined

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .staticOnly: return "Static"
        case .dynamicOnly: return "Dynamic (Experimental)"
        case .combined: return "Static + Dynamic"
        }
    }

    func displayName(language: AppLanguage) -> String {
        guard language == .zhHans else { return displayName }
        switch self {
        case .staticOnly: return "静态分析"
        case .dynamicOnly: return "动态分析（实验性）"
        case .combined: return "静态 + 动态"
        }
    }
}

enum AnalysisDepth: String, Codable, CaseIterable, Identifiable, Sendable {
    case quick
    case deep

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .quick: return "Quick"
        case .deep: return "Deep"
        }
    }

    func displayName(language: AppLanguage) -> String {
        guard language == .zhHans else { return displayName }
        switch self {
        case .quick: return "快速"
        case .deep: return "深度"
        }
    }
}

enum AppLanguage: String, Codable, CaseIterable, Identifiable, Sendable {
    case zhHans
    case en

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .zhHans: return "简体中文"
        case .en: return "English"
        }
    }
}

enum AppAppearance: String, Codable, CaseIterable, Identifiable, Sendable {
    case system
    case light
    case dark

    var id: String { rawValue }

    func displayName(language: AppLanguage) -> String {
        if language == .zhHans {
            switch self {
            case .system: return "跟随系统"
            case .light: return "浅色"
            case .dark: return "深色"
            }
        }

        switch self {
        case .system: return "System"
        case .light: return "Light"
        case .dark: return "Dark"
        }
    }
}

enum ScoringProfile: String, Codable, CaseIterable, Identifiable, Sendable {
    case optimistic
    case balanced
    case aggressive

    var id: String { rawValue }

    func displayName(language: AppLanguage) -> String {
        switch (self, language) {
        case (.optimistic, .zhHans):
            return "乐观"
        case (.balanced, .zhHans):
            return "均衡"
        case (.aggressive, .zhHans):
            return "激进"
        case (.optimistic, .en):
            return "Optimistic"
        case (.balanced, .en):
            return "Balanced"
        case (.aggressive, .en):
            return "Aggressive"
        }
    }
}

struct AnalysisRequest: Codable, Sendable {
    var mode: AnalysisMode
    var depth: AnalysisDepth
    var dynamicDurationSeconds: Int
    var language: AppLanguage
    var allowNonAppDynamicExecution: Bool
    var preferBackgroundAppLaunch: Bool
    var manualDynamicInteraction: Bool

    static let `default` = AnalysisRequest(
        mode: .staticOnly,
        depth: .quick,
        dynamicDurationSeconds: 20,
        language: .zhHans,
        allowNonAppDynamicExecution: false,
        preferBackgroundAppLaunch: true,
        manualDynamicInteraction: false
    )
}

struct FileBasicInfo: Codable, Sendable {
    var fileName: String
    var fullPath: String
    var fileType: SupportedFileType
    var fileSizeBytes: Int64
    var createdAt: Date?
    var modifiedAt: Date?
}

enum FileTypeEvidenceSource: String, Codable, Sendable {
    case magicBytes
    case shebang
    case fileHeader
    case bundleStructure
    case fileExtension
    case executablePermission
    case machOCheck
    case unknown
}

struct FileTypeDetection: Codable, Sendable {
    var detectedType: SupportedFileType
    var source: FileTypeEvidenceSource
    var detail: String
    var shebang: String?
    var magicDescription: String?
    var headerDescription: String?
    var isExecutable: Bool
    var isMachO: Bool
}

struct SignatureInfo: Codable, Sendable {
    var isSigned: Bool
    var signerName: String?
    var authorities: [String]
    var teamIdentifier: String?
    var signingIdentifier: String?
    var notarizationStatus: String?
    var isLikelyNotarized: Bool?
}

struct EntitlementInfo: Codable, Sendable {
    var hasSandbox: Bool
    var entries: [String: String]
    var rawXML: String?
}

struct InstallScriptInfo: Codable, Identifiable, Sendable {
    var id = UUID()
    var scriptPath: String
    var scriptType: String
    var snippet: String?
}

struct AppDetails: Codable, Sendable {
    var appName: String?
    var bundleIdentifier: String?
    var shortVersion: String?
    var buildVersion: String?
    var helperItems: [String]
    var loginItems: [String]
    var embeddedFrameworks: [String]
    var launchItems: [String]
}

struct PkgDetails: Codable, Sendable {
    var packageIdentifiers: [String]
    var packageVersion: String?
    var installLocations: [String]
    var payloadFileSample: [String]
    var payloadFileCount: Int?
    var scripts: [InstallScriptInfo]
    var modifiedLocations: [String]
}

struct EmbeddedTargetSummary: Codable, Identifiable, Sendable {
    var id = UUID()
    var path: String
    var type: SupportedFileType
    var riskLevel: RiskLevel?
    var summaryLines: [String]
}

struct DmgDetails: Codable, Sendable {
    var mountedVolumePath: String?
    var topLevelContents: [String]
    var embeddedTargets: [EmbeddedTargetSummary]
}

struct GenericFileDetails: Codable, Sendable {
    var fileTypeByMagic: String?
    var mimeType: String?
    var sha256: String?
    var isExecutable: Bool
    var isPossiblyDisguised: Bool
    var scriptSnippet: String?
    var suspiciousKeywordHits: [String]
}

enum ScriptFindingSeverity: String, Codable, CaseIterable, Sendable {
    case low
    case medium
    case high
    case critical

    func displayName(language: AppLanguage) -> String {
        switch (self, language) {
        case (.low, .zhHans):
            return "低"
        case (.medium, .zhHans):
            return "中"
        case (.high, .zhHans):
            return "高"
        case (.critical, .zhHans):
            return "严重"
        case (.low, .en):
            return "Low"
        case (.medium, .en):
            return "Medium"
        case (.high, .en):
            return "High"
        case (.critical, .en):
            return "Critical"
        }
    }
}

enum FindingSeverity: String, Codable, CaseIterable, Sendable {
    case critical
    case high
    case medium
    case low
    case info
}

enum FindingConfidence: String, Codable, CaseIterable, Sendable {
    case high
    case medium
    case low
}

enum EvidenceStrength: String, Codable, CaseIterable, Sendable {
    case strong
    case moderate
    case weak
}

enum ExecutionSemantics: String, Codable, CaseIterable, Sendable {
    case actualExecutionLike
    case persistenceLike
    case downloadExecuteLike
    case printedOnly
    case echoedOnly
    case commentOnly
    case documentationOnly
    case simulationOnly
    case dryRunOnly
    case configOnly
    case unknown
}

struct StaticFindingSourceLocation: Codable, Sendable {
    var filePath: String?
    var lineStart: Int?
    var lineEnd: Int?
    var keyPath: String?
}

struct StaticFinding: Codable, Identifiable, Sendable {
    var id: String
    var ruleID: String
    var title: String
    var category: String
    var severity: FindingSeverity
    var confidence: FindingConfidence
    var evidenceStrength: EvidenceStrength
    var scoreDeltaBase: Int
    var explanation: String
    var evidenceSnippet: String
    var sourceLocation: StaticFindingSourceLocation
    var executionSemantics: ExecutionSemantics
    var tags: [String]
    var detectedType: SupportedFileType
}

struct ScoreAdjustmentTrace: Codable, Identifiable, Sendable {
    var id = UUID()
    var name: String
    var delta: Int
    var reason: String
}

struct ScoreCapTrace: Codable, Identifiable, Sendable {
    var id = UUID()
    var cap: Int
    var reason: String
    var applied: Bool
    var beforeScore: Int
    var afterScore: Int
}

struct StaticScoringTrace: Codable, Sendable {
    var sampleID: String
    var detectedType: String
    var typeScorerUsed: String
    var baseScore: Int
    var contextAdjustments: [ScoreAdjustmentTrace]
    var chainBonuses: [ScoreAdjustmentTrace]
    var scoreCapsApplied: [ScoreCapTrace]
    var finalScore: Int
    var verdict: String
    var topFindings: [String]
    var notes: [String]
}

struct ScriptRuleHit: Codable, Identifiable, Sendable {
    var id = UUID()
    var ruleID: String
    var title: String
    var severity: ScriptFindingSeverity
    var matchedContent: String
    var lineStart: Int
    var lineEnd: Int
    var explanation: String
    var suggestedRiskScoreDelta: Int
}

struct ScriptAnalysisDetails: Codable, Sendable {
    var scriptType: SupportedFileType
    var shebang: String?
    var lineCount: Int
    var tokenCount: Int
    var commandSample: [String]
    var summary: [String]
    var ruleHits: [ScriptRuleHit]
}

struct TechnicalDetail: Codable, Identifiable, Sendable {
    var id = UUID()
    var title: String
    var content: String
}

struct RandomForestPredictionResult: Codable, Sendable {
    var path: String
    var exists: Bool?
    var isDir: Bool?
    var analysisScope: String?
    var contentFullyInspected: Bool?
    var verdictLabel: String?
    var riskBucket: String?
    var probMalicious: Double?
    var modelRawVerdictLabel: String?
    var modelRawProbMalicious: Double?
    var modelWarnings: [String]
    var containerSignals: [String]
    var heuristicReasons: [String]
    var extractorNotes: [String]
    var modelActiveTopFeatures: [String]
    var selectedFeatureSnapshot: [String: Double]
    var modelPath: String?
    var error: String?

    var normalizedVerdictLabel: String {
        verdictLabel?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? "unknown"
    }

    var safeProbMalicious: Double {
        let raw = probMalicious ?? modelRawProbMalicious ?? 0
        return max(0, min(1, raw))
    }

    var hasUsablePrediction: Bool {
        error == nil && verdictLabel != nil && (probMalicious != nil || modelRawProbMalicious != nil)
    }

    enum CodingKeys: String, CodingKey {
        case path
        case exists
        case isDir = "is_dir"
        case analysisScope = "analysis_scope"
        case contentFullyInspected = "content_fully_inspected"
        case verdictLabel = "verdict_label"
        case riskBucket = "risk_bucket"
        case probMalicious = "prob_malicious"
        case modelRawVerdictLabel = "model_raw_verdict_label"
        case modelRawProbMalicious = "model_raw_prob_malicious"
        case modelWarnings = "model_warnings"
        case containerSignals = "container_signals"
        case heuristicReasons = "heuristic_reasons"
        case extractorNotes = "extractor_notes"
        case modelActiveTopFeatures = "model_active_top_features"
        case selectedFeatureSnapshot = "selected_feature_snapshot"
        case modelPath = "model_path"
        case error
    }

    init(
        path: String,
        exists: Bool? = nil,
        isDir: Bool? = nil,
        analysisScope: String? = nil,
        contentFullyInspected: Bool? = nil,
        verdictLabel: String? = nil,
        riskBucket: String? = nil,
        probMalicious: Double? = nil,
        modelRawVerdictLabel: String? = nil,
        modelRawProbMalicious: Double? = nil,
        modelWarnings: [String] = [],
        containerSignals: [String] = [],
        heuristicReasons: [String] = [],
        extractorNotes: [String] = [],
        modelActiveTopFeatures: [String] = [],
        selectedFeatureSnapshot: [String: Double] = [:],
        modelPath: String? = nil,
        error: String? = nil
    ) {
        self.path = path
        self.exists = exists
        self.isDir = isDir
        self.analysisScope = analysisScope
        self.contentFullyInspected = contentFullyInspected
        self.verdictLabel = verdictLabel
        self.riskBucket = riskBucket
        self.probMalicious = probMalicious
        self.modelRawVerdictLabel = modelRawVerdictLabel
        self.modelRawProbMalicious = modelRawProbMalicious
        self.modelWarnings = modelWarnings
        self.containerSignals = containerSignals
        self.heuristicReasons = heuristicReasons
        self.extractorNotes = extractorNotes
        self.modelActiveTopFeatures = modelActiveTopFeatures
        self.selectedFeatureSnapshot = selectedFeatureSnapshot
        self.modelPath = modelPath
        self.error = error
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        path = try container.decodeIfPresent(String.self, forKey: .path) ?? ""
        exists = try container.decodeIfPresent(Bool.self, forKey: .exists)
        isDir = try container.decodeIfPresent(Bool.self, forKey: .isDir)
        analysisScope = try container.decodeIfPresent(String.self, forKey: .analysisScope)
        contentFullyInspected = try container.decodeIfPresent(Bool.self, forKey: .contentFullyInspected)
        verdictLabel = try container.decodeIfPresent(String.self, forKey: .verdictLabel)
        riskBucket = try container.decodeIfPresent(String.self, forKey: .riskBucket)
        probMalicious = try container.decodeIfPresent(Double.self, forKey: .probMalicious)
        modelRawVerdictLabel = try container.decodeIfPresent(String.self, forKey: .modelRawVerdictLabel)
        modelRawProbMalicious = try container.decodeIfPresent(Double.self, forKey: .modelRawProbMalicious)
        modelWarnings = try container.decodeIfPresent([String].self, forKey: .modelWarnings) ?? []
        containerSignals = try container.decodeIfPresent([String].self, forKey: .containerSignals) ?? []
        heuristicReasons = try container.decodeIfPresent([String].self, forKey: .heuristicReasons) ?? []
        extractorNotes = try container.decodeIfPresent([String].self, forKey: .extractorNotes) ?? []
        modelActiveTopFeatures = try container.decodeIfPresent([String].self, forKey: .modelActiveTopFeatures) ?? []
        selectedFeatureSnapshot = try container.decodeIfPresent([String: Double].self, forKey: .selectedFeatureSnapshot) ?? [:]
        modelPath = try container.decodeIfPresent(String.self, forKey: .modelPath)
        error = try container.decodeIfPresent(String.self, forKey: .error)
    }
}

struct RiskReason: Codable, Identifiable, Sendable {
    var id: String
    var titleZH: String
    var titleEN: String
    var delta: Int
    var evidence: String

    func title(language: AppLanguage) -> String {
        language == .zhHans ? titleZH : titleEN
    }
}

struct FailureIssue: Codable, Identifiable, Sendable {
    var id = UUID()
    var code: String
    var titleZH: String
    var titleEN: String
    var suggestionZH: String
    var suggestionEN: String
    var rawMessage: String

    func title(language: AppLanguage) -> String {
        language == .zhHans ? titleZH : titleEN
    }

    func suggestion(language: AppLanguage) -> String {
        language == .zhHans ? suggestionZH : suggestionEN
    }
}

struct RiskAssessment: Codable, Sendable {
    var level: RiskLevel
    var score: Int
    var reasons: [String]
    var breakdown: [RiskReason]
}

enum ScanVerdict: String, Codable, Sendable {
    case clean
    case suspicious
    case malicious
    case unknown

    func displayName(language: AppLanguage) -> String {
        switch (self, language) {
        case (.clean, .zhHans):
            return "Clean（低风险）"
        case (.suspicious, .zhHans):
            return "Suspicious（可疑）"
        case (.malicious, .zhHans):
            return "Malicious（高风险）"
        case (.unknown, .zhHans):
            return "Unknown（证据不足）"
        case (.clean, .en):
            return "Clean (Low Risk)"
        case (.suspicious, .en):
            return "Suspicious"
        case (.malicious, .en):
            return "Malicious (High Risk)"
        case (.unknown, .en):
            return "Unknown (Insufficient Evidence)"
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        if let verdict = ScanVerdict(rawValue: rawValue) {
            self = verdict
            return
        }

        switch rawValue {
        case "allow":
            self = .clean
        case "caution":
            self = .suspicious
        case "highRisk":
            self = .malicious
        default:
            self = .unknown
        }
    }
}

struct RiskRuleResult: Codable, Identifiable, Sendable {
    var id: String
    var titleZH: String
    var titleEN: String
    var shortSummaryZH: String
    var shortSummaryEN: String
    var technicalDetails: String
    var scoreDelta: Int
    var severity: String? = nil
    var category: String? = nil
    var explanation: String? = nil
    var confidence: String? = nil
    var evidenceStrength: String? = nil
    var executionSemantics: String? = nil
    var scoreDeltaBase: Int? = nil
    var sourceLocation: String? = nil
    var tags: [String]? = nil
    var typeScorer: String? = nil

    func title(language: AppLanguage) -> String {
        language == .zhHans ? titleZH : titleEN
    }

    func shortSummary(language: AppLanguage) -> String {
        language == .zhHans ? shortSummaryZH : shortSummaryEN
    }
}

struct RiskEvaluation: Codable, Sendable {
    var totalScore: Int
    var verdict: ScanVerdict
    var reasoningSummaryZH: String
    var reasoningSummaryEN: String
    var topFindings: [RiskRuleResult]
    var allFindings: [RiskRuleResult]
    var isEvidenceInsufficient: Bool
    var staticScoringTrace: StaticScoringTrace? = nil
    var findingsTrace: [StaticFinding]? = nil
    var scoreCapTrace: [ScoreCapTrace]? = nil
    var contextTrace: [ScoreAdjustmentTrace]? = nil

    func reasoningSummary(language: AppLanguage) -> String {
        language == .zhHans ? reasoningSummaryZH : reasoningSummaryEN
    }
}

struct ScanReport: Codable, Identifiable, Sendable {
    var id = UUID()
    var analyzedAt: Date
    var filePath: String
    var detectedType: SupportedFileType
    var fileSizeBytes: Int64
    var sha256: String?
    var signingInfo: SignatureInfo?
    var findings: [String]
    var riskScore: Int
    var finalVerdict: ScanVerdict
    var reasoningSummary: String
    var topFindings: [RiskRuleResult]
    var riskEvaluation: RiskEvaluation?
    var filesystemDiff: FileSystemDiffResult?
    var networkSummary: NetworkSummary?
    var dynamicResults: DynamicAnalysisSession?
    var analysisResult: AnalysisResult
    var detection: FileTypeDetection
}

struct AnalysisResult: Codable, Identifiable, Sendable {
    var id = UUID()
    var analyzedAt: Date

    var basicInfo: FileBasicInfo
    var analysisMode: AnalysisMode
    var analysisDepth: AnalysisDepth

    var signatureInfo: SignatureInfo?
    var entitlementInfo: EntitlementInfo?
    var appDetails: AppDetails?
    var pkgDetails: PkgDetails?
    var dmgDetails: DmgDetails?
    var scriptDetails: ScriptAnalysisDetails?
    var genericDetails: GenericFileDetails?
    var randomForestPrediction: RandomForestPredictionResult?
    var dynamicReport: DynamicAnalysisReport?
    var dynamicResults: DynamicAnalysisSession?

    var sensitiveCapabilities: [String]
    var persistenceIndicators: [String]
    var technicalDetails: [TechnicalDetail]
    var warnings: [String]
    var failureIssues: [FailureIssue]

    var plainSummary: [String]
    var riskAssessment: RiskAssessment
    var riskEvaluation: RiskEvaluation?
}

extension AnalysisResult {
    static func placeholder(for basic: FileBasicInfo) -> AnalysisResult {
        placeholder(for: basic, request: .default)
    }

    static func placeholder(for basic: FileBasicInfo, request: AnalysisRequest) -> AnalysisResult {
        AnalysisResult(
            analyzedAt: Date(),
            basicInfo: basic,
            analysisMode: request.mode,
            analysisDepth: request.depth,
            signatureInfo: nil,
            entitlementInfo: nil,
            appDetails: nil,
            pkgDetails: nil,
            dmgDetails: nil,
            scriptDetails: nil,
            genericDetails: nil,
            randomForestPrediction: nil,
            dynamicReport: nil,
            dynamicResults: nil,
            sensitiveCapabilities: [],
            persistenceIndicators: [],
            technicalDetails: [],
            warnings: [],
            failureIssues: [],
            plainSummary: [],
            riskAssessment: RiskAssessment(level: .low, score: 0, reasons: [], breakdown: []),
            riskEvaluation: nil
        )
    }
}
