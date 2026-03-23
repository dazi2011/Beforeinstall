import Foundation

final class DmgAnalyzer: StaticAnalyzer {
    let analyzerName = "DmgAnalyzer"
    let supportedTypes: Set<SupportedFileType> = [.dmg]

    private let commandRunner: CommandRunning
    private let metadataService: FileMetadataService
    private let appAnalyzer: AppAnalyzer
    private let pkgAnalyzer: PkgAnalyzer
    private let riskEngine: RiskEngine
    private let summaryBuilder: PlainSummaryBuilder
    private let detector: FileTypeDetector
    private let fileManager = FileManager.default

    init(
        commandRunner: CommandRunning,
        metadataService: FileMetadataService,
        appAnalyzer: AppAnalyzer,
        pkgAnalyzer: PkgAnalyzer,
        riskEngine: RiskEngine,
        summaryBuilder: PlainSummaryBuilder,
        detector: FileTypeDetector
    ) {
        self.commandRunner = commandRunner
        self.metadataService = metadataService
        self.appAnalyzer = appAnalyzer
        self.pkgAnalyzer = pkgAnalyzer
        self.riskEngine = riskEngine
        self.summaryBuilder = summaryBuilder
        self.detector = detector
    }

    func analyze(fileURL: URL, basicInfo: FileBasicInfo) async -> AnalysisResult {
        var result = AnalysisResult.placeholder(for: basicInfo)
        var dmgDetails = DmgDetails(mountedVolumePath: nil, topLevelContents: [], embeddedTargets: [])

        let attachResult = commandRunner.run(
            executable: "/usr/bin/hdiutil",
            arguments: ["attach", "-readonly", "-nobrowse", "-noautoopen", "-plist", fileURL.path]
        )

        var mountPoint: String?

        switch attachResult {
        case let .success(command):
            result.technicalDetails.append(TechnicalDetail(title: "hdiutil attach", content: command.combinedOutput))
            if let parsedMountPoint = parseMountPoint(fromPlistText: command.stdout) {
                mountPoint = parsedMountPoint
                dmgDetails.mountedVolumePath = parsedMountPoint
            } else {
                result.warnings.append("无法从 hdiutil 输出中解析挂载点")
            }
        case let .failure(error):
            result.warnings.append("挂载 DMG 失败：\(error.localizedDescription)")
        }

        guard let mountPoint else {
            // 挂载失败时降级为 imageinfo，至少给出容器级信息。
            appendImageInfo(for: fileURL, result: &result)
            result.dmgDetails = dmgDetails
            return result
        }

        defer {
            _ = commandRunner.run(executable: "/usr/bin/hdiutil", arguments: ["detach", mountPoint, "-force"])
        }

        let mountURL = URL(fileURLWithPath: mountPoint)

        do {
            let topLevelItems = try fileManager.contentsOfDirectory(at: mountURL, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles])
            dmgDetails.topLevelContents = topLevelItems.map { $0.lastPathComponent }.sorted()
            if !dmgDetails.topLevelContents.isEmpty {
                result.technicalDetails.append(
                    TechnicalDetail(
                        title: "DMG 顶层内容",
                        content: dmgDetails.topLevelContents.joined(separator: "\n")
                    )
                )
            }
        } catch {
            result.warnings.append("读取 DMG 内容失败：\(error.localizedDescription)")
        }

        let embeddedTargets = findEmbeddedTargets(in: mountURL, maxDepth: 4, limit: 3)

        for target in embeddedTargets {
            let targetDetection = detector.detect(fileURL: target)
            let targetType = targetDetection.detectedType
            let nestedBasic: FileBasicInfo
            switch metadataService.basicInfo(for: target, detectedType: targetType) {
            case let .success(info):
                nestedBasic = info
            case .failure:
                nestedBasic = metadataService.makeFallbackInfo(for: target, detectedType: targetType)
            }

            let nestedResult: AnalysisResult
            switch targetType {
            case .appBundle:
                nestedResult = await appAnalyzer.analyze(fileURL: target, basicInfo: nestedBasic)
            case .pkg:
                nestedResult = await pkgAnalyzer.analyze(fileURL: target, basicInfo: nestedBasic)
            default:
                continue
            }

            var nestedWithAssessment = nestedResult
            nestedWithAssessment.riskAssessment = riskEngine.assess(nestedWithAssessment, language: .zhHans)
            nestedWithAssessment.plainSummary = summaryBuilder.build(for: nestedWithAssessment, language: .zhHans)

            dmgDetails.embeddedTargets.append(
                EmbeddedTargetSummary(
                    path: target.path.replacingOccurrences(of: mountPoint, with: ""),
                    type: targetType,
                    riskLevel: nestedWithAssessment.riskAssessment.level,
                    summaryLines: nestedWithAssessment.plainSummary.prefix(4).map { $0 }
                )
            )

            result.technicalDetails.append(
                TechnicalDetail(
                    title: "递归分析：\(target.lastPathComponent)",
                    content: nestedWithAssessment.technicalDetails.prefix(3).map { "[\($0.title)]\n\($0.content)" }.joined(separator: "\n\n")
                )
            )
        }

        if embeddedTargets.isEmpty {
            result.warnings.append("未在 DMG 中发现 .app 或 .pkg（已输出内容概览）")
        }

        result.dmgDetails = dmgDetails
        return result
    }

    private func parseMountPoint(fromPlistText plistText: String) -> String? {
        guard let data = plistText.data(using: .utf8),
              let raw = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = raw as? [String: Any],
              let entities = dict["system-entities"] as? [[String: Any]]
        else {
            return nil
        }

        for entity in entities {
            if let mountPoint = entity["mount-point"] as? String {
                return mountPoint
            }
        }

        return nil
    }

    private func appendImageInfo(for fileURL: URL, result: inout AnalysisResult) {
        switch commandRunner.run(executable: "/usr/bin/hdiutil", arguments: ["imageinfo", fileURL.path]) {
        case let .success(command):
            result.technicalDetails.append(TechnicalDetail(title: "hdiutil imageinfo", content: command.combinedOutput))
        case let .failure(error):
            result.warnings.append("读取 DMG 基本信息失败：\(error.localizedDescription)")
        }
    }

    private func findEmbeddedTargets(in root: URL, maxDepth: Int, limit: Int) -> [URL] {
        guard let enumerator = fileManager.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles],
            errorHandler: nil
        ) else {
            return []
        }

        var found: [URL] = []
        let baseDepth = root.pathComponents.count

        for case let url as URL in enumerator {
            let depth = url.pathComponents.count - baseDepth
            if depth > maxDepth {
                enumerator.skipDescendants()
                continue
            }

            let ext = url.pathExtension.lowercased()
            if ext == "app" || ext == "pkg" {
                found.append(url)
                enumerator.skipDescendants()
            }

            if found.count >= limit {
                break
            }
        }

        return found
    }
}
