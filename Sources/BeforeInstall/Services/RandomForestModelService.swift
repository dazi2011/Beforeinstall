import Foundation

struct RandomForestTrainingResult: Sendable {
    var outputDirectoryPath: String
    var modelPath: String?
    var reportPath: String?
    var importancePath: String?
    var featureDumpPath: String?
    var stdout: String
    var stderr: String
}

enum RandomForestModelServiceError: LocalizedError {
    case bundledAssetMissing(String)
    case commandFailed(String)
    case invalidPredictionOutput(String)
    case ioFailure(String)

    var errorDescription: String? {
        switch self {
        case let .bundledAssetMissing(message),
             let .commandFailed(message),
             let .invalidPredictionOutput(message),
             let .ioFailure(message):
            return message
        }
    }
}

final class RandomForestModelService: @unchecked Sendable {
    static let shared = RandomForestModelService()

    static let bundleSubdirectory = "RandomForest"
    static let scriptFileName = "macos_static_malware_ai_enhanced_batch_recursive_bundles_ultimate_v4.py"
    static let defaultModelFileName = "trained_static_macos_malware_model.joblib"
    static let defaultReportFileName = "training_report.json"
    static let defaultImportanceFileName = "top_feature_importance.json"
    static let defaultFeatureDumpFileName = "feature_samples.jsonl"

    private let fileManager = FileManager.default
    private let lock = NSLock()

    private init() {}

    var runtimeDirectoryURL: URL {
        AppPaths.randomForestDirectory
    }

    var runtimeScriptURL: URL {
        runtimeDirectoryURL.appendingPathComponent(Self.scriptFileName, isDirectory: false)
    }

    func ensureRuntimeAssetsReady() throws {
        lock.lock()
        defer { lock.unlock() }
        try ensureRuntimeAssetsReadyLocked()
    }

    func modelCandidates() -> [URL] {
        lock.lock()
        defer { lock.unlock() }
        try? ensureRuntimeAssetsReadyLocked()
        return modelCandidatesLocked()
    }

    @discardableResult
    func replaceModel(with sourceURL: URL) throws -> URL {
        lock.lock()
        defer { lock.unlock() }

        try ensureRuntimeAssetsReadyLocked()

        let hasScope = sourceURL.startAccessingSecurityScopedResource()
        defer {
            if hasScope {
                sourceURL.stopAccessingSecurityScopedResource()
            }
        }

        guard fileManager.fileExists(atPath: sourceURL.path) else {
            throw RandomForestModelServiceError.ioFailure("待导入模型不存在: \(sourceURL.path)")
        }

        let modelName = sourceURL.pathExtension.lowercased() == "joblib"
            ? sourceURL.lastPathComponent
            : sourceURL.lastPathComponent + ".joblib"
        let destinationURL = runtimeDirectoryURL.appendingPathComponent(modelName, isDirectory: false)

        let existingModels = modelCandidatesLocked()
        for modelURL in existingModels where modelURL.standardizedFileURL != destinationURL.standardizedFileURL {
            try? fileManager.removeItem(at: modelURL)
        }

        if sourceURL.standardizedFileURL == destinationURL.standardizedFileURL {
            return destinationURL
        }

        if fileManager.fileExists(atPath: destinationURL.path) {
            try fileManager.removeItem(at: destinationURL)
        }
        do {
            try fileManager.copyItem(at: sourceURL, to: destinationURL)
        } catch {
            throw RandomForestModelServiceError.ioFailure("替换模型失败: \(error.localizedDescription)")
        }

        return destinationURL
    }

    func predict(targetURL: URL, commandRunner: CommandRunning = ShellCommandService()) throws -> RandomForestPredictionResult {
        try ensureRuntimeAssetsReady()

        let command = try runPython(
            arguments: [runtimeScriptURL.path, "--predict", targetURL.path],
            commandRunner: commandRunner
        )

        guard let parsed = decodePrediction(from: command.stdout) else {
            let preview = String(command.stdout.prefix(1600))
            throw RandomForestModelServiceError.invalidPredictionOutput(
                "随机森林预测输出无法解析为 JSON。\nstdout:\n\(preview)"
            )
        }
        return parsed
    }

    func train(
        datasetRoot: URL,
        outputDirectory: URL,
        commandRunner: CommandRunning = ShellCommandService()
    ) throws -> RandomForestTrainingResult {
        try ensureRuntimeAssetsReady()

        let hasDatasetScope = datasetRoot.startAccessingSecurityScopedResource()
        let hasOutputScope = outputDirectory.startAccessingSecurityScopedResource()
        defer {
            if hasDatasetScope {
                datasetRoot.stopAccessingSecurityScopedResource()
            }
            if hasOutputScope {
                outputDirectory.stopAccessingSecurityScopedResource()
            }
        }

        do {
            try fileManager.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        } catch {
            throw RandomForestModelServiceError.ioFailure("创建训练输出目录失败: \(error.localizedDescription)")
        }

        let command = try runPython(
            arguments: [runtimeScriptURL.path, datasetRoot.path, "--output-dir", outputDirectory.path],
            commandRunner: commandRunner
        )

        let modelPath = modelCandidates(in: outputDirectory).first?.path
        let reportPath = resolvedOutputFilePath(directory: outputDirectory, fileName: Self.defaultReportFileName)
        let importancePath = resolvedOutputFilePath(directory: outputDirectory, fileName: Self.defaultImportanceFileName)
        let featureDumpPath = resolvedOutputFilePath(directory: outputDirectory, fileName: Self.defaultFeatureDumpFileName)

        return RandomForestTrainingResult(
            outputDirectoryPath: outputDirectory.path,
            modelPath: modelPath,
            reportPath: reportPath,
            importancePath: importancePath,
            featureDumpPath: featureDumpPath,
            stdout: command.stdout,
            stderr: command.stderr
        )
    }

    private func ensureRuntimeAssetsReadyLocked() throws {
        do {
            try fileManager.createDirectory(at: runtimeDirectoryURL, withIntermediateDirectories: true)
        } catch {
            throw RandomForestModelServiceError.ioFailure("创建随机森林运行目录失败: \(error.localizedDescription)")
        }

        if !fileManager.fileExists(atPath: runtimeScriptURL.path) {
            let bundledScript = try bundledAssetURL(fileName: Self.scriptFileName)
            do {
                try fileManager.copyItem(at: bundledScript, to: runtimeScriptURL)
            } catch {
                throw RandomForestModelServiceError.ioFailure("复制随机森林脚本失败: \(error.localizedDescription)")
            }
        }

        if modelCandidatesLocked().isEmpty {
            let bundledModel = try bundledAssetURL(fileName: Self.defaultModelFileName)
            let runtimeModel = runtimeDirectoryURL.appendingPathComponent(Self.defaultModelFileName, isDirectory: false)
            do {
                try fileManager.copyItem(at: bundledModel, to: runtimeModel)
            } catch {
                throw RandomForestModelServiceError.ioFailure("复制默认随机森林模型失败: \(error.localizedDescription)")
            }
        }
    }

    private func bundledAssetURL(fileName: String) throws -> URL {
        let name = (fileName as NSString).deletingPathExtension
        let ext = (fileName as NSString).pathExtension

        if let fromBundle = Bundle.main.url(
            forResource: name,
            withExtension: ext.isEmpty ? nil : ext,
            subdirectory: Self.bundleSubdirectory
        ) {
            return fromBundle
        }

        if let resourceBase = Bundle.main.resourceURL {
            let rootCandidate = resourceBase.appendingPathComponent(fileName, isDirectory: false)
            if fileManager.fileExists(atPath: rootCandidate.path) {
                return rootCandidate
            }
            let candidate = resourceBase
                .appendingPathComponent(Self.bundleSubdirectory, isDirectory: true)
                .appendingPathComponent(fileName, isDirectory: false)
            if fileManager.fileExists(atPath: candidate.path) {
                return candidate
            }
        }

        throw RandomForestModelServiceError.bundledAssetMissing(
            "应用资源缺少随机森林资产: \(fileName)"
        )
    }

    private func modelCandidatesLocked() -> [URL] {
        modelCandidates(in: runtimeDirectoryURL)
    }

    private func modelCandidates(in directory: URL) -> [URL] {
        guard let entries = try? fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }

        return entries
            .filter { $0.pathExtension.lowercased() == "joblib" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private func resolvedOutputFilePath(directory: URL, fileName: String) -> String? {
        let url = directory.appendingPathComponent(fileName, isDirectory: false)
        return fileManager.fileExists(atPath: url.path) ? url.path : nil
    }

    private func runPython(arguments: [String], commandRunner: CommandRunning) throws -> CommandResult {
        switch commandRunner.run(executable: "/usr/bin/python3", arguments: arguments) {
        case let .success(result):
            guard result.succeeded else {
                let output = [result.stdout, result.stderr]
                    .filter { !$0.isEmpty }
                    .joined(separator: "\n")
                throw RandomForestModelServiceError.commandFailed(
                    "执行随机森林脚本失败（exit=\(result.exitCode)）。\n\(output)"
                )
            }
            return result
        case let .failure(error):
            throw RandomForestModelServiceError.commandFailed(error.localizedDescription)
        }
    }

    private func decodePrediction(from stdout: String) -> RandomForestPredictionResult? {
        let decoder = JSONDecoder()

        for payload in jsonPayloadCandidates(from: stdout) {
            guard let data = payload.data(using: .utf8) else { continue }

            if let single = try? decoder.decode(RandomForestPredictionResult.self, from: data) {
                return single
            }

            if let summary = try? decoder.decode(PredictionSummaryEnvelope.self, from: data) {
                guard var selected = selectBestPrediction(from: summary.results) else {
                    continue
                }
                if selected.modelPath == nil {
                    selected.modelPath = summary.modelPath
                }
                return selected
            }
        }

        return nil
    }

    private func selectBestPrediction(from results: [RandomForestPredictionResult]) -> RandomForestPredictionResult? {
        let usable = results.filter { $0.error == nil && $0.hasUsablePrediction }
        if let best = usable.max(by: { lhs, rhs in
            let leftRank = predictionRiskRank(lhs)
            let rightRank = predictionRiskRank(rhs)
            if leftRank == rightRank {
                return lhs.safeProbMalicious < rhs.safeProbMalicious
            }
            return leftRank < rightRank
        }) {
            return best
        }
        return results.first(where: { $0.error == nil }) ?? results.first
    }

    private func predictionRiskRank(_ prediction: RandomForestPredictionResult) -> Int {
        let label = prediction.normalizedVerdictLabel
        switch label {
        case "malicious":
            return 500
        case "container_suspicious":
            return 420
        case "container_needs_deeper_inspection":
            return 360
        case "suspicious":
            return 320
        case "container_low_risk":
            return 180
        case "benign":
            return 80
        default:
            return 200
        }
    }

    private func jsonPayloadCandidates(from text: String) -> [String] {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }

        var candidates: [String] = [trimmed]
        guard let lastBrace = trimmed.lastIndex(of: "}") else {
            return candidates
        }

        var starts: [String.Index] = []
        for index in trimmed.indices where trimmed[index] == "{" {
            starts.append(index)
        }

        for index in starts.reversed().prefix(40) where index <= lastBrace {
            let payload = String(trimmed[index...lastBrace]).trimmingCharacters(in: .whitespacesAndNewlines)
            if payload.isEmpty {
                continue
            }
            if !candidates.contains(payload) {
                candidates.append(payload)
            }
        }

        return candidates
    }
}

private struct PredictionSummaryEnvelope: Decodable {
    var modelPath: String?
    var results: [RandomForestPredictionResult]

    enum CodingKeys: String, CodingKey {
        case modelPath = "model_path"
        case results
    }
}
