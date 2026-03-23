import Foundation

struct BenchmarkAnalysisOutput {
    var detectedType: String
    var score: Int
    var verdict: String
    var findings: [String]
    var summary: String?
    var riskFindings: [RiskRuleResult]
    var riskEvaluation: RiskEvaluation?
    var replayDebug: BenchmarkReplayDebugRecord?
}

final class BenchmarkRunner {
    enum RunnerError: LocalizedError {
        case invalidRoot(String)
        case exportFailure(String)

        var errorDescription: String? {
            switch self {
            case let .invalidRoot(message), let .exportFailure(message):
                return message
            }
        }
    }

    // TODO(benchmark): add VM-backed execution mode for higher-fidelity dynamic evaluation.
    // TODO(benchmark): add optional cloud intelligence enrichment comparison in developer tools.
    // TODO(benchmark): persist historical trend series for score/accuracy sparkline charts.
    private let fileManager = FileManager.default
    private let coordinator: AnalyzerCoordinator
    private let discoveryService: BenchmarkDiscoveryService
    private let replayAdapter: BenchmarkReplayAdapter
    private let diffEngine: BenchmarkDiffEngine

    init(
        coordinator: AnalyzerCoordinator = AnalyzerCoordinator(),
        discoveryService: BenchmarkDiscoveryService = BenchmarkDiscoveryService(),
        replayAdapter: BenchmarkReplayAdapter = BenchmarkReplayAdapter(),
        diffEngine: BenchmarkDiffEngine = BenchmarkDiffEngine()
    ) {
        self.coordinator = coordinator
        self.discoveryService = discoveryService
        self.replayAdapter = replayAdapter
        self.diffEngine = diffEngine
    }

    func discover(rootURL: URL) throws -> BenchmarkDiscoveryResult {
        try discoveryService.discover(rootURL: rootURL)
    }

    func run(
        rootURL: URL,
        language: AppLanguage,
        progress: @escaping @Sendable (BenchmarkRunnerProgress) -> Void
    ) async throws -> BenchmarkRunExecution {
        let standardizedRoot = rootURL.standardizedFileURL

        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: standardizedRoot.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw RunnerError.invalidRoot("Benchmark root directory is invalid: \(standardizedRoot.path)")
        }

        let rootScopeEnabled = standardizedRoot.startAccessingSecurityScopedResource()
        defer {
            if rootScopeEnabled {
                standardizedRoot.stopAccessingSecurityScopedResource()
            }
        }

        let discovery = try discoveryService.discover(rootURL: standardizedRoot)
        let discoveredSamples = discovery.samples.map { sample in
            BenchmarkDiscoveredSampleRecord(
                sampleID: sample.sampleID,
                relativePath: sample.relativePath,
                absolutePath: sample.absolutePath,
                group: sample.group,
                subtype: sample.subtype,
                fixtureKind: sample.fixtureKind,
                metadataPath: sample.metadataPath,
                isReplay: sample.sourceKind == .replayJSON,
                isDirectorySample: sample.isDirectorySample
            )
        }
        let previousRun = loadLatestRun(rootURL: standardizedRoot)
        let startedAt = Date()
        let runID = makeRunID(date: startedAt)

        let total = discovery.samples.count
        progress(
            BenchmarkRunnerProgress(
                totalSamples: total,
                completedSamples: 0,
                currentSampleID: nil,
                currentPath: nil,
                message: "benchmark_started"
            )
        )

        var results: [BenchmarkSampleResult] = []
        var errors: [BenchmarkRunnerErrorRecord] = []
        var scoringTraces: [BenchmarkScoringTraceEntry] = []
        var findingsTraces: [BenchmarkFindingsTraceEntry] = []
        var scoreCapTraces: [BenchmarkScoreCapTraceEntry] = []
        var contextTraces: [BenchmarkContextTraceEntry] = []
        var replayDebugRecords: [BenchmarkReplayDebugRecord] = []

        for (index, sample) in discovery.samples.enumerated() {
            if Task.isCancelled {
                throw CancellationError()
            }

            progress(
                BenchmarkRunnerProgress(
                    totalSamples: total,
                    completedSamples: index,
                    currentSampleID: sample.sampleID,
                    currentPath: sample.relativePath,
                    message: "analyzing"
                )
            )

            let sampleStart = Date()
            do {
                let output = try await analyze(sample: sample, language: language)
                let expectation = evaluateExpectation(
                    sample: sample,
                    actualVerdict: output.verdict,
                    score: output.score,
                    status: .completed
                )

                results.append(
                    BenchmarkSampleResult(
                        sampleID: sample.sampleID,
                        path: sample.relativePath,
                        group: sample.group,
                        subtype: sample.subtype,
                        fixtureKind: sample.fixtureKind,
                        detectedType: output.detectedType,
                        score: output.score,
                        verdict: normalizeVerdict(output.verdict),
                        findings: output.findings,
                        findingDeltas: toFindingDeltas(output.riskFindings),
                        analysisSummary: output.summary,
                        expectedVerdict: sample.expectation?.expectedVerdict,
                        expectedScoreRange: sample.expectation?.expectedScoreRange,
                        matchedVerdict: expectation.matchedVerdict,
                        matchedScoreRange: expectation.matchedScoreRange,
                        mismatchReason: expectation.mismatchReason,
                        analysisDurationMs: Int(max(0, Date().timeIntervalSince(sampleStart) * 1000)),
                        timestamp: Date(),
                        status: .completed,
                        errorMessage: nil,
                        errorCode: nil
                    )
                )

                if let replayDebug = output.replayDebug {
                    replayDebugRecords.append(replayDebug)
                }

                let staticTrace = output.riskEvaluation?.staticScoringTrace
                if let findingTrace = output.riskEvaluation?.findingsTrace, !findingTrace.isEmpty {
                    findingsTraces.append(
                        BenchmarkFindingsTraceEntry(
                            sampleID: sample.sampleID,
                            detectedType: output.detectedType,
                            findings: findingTrace
                        )
                    )
                }
                if let capTrace = output.riskEvaluation?.scoreCapTrace, !capTrace.isEmpty {
                    scoreCapTraces.append(
                        BenchmarkScoreCapTraceEntry(
                            sampleID: sample.sampleID,
                            detectedType: output.detectedType,
                            caps: capTrace
                        )
                    )
                }
                if let contextTrace = output.riskEvaluation?.contextTrace, !contextTrace.isEmpty {
                    contextTraces.append(
                        BenchmarkContextTraceEntry(
                            sampleID: sample.sampleID,
                            detectedType: output.detectedType,
                            adjustments: contextTrace
                        )
                    )
                }

                scoringTraces.append(
                    BenchmarkScoringTraceEntry(
                        sampleID: sample.sampleID,
                        detectedType: output.detectedType,
                        typeScorerUsed: staticTrace?.typeScorerUsed,
                        baseScore: staticTrace?.baseScore ?? 0,
                        findingDeltas: toFindingDeltas(output.riskFindings),
                        contextAdjustments: staticTrace?.contextAdjustments,
                        chainBonuses: staticTrace?.chainBonuses,
                        scoreCapsApplied: staticTrace?.scoreCapsApplied,
                        finalScore: output.score,
                        verdict: normalizeVerdict(output.verdict),
                        thresholdUsed: "suspicious>=30, malicious>=60",
                        notes: [
                            "group=\(sample.group)",
                            "subtype=\(sample.subtype)",
                            "status=completed",
                            staticTrace.map { "type_scorer=\($0.typeScorerUsed)" } ?? "type_scorer=none"
                        ]
                    )
                )
            } catch {
                let expectation = evaluateExpectation(
                    sample: sample,
                    actualVerdict: "unknown",
                    score: 0,
                    status: .failed
                )

                var message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                var errorCode: BenchmarkRunnerErrorCode? = .analysisFailed
                var errorDetails: [String: String] = [:]

                if sample.sourceKind == .replayJSON {
                    if let replayFailure = error as? BenchmarkReplayAdapter.ReplayFailure {
                        message = replayFailure.replayError.localizedDescription
                        errorCode = replayFailure.replayError.errorCode
                        replayDebugRecords.append(replayFailure.debugRecord)
                        errorDetails["replay_error"] = "\(replayFailure.replayError)"
                    } else if let replayError = error as? BenchmarkReplayAdapter.ReplayError {
                        message = replayError.localizedDescription
                        errorCode = replayError.errorCode
                    }
                }

                results.append(
                    BenchmarkSampleResult(
                        sampleID: sample.sampleID,
                        path: sample.relativePath,
                        group: sample.group,
                        subtype: sample.subtype,
                        fixtureKind: sample.fixtureKind,
                        detectedType: sample.subtype,
                        score: 0,
                        verdict: "unknown",
                        findings: [],
                        findingDeltas: [],
                        analysisSummary: nil,
                        expectedVerdict: sample.expectation?.expectedVerdict,
                        expectedScoreRange: sample.expectation?.expectedScoreRange,
                        matchedVerdict: expectation.matchedVerdict,
                        matchedScoreRange: expectation.matchedScoreRange,
                        mismatchReason: expectation.mismatchReason,
                        analysisDurationMs: Int(max(0, Date().timeIntervalSince(sampleStart) * 1000)),
                        timestamp: Date(),
                        status: .failed,
                        errorMessage: message,
                        errorCode: errorCode
                    )
                )

                errors.append(
                    BenchmarkRunnerErrorRecord(
                        sampleID: sample.sampleID,
                        path: sample.relativePath,
                        stage: sample.sourceKind == .replayJSON ? "replay_analysis" : "sample_analysis",
                        errorCode: errorCode,
                        message: message,
                        details: errorDetails.isEmpty ? nil : errorDetails,
                        timestamp: Date()
                    )
                )

                if sample.sourceKind == .replayJSON,
                   !replayDebugRecords.contains(where: { $0.sampleID == sample.sampleID }) {
                    replayDebugRecords.append(
                        BenchmarkReplayDebugRecord(
                            sampleID: sample.sampleID,
                            relativePath: sample.relativePath,
                            resolvedAbsolutePath: sample.absolutePath,
                            fileExists: fileManager.fileExists(atPath: sample.absolutePath),
                            fileSizeBytes: ((try? fileManager.attributesOfItem(atPath: sample.absolutePath))?[.size] as? NSNumber)?.int64Value,
                            readSucceeded: false,
                            decodeSucceeded: false,
                            eventCount: nil,
                            mappingSucceeded: false,
                            errorCode: errorCode,
                            finalError: message
                        )
                    )
                }

                scoringTraces.append(
                    BenchmarkScoringTraceEntry(
                        sampleID: sample.sampleID,
                        baseScore: 0,
                        findingDeltas: [],
                        finalScore: 0,
                        verdict: "unknown",
                        thresholdUsed: "suspicious>=30, malicious>=60",
                        notes: [
                            "group=\(sample.group)",
                            "subtype=\(sample.subtype)",
                            "status=failed",
                            "error=\(message)"
                        ]
                    )
                )
            }

            progress(
                BenchmarkRunnerProgress(
                    totalSamples: total,
                    completedSamples: index + 1,
                    currentSampleID: sample.sampleID,
                    currentPath: sample.relativePath,
                    message: "sample_completed"
                )
            )
        }

        let summary = buildSummary(results: results)

        var run = BenchmarkRun(
            schemaVersion: "1.2",
            runID: runID,
            benchmarkRootPath: standardizedRoot.path,
            startedAt: startedAt,
            finishedAt: Date(),
            discoveryWarnings: discovery.warnings,
            missingRequiredDirectories: discovery.missingRequiredDirectories,
            samples: discovery.samples,
            results: results,
            summary: summary,
            errors: errors,
            discoveredSamples: discoveredSamples,
            scoringTraces: scoringTraces,
            findingsTraces: findingsTraces,
            scoreCapTraces: scoreCapTraces,
            contextTraces: contextTraces,
            replayDebug: replayDebugRecords,
            exportBundle: nil,
            diffSummary: nil
        )

        run.diffSummary = diffEngine.generate(currentRun: run, previousRun: previousRun)

        let bundle = try writeArtifacts(run: run, rootURL: standardizedRoot)
        run.exportBundle = bundle
        try rewriteArtifacts(run: run, bundle: bundle)
        try writeLatestPointer(run: run, bundle: bundle, rootURL: standardizedRoot)

        progress(
            BenchmarkRunnerProgress(
                totalSamples: total,
                completedSamples: total,
                currentSampleID: nil,
                currentPath: nil,
                message: "benchmark_finished"
            )
        )

        return BenchmarkRunExecution(run: run, exportBundle: bundle)
    }

    func loadLatestRun(rootURL: URL) -> BenchmarkRun? {
        let standardizedRoot = rootURL.standardizedFileURL
        let resultsRoot = standardizedRoot.appendingPathComponent("results", isDirectory: true)
        let latestPointerURL = resultsRoot.appendingPathComponent("latest.json", isDirectory: false)

        if let pointerData = try? Data(contentsOf: latestPointerURL),
           let pointer = try? decoder().decode(BenchmarkLatestPointer.self, from: pointerData),
           let data = try? Data(contentsOf: URL(fileURLWithPath: pointer.rawResultsPath)),
           let run = try? decoder().decode(BenchmarkRun.self, from: data) {
            return run
        }

        guard let directories = try? fileManager.contentsOfDirectory(
            at: resultsRoot,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else {
            return nil
        }

        let runDirectories = directories
            .filter { url in
                let values = try? url.resourceValues(forKeys: [.isDirectoryKey])
                return values?.isDirectory == true
            }
            .sorted { $0.lastPathComponent > $1.lastPathComponent }

        for directory in runDirectories {
            let rawResultsURL = directory.appendingPathComponent("raw_results.json", isDirectory: false)
            guard let data = try? Data(contentsOf: rawResultsURL),
                  let run = try? decoder().decode(BenchmarkRun.self, from: data)
            else {
                continue
            }
            return run
        }

        return nil
    }

    func loadRecentRuns(rootURL: URL, limit: Int = 10) -> [BenchmarkRun] {
        let standardizedRoot = rootURL.standardizedFileURL
        let resultsRoot = standardizedRoot.appendingPathComponent("results", isDirectory: true)

        guard let directories = try? fileManager.contentsOfDirectory(
            at: resultsRoot,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }

        let runDirectories = directories
            .filter { url in
                let values = try? url.resourceValues(forKeys: [.isDirectoryKey])
                return values?.isDirectory == true
            }
            .sorted { $0.lastPathComponent > $1.lastPathComponent }

        var runs: [BenchmarkRun] = []
        for directory in runDirectories {
            if runs.count >= max(1, limit) {
                break
            }
            let rawResultsURL = directory.appendingPathComponent("raw_results.json", isDirectory: false)
            guard let data = try? Data(contentsOf: rawResultsURL),
                  let run = try? decoder().decode(BenchmarkRun.self, from: data)
            else {
                continue
            }
            runs.append(run)
        }

        return runs
    }

    func exportArtifacts(for run: BenchmarkRun, to destinationDirectory: URL) throws -> URL {
        guard let bundle = run.exportBundle else {
            throw RunnerError.exportFailure("Benchmark run has no export bundle metadata.")
        }

        var sourceFiles = [
            bundle.rawResultsPath,
            bundle.summaryJSONPath,
            bundle.samplesCSVPath,
            bundle.summaryMarkdownPath,
            bundle.errorsJSONPath
        ]

        if let diffJSONPath = bundle.diffJSONPath {
            sourceFiles.append(diffJSONPath)
        }
        if let diffMarkdownPath = bundle.diffMarkdownPath {
            sourceFiles.append(diffMarkdownPath)
        }
        if let discoveredSamplesPath = bundle.discoveredSamplesPath {
            sourceFiles.append(discoveredSamplesPath)
        }
        if let scoringTracePath = bundle.scoringTracePath {
            sourceFiles.append(scoringTracePath)
        }
        if let findingsTracePath = bundle.findingsTracePath {
            sourceFiles.append(findingsTracePath)
        }
        if let scoreCapTracePath = bundle.scoreCapTracePath {
            sourceFiles.append(scoreCapTracePath)
        }
        if let contextTracePath = bundle.contextTracePath {
            sourceFiles.append(contextTracePath)
        }
        if let replayDebugPath = bundle.replayDebugPath {
            sourceFiles.append(replayDebugPath)
        }

        let targetDirectory = destinationDirectory
            .appendingPathComponent("BeforeInstall-Benchmark-\(run.runID)", isDirectory: true)
        try fileManager.createDirectory(at: targetDirectory, withIntermediateDirectories: true)

        for sourcePath in sourceFiles {
            let sourceURL = URL(fileURLWithPath: sourcePath)
            let destinationURL = targetDirectory.appendingPathComponent(sourceURL.lastPathComponent, isDirectory: false)
            if fileManager.fileExists(atPath: destinationURL.path) {
                try fileManager.removeItem(at: destinationURL)
            }
            try fileManager.copyItem(at: sourceURL, to: destinationURL)
        }

        return targetDirectory
    }

    func exportArtifactPath(for run: BenchmarkRun, artifact: BenchmarkExportArtifact) -> String? {
        guard let bundle = run.exportBundle else {
            return nil
        }

        switch artifact {
        case .rawResults:
            return bundle.rawResultsPath
        case .summaryMarkdown:
            return bundle.summaryMarkdownPath
        case .samplesCSV:
            return bundle.samplesCSVPath
        case .diffMarkdown:
            return bundle.diffMarkdownPath
        case .scoringTrace:
            return bundle.scoringTracePath
        case .findingsTrace:
            return bundle.findingsTracePath
        case .scoreCapTrace:
            return bundle.scoreCapTracePath
        case .contextTrace:
            return bundle.contextTracePath
        }
    }

    private func analyze(sample: BenchmarkSample, language: AppLanguage) async throws -> BenchmarkAnalysisOutput {
        if sample.sourceKind == .replayJSON {
            let replayOutput = try replayAdapter.analyzeReplaySample(sample: sample, language: language)
            return BenchmarkAnalysisOutput(
                detectedType: replayOutput.detectedType,
                score: replayOutput.score,
                verdict: replayOutput.verdict,
                findings: replayOutput.findings,
                summary: "Replay evaluation: \(replayOutput.verdict) (score \(replayOutput.score))",
                riskFindings: replayOutput.riskFindings,
                riskEvaluation: nil,
                replayDebug: replayOutput.replayDebug
            )
        }

        let request = AnalysisRequest(
            mode: .staticOnly,
            depth: .quick,
            dynamicDurationSeconds: 20,
            language: language,
            allowNonAppDynamicExecution: false,
            preferBackgroundAppLaunch: true,
            manualDynamicInteraction: false
        )

        let result = await coordinator.analyze(
            fileURL: URL(fileURLWithPath: sample.absolutePath),
            request: request,
            stopToken: nil,
            progress: { _ in }
        )

        switch result {
        case let .success(report):
            return BenchmarkAnalysisOutput(
                detectedType: report.detectedType.rawValue,
                score: report.riskScore,
                verdict: report.finalVerdict.rawValue,
                findings: report.findings,
                summary: report.reasoningSummary,
                riskFindings: report.riskEvaluation?.allFindings ?? [],
                riskEvaluation: report.riskEvaluation,
                replayDebug: nil
            )
        case let .failure(error):
            throw error
        }
    }

    private func evaluateExpectation(
        sample: BenchmarkSample,
        actualVerdict: String,
        score: Int,
        status: BenchmarkSampleExecutionStatus
    ) -> (matchedVerdict: Bool?, matchedScoreRange: Bool?, mismatchReason: BenchmarkMismatchReason?) {
        let expectedVerdict = sample.expectation?.expectedVerdict
        let expectedRange = sample.expectation?.expectedScoreRange

        if status == .failed {
            return (
                matchedVerdict: expectedVerdict == nil ? nil : false,
                matchedScoreRange: expectedRange == nil ? nil : false,
                mismatchReason: .analysisFailed
            )
        }

        let normalizedActual = normalizeVerdict(actualVerdict)
        let matchedVerdict = expectedVerdict.map { normalizeVerdict($0) == normalizedActual }
        let matchedScoreRange = expectedRange.map { $0.contains(score: score) }

        let mismatch: BenchmarkMismatchReason?
        if expectedVerdict == nil, expectedRange == nil {
            mismatch = .expectationMissing
        } else if matchedVerdict == false, let expectedVerdict {
            mismatch = classifyVerdictMismatch(expected: expectedVerdict, actual: actualVerdict)
        } else if matchedScoreRange == false, let expectedRange {
            mismatch = score > expectedRange.max ? .scoreTooHigh : .scoreTooLow
        } else {
            mismatch = nil
        }

        return (matchedVerdict, matchedScoreRange, mismatch)
    }

    private func classifyVerdictMismatch(expected: String, actual: String) -> BenchmarkMismatchReason {
        let expectedLevel = verdictLevel(normalizeVerdict(expected))
        let actualLevel = verdictLevel(normalizeVerdict(actual))

        guard let expectedLevel, let actualLevel else {
            return normalizeVerdict(actual) == "unknown" ? .verdictTooLow : .verdictTooHigh
        }

        return actualLevel > expectedLevel ? .verdictTooHigh : .verdictTooLow
    }

    private func buildSummary(results: [BenchmarkSampleResult]) -> BenchmarkSummary {
        let totalSamples = results.count
        let analyzedSamples = results.filter { $0.status == .completed }.count
        let failedSamples = results.filter { $0.status == .failed }.count
        let effectiveCoverageRate = totalSamples == 0 ? 0 : Double(analyzedSamples) / Double(totalSamples)

        let analyzedScores = results.filter { $0.status == .completed }.map(\.score)
        let averageScore = analyzedScores.isEmpty ? 0 : Double(analyzedScores.reduce(0, +)) / Double(analyzedScores.count)
        let medianScore = computeMedian(values: analyzedScores)

        var cleanCount = 0
        var suspiciousCount = 0
        var maliciousCount = 0
        var unknownCount = 0

        var falsePositiveCount = 0
        var falseNegativeCount = 0
        var expectedNegativeCount = 0
        var expectedPositiveCount = 0

        var verdictMatchedCount = 0
        var verdictEligibleCount = 0

        var scoreRangeMatchedCount = 0
        var scoreRangeEligibleCount = 0

        var mismatchBreakdown: [String: Int] = [:]
        var confusionMatrix: [String: [String: Int]] = [:]
        var groupMetrics: [String: MutableGroupMetrics] = [:]

        var cleanAnalyzedCount = 0
        var cleanFalsePositive = 0
        var noisyAnalyzedCount = 0
        var noisyFalsePositive = 0
        var suspiciousAnalyzedCount = 0
        var suspiciousHitCount = 0
        var replayMaliciousTotal = 0
        var replayMaliciousAnalyzedCount = 0
        var replayMaliciousDetectedCount = 0

        for result in results {
            let actualVerdict = normalizeVerdict(result.verdict)
            switch actualVerdict {
            case "clean": cleanCount += 1
            case "suspicious": suspiciousCount += 1
            case "malicious": maliciousCount += 1
            default: unknownCount += 1
            }

            if let reason = result.mismatchReason {
                mismatchBreakdown[reason.rawValue, default: 0] += 1
            }

            let expectedVerdict = normalizeExpectedVerdict(result.expectedVerdict, group: result.group)
            confusionMatrix[expectedVerdict, default: [:]][actualVerdict, default: 0] += 1

            if expectedVerdict != "unknown" {
                verdictEligibleCount += 1
                if expectedVerdict == actualVerdict {
                    verdictMatchedCount += 1
                }
            }

            if let expectedRange = result.expectedScoreRange {
                scoreRangeEligibleCount += 1
                if expectedRange.contains(score: result.score), result.status == .completed {
                    scoreRangeMatchedCount += 1
                }
            }

            if expectedVerdict == "clean" {
                expectedNegativeCount += 1
                if actualVerdict == "suspicious" || actualVerdict == "malicious" {
                    falsePositiveCount += 1
                }
            } else if expectedVerdict == "suspicious" || expectedVerdict == "malicious" {
                expectedPositiveCount += 1
                if actualVerdict == "clean" || actualVerdict == "unknown" {
                    falseNegativeCount += 1
                }
            }

            if result.group == "clean", result.status == .completed {
                cleanAnalyzedCount += 1
                if actualVerdict == "suspicious" || actualVerdict == "malicious" {
                    cleanFalsePositive += 1
                }
            }
            if result.group == "noisy_benign", result.status == .completed {
                noisyAnalyzedCount += 1
                if actualVerdict == "suspicious" || actualVerdict == "malicious" {
                    noisyFalsePositive += 1
                }
            }
            if result.group == "suspicious", result.status == .completed {
                suspiciousAnalyzedCount += 1
                if actualVerdict == "suspicious" || actualVerdict == "malicious" {
                    suspiciousHitCount += 1
                }
            }
            if result.group == "replay_malicious", result.status == .completed {
                replayMaliciousAnalyzedCount += 1
                if actualVerdict == "suspicious" || actualVerdict == "malicious" {
                    replayMaliciousDetectedCount += 1
                }
            }
            if result.group == "replay_malicious" {
                replayMaliciousTotal += 1
            }

            var metric = groupMetrics[result.group] ?? MutableGroupMetrics()
            metric.total += 1
            if result.status == .failed {
                metric.failed += 1
            } else {
                metric.analyzed += 1
                metric.scoreTotal += result.score
                metric.scoreCount += 1
            }

            switch actualVerdict {
            case "clean": metric.clean += 1
            case "suspicious": metric.suspicious += 1
            case "malicious": metric.malicious += 1
            default: metric.unknown += 1
            }
            groupMetrics[result.group] = metric
        }

        var groupStats: [String: BenchmarkGroupSummary] = [:]
        for (group, metric) in groupMetrics {
            groupStats[group] = BenchmarkGroupSummary(
                total: metric.total,
                analyzed: metric.analyzed,
                failed: metric.failed,
                avgScore: metric.scoreCount == 0 ? 0 : Double(metric.scoreTotal) / Double(metric.scoreCount),
                clean: metric.clean,
                suspicious: metric.suspicious,
                malicious: metric.malicious,
                unknown: metric.unknown
            )
        }
        let groupAnalyzedRatio = groupStats.mapValues { summary in
            summary.total == 0 ? 0 : Double(summary.analyzed) / Double(summary.total)
        }

        let falsePositiveRate = expectedNegativeCount == 0 ? 0 : Double(falsePositiveCount) / Double(expectedNegativeCount)
        let falseNegativeRate = expectedPositiveCount == 0 ? 0 : Double(falseNegativeCount) / Double(expectedPositiveCount)
        let verdictAccuracy = verdictEligibleCount == 0 ? 0 : Double(verdictMatchedCount) / Double(verdictEligibleCount)
        let scoreRangeMatchRate = scoreRangeEligibleCount == 0 ? 0 : Double(scoreRangeMatchedCount) / Double(scoreRangeEligibleCount)

        let cleanFalsePositiveRate = cleanAnalyzedCount == 0 ? 0 : Double(cleanFalsePositive) / Double(cleanAnalyzedCount)
        let noisyBenignFalsePositiveRate = noisyAnalyzedCount == 0 ? 0 : Double(noisyFalsePositive) / Double(noisyAnalyzedCount)
        let suspiciousHitRate = suspiciousAnalyzedCount == 0 ? 0 : Double(suspiciousHitCount) / Double(suspiciousAnalyzedCount)
        let replayMaliciousDetectionRate = replayMaliciousAnalyzedCount == 0 ? 0 : Double(replayMaliciousDetectedCount) / Double(replayMaliciousAnalyzedCount)

        let monotonicity = buildMonotonicityHints(groupStats: groupStats)

        return BenchmarkSummary(
            totalSamples: totalSamples,
            analyzedSamples: analyzedSamples,
            failedSamples: failedSamples,
            effectiveCoverageRate: effectiveCoverageRate,
            averageScore: averageScore,
            medianScore: medianScore,
            cleanCount: cleanCount,
            suspiciousCount: suspiciousCount,
            maliciousCount: maliciousCount,
            unknownCount: unknownCount,
            falsePositiveCount: falsePositiveCount,
            falseNegativeCount: falseNegativeCount,
            falsePositiveRate: falsePositiveRate,
            falseNegativeRate: falseNegativeRate,
            verdictAccuracy: verdictAccuracy,
            scoreRangeMatchRate: scoreRangeMatchRate,
            cleanFalsePositiveRate: cleanFalsePositiveRate,
            noisyBenignFalsePositiveRate: noisyBenignFalsePositiveRate,
            suspiciousHitRate: suspiciousHitRate,
            replayMaliciousDetectionRate: replayMaliciousDetectionRate,
            replayMaliciousTotal: replayMaliciousTotal,
            replayMaliciousAnalyzed: replayMaliciousAnalyzedCount,
            replayMaliciousFailed: max(0, replayMaliciousTotal - replayMaliciousAnalyzedCount),
            replayMaliciousDetected: replayMaliciousDetectedCount,
            groupAnalyzedRatio: groupAnalyzedRatio,
            groupStats: groupStats,
            confusionMatrix: confusionMatrix,
            mismatchBreakdown: mismatchBreakdown,
            scoreMonotonicityHints: monotonicity.hints,
            isScoreMonotonic: monotonicity.isMonotonic
        )
    }

    private func buildMonotonicityHints(groupStats: [String: BenchmarkGroupSummary]) -> (hints: [String], isMonotonic: Bool) {
        var hints: [String] = []
        var violated = false

        let clean = groupStats["clean"]?.avgScore
        let noisy = groupStats["noisy_benign"]?.avgScore
        let suspicious = groupStats["suspicious"]?.avgScore
        let replayMalicious = groupStats["replay_malicious"]?.avgScore

        if let clean, let noisy, clean >= noisy {
            violated = true
            hints.append("clean_avg(\(format(clean))) should be lower than noisy_benign_avg(\(format(noisy))).")
        }
        if let noisy, let suspicious, noisy >= suspicious {
            violated = true
            hints.append("noisy_benign_avg(\(format(noisy))) should be lower than suspicious_avg(\(format(suspicious))).")
        }
        if let suspicious, let replayMalicious, suspicious >= replayMalicious {
            violated = true
            hints.append("suspicious_avg(\(format(suspicious))) should be lower than replay_malicious_avg(\(format(replayMalicious))).")
        }

        if clean == nil || noisy == nil || suspicious == nil || replayMalicious == nil {
            hints.append("Monotonicity check is partial because one or more groups have no analyzed samples.")
        }

        return (hints, !violated)
    }

    private func writeArtifacts(run: BenchmarkRun, rootURL: URL) throws -> BenchmarkExportBundle {
        let resultsRoot = rootURL.appendingPathComponent("results", isDirectory: true)
        try fileManager.createDirectory(at: resultsRoot, withIntermediateDirectories: true)

        let runDirectory = resultsRoot.appendingPathComponent(run.runID, isDirectory: true)
        try fileManager.createDirectory(at: runDirectory, withIntermediateDirectories: true)

        let rawResultsURL = runDirectory.appendingPathComponent("raw_results.json", isDirectory: false)
        let summaryURL = runDirectory.appendingPathComponent("summary.json", isDirectory: false)
        let samplesCSVURL = runDirectory.appendingPathComponent("samples.csv", isDirectory: false)
        let summaryMarkdownURL = runDirectory.appendingPathComponent("summary.md", isDirectory: false)
        let errorsURL = runDirectory.appendingPathComponent("errors.json", isDirectory: false)
        let discoveredSamplesURL = runDirectory.appendingPathComponent("discovered_samples.json", isDirectory: false)
        let scoringTraceURL = runDirectory.appendingPathComponent("scoring_trace.json", isDirectory: false)
        let findingsTraceURL = runDirectory.appendingPathComponent("findings_trace.json", isDirectory: false)
        let scoreCapTraceURL = runDirectory.appendingPathComponent("score_cap_trace.json", isDirectory: false)
        let contextTraceURL = runDirectory.appendingPathComponent("context_trace.json", isDirectory: false)
        let replayDebugURL = runDirectory.appendingPathComponent("replay_debug.json", isDirectory: false)
        let latestPointerURL = resultsRoot.appendingPathComponent("latest.json", isDirectory: false)
        let diffJSONURL = run.diffSummary == nil ? nil : runDirectory.appendingPathComponent("diff.json", isDirectory: false)
        let diffMarkdownURL = run.diffSummary == nil ? nil : runDirectory.appendingPathComponent("diff.md", isDirectory: false)

        let bundle = BenchmarkExportBundle(
            outputDirectoryPath: runDirectory.path,
            rawResultsPath: rawResultsURL.path,
            summaryJSONPath: summaryURL.path,
            samplesCSVPath: samplesCSVURL.path,
            summaryMarkdownPath: summaryMarkdownURL.path,
            errorsJSONPath: errorsURL.path,
            diffJSONPath: diffJSONURL?.path,
            diffMarkdownPath: diffMarkdownURL?.path,
            discoveredSamplesPath: discoveredSamplesURL.path,
            scoringTracePath: scoringTraceURL.path,
            findingsTracePath: findingsTraceURL.path,
            scoreCapTracePath: scoreCapTraceURL.path,
            contextTracePath: contextTraceURL.path,
            replayDebugPath: replayDebugURL.path,
            latestPointerPath: latestPointerURL.path
        )

        var persistedRun = run
        persistedRun.exportBundle = bundle

        try writeJSON(persistedRun, to: rawResultsURL)
        try writeJSON(BenchmarkSummaryPayload(run: persistedRun), to: summaryURL)
        try writeText(buildSamplesCSV(run: persistedRun), to: samplesCSVURL)
        try writeText(buildSummaryMarkdown(run: persistedRun), to: summaryMarkdownURL)
        try writeJSON(persistedRun.errors, to: errorsURL)
        try writeJSON(persistedRun.discoveredSamples ?? [], to: discoveredSamplesURL)
        try writeJSON(filteredScoringTrace(run: persistedRun), to: scoringTraceURL)
        try writeJSON(persistedRun.findingsTraces ?? [], to: findingsTraceURL)
        try writeJSON(persistedRun.scoreCapTraces ?? [], to: scoreCapTraceURL)
        try writeJSON(persistedRun.contextTraces ?? [], to: contextTraceURL)
        try writeJSON(persistedRun.replayDebug ?? [], to: replayDebugURL)

        if let diff = persistedRun.diffSummary,
           let diffJSONURL,
           let diffMarkdownURL {
            try writeJSON(diff, to: diffJSONURL)
            try writeText(diffEngine.buildMarkdown(diff: diff), to: diffMarkdownURL)
        }

        return bundle
    }

    private func rewriteArtifacts(run: BenchmarkRun, bundle: BenchmarkExportBundle) throws {
        try writeJSON(run, to: URL(fileURLWithPath: bundle.rawResultsPath))
        try writeJSON(BenchmarkSummaryPayload(run: run), to: URL(fileURLWithPath: bundle.summaryJSONPath))
        try writeText(buildSamplesCSV(run: run), to: URL(fileURLWithPath: bundle.samplesCSVPath))
        try writeText(buildSummaryMarkdown(run: run), to: URL(fileURLWithPath: bundle.summaryMarkdownPath))
        if let discoveredSamplesPath = bundle.discoveredSamplesPath {
            try writeJSON(run.discoveredSamples ?? [], to: URL(fileURLWithPath: discoveredSamplesPath))
        }
        if let scoringTracePath = bundle.scoringTracePath {
            try writeJSON(filteredScoringTrace(run: run), to: URL(fileURLWithPath: scoringTracePath))
        }
        if let findingsTracePath = bundle.findingsTracePath {
            try writeJSON(run.findingsTraces ?? [], to: URL(fileURLWithPath: findingsTracePath))
        }
        if let scoreCapTracePath = bundle.scoreCapTracePath {
            try writeJSON(run.scoreCapTraces ?? [], to: URL(fileURLWithPath: scoreCapTracePath))
        }
        if let contextTracePath = bundle.contextTracePath {
            try writeJSON(run.contextTraces ?? [], to: URL(fileURLWithPath: contextTracePath))
        }
        if let replayDebugPath = bundle.replayDebugPath {
            try writeJSON(run.replayDebug ?? [], to: URL(fileURLWithPath: replayDebugPath))
        }

        if let diff = run.diffSummary,
           let diffJSONPath = bundle.diffJSONPath,
           let diffMarkdownPath = bundle.diffMarkdownPath {
            try writeJSON(diff, to: URL(fileURLWithPath: diffJSONPath))
            try writeText(diffEngine.buildMarkdown(diff: diff), to: URL(fileURLWithPath: diffMarkdownPath))
        }
    }

    private func writeLatestPointer(run: BenchmarkRun, bundle: BenchmarkExportBundle, rootURL: URL) throws {
        let resultsRoot = rootURL.appendingPathComponent("results", isDirectory: true)
        let latestPointerURL = resultsRoot.appendingPathComponent("latest.json", isDirectory: false)
        let pointer = BenchmarkLatestPointer(
            runID: run.runID,
            runDirectoryPath: bundle.outputDirectoryPath,
            rawResultsPath: bundle.rawResultsPath,
            summaryJSONPath: bundle.summaryJSONPath,
            updatedAt: Date()
        )
        try writeJSON(pointer, to: latestPointerURL)
    }

    private func buildSamplesCSV(run: BenchmarkRun) -> String {
        let sampleMap = Dictionary(uniqueKeysWithValues: run.samples.map { ($0.sampleID, $0) })

        var rows: [String] = []
        rows.append("run_id,sample_id,group,subtype,fixture_kind,path,detected_type,score,verdict,expected_verdict,expected_score_min,expected_score_max,matched_verdict,matched_score_range,mismatch_reason,status,error_code,analysis_duration_ms,timestamp,has_findings,error,analysis_summary,finding_delta_total,findings")

        for result in run.results {
            let sample = sampleMap[result.sampleID]
            let row = [
                csvEscape(run.runID),
                csvEscape(result.sampleID),
                csvEscape(result.group),
                csvEscape(result.subtype ?? sample?.subtype ?? ""),
                csvEscape(result.fixtureKind ?? sample?.fixtureKind ?? ""),
                csvEscape(result.path),
                csvEscape(result.detectedType),
                csvEscape(String(result.score)),
                csvEscape(result.verdict),
                csvEscape(result.expectedVerdict ?? ""),
                csvEscape(result.expectedScoreRange.map { String($0.min) } ?? ""),
                csvEscape(result.expectedScoreRange.map { String($0.max) } ?? ""),
                csvEscape(result.matchedVerdict.map { $0 ? "true" : "false" } ?? ""),
                csvEscape(result.matchedScoreRange.map { $0 ? "true" : "false" } ?? ""),
                csvEscape(result.mismatchReason?.rawValue ?? ""),
                csvEscape(result.status.rawValue),
                csvEscape(result.errorCode?.rawValue ?? ""),
                csvEscape(String(result.analysisDurationMs)),
                csvEscape(iso8601(result.timestamp)),
                csvEscape(result.findings.isEmpty ? "false" : "true"),
                csvEscape(result.errorMessage ?? ""),
                csvEscape(result.analysisSummary ?? ""),
                csvEscape(String(result.findingDeltas?.reduce(0, { $0 + $1.scoreDelta }) ?? 0)),
                csvEscape(result.findings.joined(separator: " | "))
            ]
            rows.append(row.joined(separator: ","))
        }

        return rows.joined(separator: "\n")
    }

    private func buildSummaryMarkdown(run: BenchmarkRun) -> String {
        var lines: [String] = []
        lines.append("# Benchmark Evaluation Summary")
        lines.append("")
        lines.append("- Run ID: \(run.runID)")
        lines.append("- Benchmark Root: \(run.benchmarkRootPath)")
        lines.append("- Started: \(iso8601(run.startedAt))")
        lines.append("- Finished: \(iso8601(run.finishedAt))")
        lines.append("- Total Samples: \(run.summary.totalSamples)")
        lines.append("- Analyzed Samples: \(run.summary.analyzedSamples)")
        lines.append("- Failed Samples: \(run.summary.failedSamples)")
        lines.append("- Effective Coverage Rate: \(formatPercent(run.summary.effectiveCoverageRate)) (\(run.summary.analyzedSamples)/\(run.summary.totalSamples))")
        lines.append("- Average Score: \(format(run.summary.averageScore))")
        lines.append("- Median Score: \(format(run.summary.medianScore))")
        lines.append("- Verdict Accuracy: \(formatPercent(run.summary.verdictAccuracy)) (matched verdict / labeled samples)")
        lines.append("- Score Range Match Rate: \(formatPercent(run.summary.scoreRangeMatchRate)) (matched range / samples with expected range)")
        lines.append("- False Positive Rate: \(formatPercent(run.summary.falsePositiveRate)) (\(run.summary.falsePositiveCount)/expected_clean)")
        lines.append("- False Negative Rate: \(formatPercent(run.summary.falseNegativeRate)) (\(run.summary.falseNegativeCount)/expected_suspicious_or_malicious)")
        lines.append("- Clean FP Rate: \(formatPercent(run.summary.cleanFalsePositiveRate))")
        lines.append("- Noisy Benign FP Rate: \(formatPercent(run.summary.noisyBenignFalsePositiveRate))")
        lines.append("- Suspicious Hit Rate: \(formatPercent(run.summary.suspiciousHitRate))")
        lines.append("- Replay Malicious Detection Rate: \(formatPercent(run.summary.replayMaliciousDetectionRate))")
        lines.append("- Replay Malicious Detail: total=\(run.summary.replayMaliciousTotal), analyzed=\(run.summary.replayMaliciousAnalyzed), failed=\(run.summary.replayMaliciousFailed), detected=\(run.summary.replayMaliciousDetected)")

        lines.append("")
        lines.append("## Score Monotonicity")
        lines.append("- Monotonic: \(run.summary.isScoreMonotonic ? "yes" : "no")")
        if run.summary.scoreMonotonicityHints.isEmpty {
            lines.append("- No monotonicity warning.")
        } else {
            for hint in run.summary.scoreMonotonicityHints {
                lines.append("- \(hint)")
            }
        }

        if !run.missingRequiredDirectories.isEmpty {
            lines.append("")
            lines.append("## Missing Required Directories")
            for path in run.missingRequiredDirectories {
                lines.append("- \(path)")
            }
        }

        if !run.discoveryWarnings.isEmpty {
            lines.append("")
            lines.append("## Discovery Warnings")
            for warning in run.discoveryWarnings {
                lines.append("- \(warning)")
            }
        }

        lines.append("")
        lines.append("## Group Statistics")
        lines.append("| group | total | analyzed | failed | avg_score | clean | suspicious | malicious | unknown |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for group in run.summary.groupStats.keys.sorted() {
            guard let stats = run.summary.groupStats[group] else { continue }
            lines.append("| \(group) | \(stats.total) | \(stats.analyzed) | \(stats.failed) | \(format(stats.avgScore)) | \(stats.clean) | \(stats.suspicious) | \(stats.malicious) | \(stats.unknown) |")
        }

        lines.append("")
        lines.append("## Coverage Warnings")
        let lowCoverage = run.summary.groupAnalyzedRatio
            .filter { $0.value < 0.8 }
            .sorted { $0.key < $1.key }
        if lowCoverage.isEmpty {
            lines.append("- All groups have acceptable analyzed coverage.")
        } else {
            for (group, ratio) in lowCoverage {
                let analyzed = run.summary.groupStats[group]?.analyzed ?? 0
                let total = run.summary.groupStats[group]?.total ?? 0
                lines.append("- WARNING: \(group) coverage is \(formatPercent(ratio)) (\(analyzed)/\(total)).")
            }
        }

        lines.append("")
        lines.append("## Confusion Matrix")
        for expected in run.summary.confusionMatrix.keys.sorted() {
            let columns = run.summary.confusionMatrix[expected] ?? [:]
            let rendered = columns.keys.sorted().map { "\($0)=\(columns[$0] ?? 0)" }.joined(separator: ", ")
            lines.append("- expected=\(expected): \(rendered)")
        }

        let falsePositives = run.results.filter { result in
            (result.group == "clean" || result.group == "noisy_benign")
                && (normalizeVerdict(result.verdict) == "suspicious" || normalizeVerdict(result.verdict) == "malicious")
        }

        let falseNegatives = run.results.filter { result in
            result.group == "replay_malicious"
                && (normalizeVerdict(result.verdict) == "clean" || normalizeVerdict(result.verdict) == "unknown")
        }

        lines.append("")
        lines.append("## Major False Positives")
        if falsePositives.isEmpty {
            lines.append("- None")
        } else {
            for row in falsePositives.prefix(12) {
                lines.append("- \(row.sampleID) | group=\(row.group) | verdict=\(row.verdict) | score=\(row.score)")
            }
        }

        lines.append("")
        lines.append("## Major False Negatives")
        if falseNegatives.isEmpty {
            lines.append("- None")
        } else {
            for row in falseNegatives.prefix(12) {
                lines.append("- \(row.sampleID) | group=\(row.group) | verdict=\(row.verdict) | score=\(row.score)")
            }
        }

        if !run.errors.isEmpty {
            lines.append("")
            lines.append("## Errors")
            for error in run.errors {
                lines.append("- \(error.sampleID) | \(error.stage) | \(error.message)")
            }
        }

        return lines.joined(separator: "\n")
    }

    private func filteredScoringTrace(run: BenchmarkRun) -> [BenchmarkScoringTraceEntry] {
        guard let traces = run.scoringTraces else {
            return []
        }

        let resultByID = Dictionary(uniqueKeysWithValues: run.results.map { ($0.sampleID, $0) })
        return traces.filter { trace in
            guard let result = resultByID[trace.sampleID] else {
                return false
            }
            let verdict = normalizeVerdict(result.verdict)
            let isMismatch = result.matchedVerdict == false || result.matchedScoreRange == false || result.mismatchReason != nil
            let isReplay = result.group.hasPrefix("replay_")
            let isSuspiciousLike = verdict == "suspicious" || verdict == "malicious"
            return isMismatch || isReplay || isSuspiciousLike
        }
    }

    private func toFindingDeltas(_ findings: [RiskRuleResult]) -> [BenchmarkFindingDelta] {
        findings.map { finding in
            BenchmarkFindingDelta(
                ruleID: finding.id,
                severity: finding.severity,
                scoreDelta: finding.scoreDelta,
                category: finding.category,
                explanation: finding.explanation ?? finding.shortSummaryEN
            )
        }
    }

    private func makeRunID(date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH-mm-ss'Z'"
        let suffix = String(UUID().uuidString.prefix(6)).lowercased()
        return "\(formatter.string(from: date))-\(suffix)"
    }

    private func normalizeVerdict(_ value: String?) -> String {
        let normalized = value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? "unknown"
        switch normalized {
        case "clean", "benign", "benign_noisy", "allow", "low", "low_risk":
            return "clean"
        case "suspicious", "medium", "medium_risk", "caution":
            return "suspicious"
        case "malicious", "high", "high_risk", "highrisk", "critical":
            return "malicious"
        default:
            return "unknown"
        }
    }

    private func normalizeExpectedVerdict(_ expected: String?, group: String) -> String {
        if let expected {
            return normalizeVerdict(expected)
        }

        switch group {
        case "clean", "noisy_benign", "replay_clean":
            return "clean"
        case "suspicious", "replay_suspicious":
            return "suspicious"
        case "replay_malicious":
            return "malicious"
        default:
            return "unknown"
        }
    }

    private func verdictLevel(_ verdict: String) -> Int? {
        switch verdict {
        case "clean": return 0
        case "suspicious": return 1
        case "malicious": return 2
        default: return nil
        }
    }

    private func computeMedian(values: [Int]) -> Double {
        guard !values.isEmpty else {
            return 0
        }
        let sorted = values.sorted()
        let count = sorted.count
        if count % 2 == 1 {
            return Double(sorted[count / 2])
        }
        let lower = sorted[(count / 2) - 1]
        let upper = sorted[count / 2]
        return Double(lower + upper) / 2.0
    }

    private func format(_ value: Double) -> String {
        String(format: "%.2f", value)
    }

    private func formatPercent(_ value: Double) -> String {
        String(format: "%.2f%%", value * 100)
    }

    private func csvEscape(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "\"", with: "\"\"")
        return "\"\(escaped)\""
    }

    private func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    private func writeJSON<T: Encodable>(_ value: T, to url: URL) throws {
        let data = try encoder().encode(value)
        try data.write(to: url, options: .atomic)
    }

    private func writeText(_ text: String, to url: URL) throws {
        guard let data = text.data(using: .utf8) else {
            throw RunnerError.exportFailure("Unable to encode UTF-8 text for \(url.path)")
        }
        try data.write(to: url, options: .atomic)
    }

    private func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    private func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

private struct MutableGroupMetrics {
    var total = 0
    var analyzed = 0
    var failed = 0
    var scoreTotal = 0
    var scoreCount = 0
    var clean = 0
    var suspicious = 0
    var malicious = 0
    var unknown = 0
}

private struct BenchmarkSummaryPayload: Codable {
    var schemaVersion: String
    var runID: String
    var benchmarkRootPath: String
    var startedAt: Date
    var finishedAt: Date
    var summary: BenchmarkSummary
    var discoveryWarnings: [String]
    var missingRequiredDirectories: [String]
    var diffSummary: BenchmarkDiffSummary?

    init(run: BenchmarkRun) {
        schemaVersion = run.schemaVersion
        runID = run.runID
        benchmarkRootPath = run.benchmarkRootPath
        startedAt = run.startedAt
        finishedAt = run.finishedAt
        summary = run.summary
        discoveryWarnings = run.discoveryWarnings
        missingRequiredDirectories = run.missingRequiredDirectories
        diffSummary = run.diffSummary
    }
}

private struct BenchmarkLatestPointer: Codable {
    var runID: String
    var runDirectoryPath: String
    var rawResultsPath: String
    var summaryJSONPath: String
    var updatedAt: Date
}
