import Foundation

struct FullDiskScanProgressEvent: Sendable {
    var sessionID: String
    var stage: String
    var message: String
    var processed: Int
    var total: Int
    var currentPath: String?
    var discoveredCount: Int
    var selectedCount: Int
    var analyzedCount: Int
    var threatCount: Int
    var newThreat: ThreatRecord?
}

struct FullDiskScanRunResult: Sendable {
    var session: ScanSession
    var scanItemsByID: [String: ScanItem]
}

private struct FocusedAnalysisResult: Sendable {
    var item: ScanItem
    var report: Result<ScanReport, AnalysisCoordinatorError>
    var durationMs: Int
    var timedOut: Bool
}

private struct TimedAnalysisOutcome: Sendable {
    var report: Result<ScanReport, AnalysisCoordinatorError>
    var timedOut: Bool
}

private final class TimedAnalysisCompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false

    func finish(_ continuation: CheckedContinuation<TimedAnalysisOutcome, Never>, outcome: TimedAnalysisOutcome) {
        lock.lock()
        let shouldResume = !completed
        if shouldResume {
            completed = true
        }
        lock.unlock()
        if shouldResume {
            continuation.resume(returning: outcome)
        }
    }

    var isCompleted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return completed
    }
}

final class FullDiskScanOrchestrator: @unchecked Sendable {
    private let quickFocusedAnalysisTimeoutSeconds: TimeInterval = 15
    private let deepFocusedAnalysisTimeoutSeconds: TimeInterval = 45

    private let fileManager = FileManager.default
    private let planner: ScanScopePlanner
    private let enumerator: ScanEnumerator
    private let probe: LightweightFileProbe
    private let selector: CandidateSelector
    private let candidateFilter: CandidateFilter
    private let deduper: ScanDeduper
    private let coordinator: AnalyzerCoordinator
    private let aggregator: ThreatAggregator
    private let ignoreStore: IgnoreListStore
    private let historyStore: ScanHistoryStore
    private let performanceTraceStore: ScanPerformanceTraceStore

    init(
        planner: ScanScopePlanner = ScanScopePlanner(),
        enumerator: ScanEnumerator = ScanEnumerator(),
        probe: LightweightFileProbe = LightweightFileProbe(),
        selector: CandidateSelector = CandidateSelector(),
        candidateFilter: CandidateFilter = CandidateFilter(),
        deduper: ScanDeduper = ScanDeduper(),
        coordinator: AnalyzerCoordinator = AnalyzerCoordinator(),
        aggregator: ThreatAggregator = ThreatAggregator(),
        ignoreStore: IgnoreListStore = IgnoreListStore(),
        historyStore: ScanHistoryStore = ScanHistoryStore(),
        performanceTraceStore: ScanPerformanceTraceStore = ScanPerformanceTraceStore()
    ) {
        self.planner = planner
        self.enumerator = enumerator
        self.probe = probe
        self.selector = selector
        self.candidateFilter = candidateFilter
        self.deduper = deduper
        self.coordinator = coordinator
        self.aggregator = aggregator
        self.ignoreStore = ignoreStore
        self.historyStore = historyStore
        self.performanceTraceStore = performanceTraceStore
    }

    func run(
        mode: FullDiskScanMode,
        customFocusPaths: [String],
        includeExternalVolumes: Bool,
        maxConcurrentAnalyses: Int? = nil,
        language: AppLanguage,
        progress: @escaping @Sendable (FullDiskScanProgressEvent) -> Void,
        shouldCancel: @escaping @Sendable () -> Bool = { false }
    ) async -> FullDiskScanRunResult {
        let startedAt = Date()
        let sessionID = makeSessionID(startedAt: startedAt, mode: mode)
        var stageDurationsMs: [String: Int] = [:]

        let planStarted = Date()
        let plan = planner.makePlan(
            mode: mode,
            customFocusPaths: customFocusPaths,
            includeExternalVolumes: includeExternalVolumes
        )
        stageDurationsMs["plan"] = elapsedMs(since: planStarted)

        progress(
            makeProgress(
                sessionID: sessionID,
                stage: "plan",
                message: "Prepared scan plan (\(mode.rawValue)) with \(plan.roots.count) roots.",
                processed: 0,
                total: 0,
                currentPath: nil,
                discovered: 0,
                selected: 0,
                analyzed: 0,
                threatCount: 0
            )
        )
        if shouldCancel() || Task.isCancelled {
            return makeCancelledResult(
                sessionID: sessionID,
                mode: mode,
                startedAt: startedAt,
                plan: plan,
                message: "Scan cancelled before enumeration."
            )
        }

        let enumerationStarted = Date()
        let enumeration = enumerator.enumerate(
            plan: plan,
            shouldCancel: shouldCancel,
            progress: { [self] progressEvent in
                if shouldCancel() {
                    return
                }
                let runningTotal = max(progressEvent.visitedEntries, progressEvent.discoveredCandidates, 1)
                progress(
                    self.makeProgress(
                        sessionID: sessionID,
                        stage: "fast_discovery",
                        message: "Fast discovery: \(progressEvent.discoveredCandidates) candidate(s), visited \(progressEvent.visitedEntries) entries.",
                        processed: min(progressEvent.discoveredCandidates, runningTotal),
                        total: runningTotal,
                        currentPath: progressEvent.currentPath ?? progressEvent.rootPath,
                        discovered: progressEvent.discoveredCandidates,
                        selected: 0,
                        analyzed: 0,
                        threatCount: 0
                    )
                )
            }
        )
        stageDurationsMs["enumeration"] = elapsedMs(since: enumerationStarted)

        progress(
            makeProgress(
                sessionID: sessionID,
                stage: "fast_discovery",
                message: "Fast discovery completed: visited \(enumeration.visitedEntries) entries, discovered \(enumeration.candidates.count) raw objects.",
                processed: enumeration.candidates.count,
                total: max(1, enumeration.candidates.count),
                currentPath: nil,
                discovered: enumeration.candidates.count,
                selected: 0,
                analyzed: 0,
                threatCount: 0
            )
        )
        if shouldCancel() || Task.isCancelled {
            return makeCancelledResult(
                sessionID: sessionID,
                mode: mode,
                startedAt: startedAt,
                plan: plan,
                inaccessiblePaths: enumeration.inaccessiblePaths,
                message: "Scan cancelled during enumeration."
            )
        }

        let discoveryStarted = Date()
        let discovery = probe.discover(candidates: enumeration.candidates, mode: mode)
        stageDurationsMs["discovery"] = elapsedMs(since: discoveryStarted)

        let selectionStarted = Date()
        let selection = selector.select(candidates: discovery.candidates, mode: mode)
        stageDurationsMs["selection"] = elapsedMs(since: selectionStarted)

        progress(
            makeProgress(
                sessionID: sessionID,
                stage: "candidate_selection",
                message: "Fast discovery kept \(discovery.candidates.count) candidates; focused analysis queue \(selection.selected.count).",
                processed: selection.selected.count,
                total: discovery.candidates.count,
                currentPath: nil,
                discovered: discovery.candidates.count,
                selected: selection.selected.count,
                analyzed: 0,
                threatCount: 0
            )
        )
        if shouldCancel() || Task.isCancelled {
            return makeCancelledResult(
                sessionID: sessionID,
                mode: mode,
                startedAt: startedAt,
                plan: plan,
                inaccessiblePaths: enumeration.inaccessiblePaths,
                message: "Scan cancelled during candidate selection."
            )
        }

        let materializeStarted = Date()
        let selectedRaw = prioritize(candidates: selection.selected, prefixes: plan.prioritizedPathPrefixes).map { candidate in
            DiscoveredCandidate(
                path: candidate.path,
                isDirectory: candidate.isDirectory,
                size: candidate.size,
                modifiedAt: candidate.lastModifiedAt,
                isExecutable: candidate.isExecutable,
                sourceRoot: candidate.sourceRoot
            )
        }
        let materializedItems = candidateFilter.toScanItems(selectedRaw, mode: mode)
        let focusedItems = deduper.dedupe(materializedItems)
        stageDurationsMs["materialization"] = elapsedMs(since: materializeStarted)

        var scanItemsByID: [String: ScanItem] = [:]
        var threats: [ThreatRecord] = []
        var failedCount = 0
        var analyzedCount = 0
        var skippedCount = max(0, discovery.candidates.count - focusedItems.count) + discovery.skippedByType
        var analysisDurations: [ScanSlowAnalysisRecord] = []
        var analysisQueue: [ScanItem] = []
        let perItemTimeoutSeconds = focusedAnalysisTimeoutSeconds(for: mode)

        for item in focusedItems {
            scanItemsByID[item.itemID] = item
            let bundleIdentifier = resolveBundleIdentifierIfNeeded(path: item.path, type: item.detectedType)
            let ignored = ignoreStore.shouldIgnore(item: item, bundleIdentifier: bundleIdentifier)
            if ignored {
                skippedCount += 1
            } else {
                analysisQueue.append(item)
            }
        }

        let analysisStarted = Date()
        let defaultConcurrency = mode == .quick ? 6 : 2
        let concurrencyLimit = max(1, min(maxConcurrentAnalyses ?? defaultConcurrency, 16))
        var nextIndex = 0
        var processedCount = 0
        var cancelledByUser = false
        var timedOutCount = 0

        await withTaskGroup(of: FocusedAnalysisResult?.self) { group in
            func enqueueTask(for item: ScanItem) {
                group.addTask { [coordinator] in
                    if shouldCancel() || Task.isCancelled {
                        return nil
                    }
                    let request = AnalysisRequest(
                        mode: .staticOnly,
                        depth: mode == .quick ? .quick : .deep,
                        dynamicDurationSeconds: 20,
                        language: language,
                        allowNonAppDynamicExecution: false,
                        preferBackgroundAppLaunch: true,
                        manualDynamicInteraction: false
                    )

                    let started = Date()
                    let outcome = await Self.runTimedFocusedAnalysis(
                        coordinator: coordinator,
                        item: item,
                        request: request,
                        timeoutSeconds: perItemTimeoutSeconds,
                        shouldCancel: shouldCancel
                    )
                    if shouldCancel() || Task.isCancelled {
                        return nil
                    }
                    return FocusedAnalysisResult(
                        item: item,
                        report: outcome.report,
                        durationMs: Int(Date().timeIntervalSince(started) * 1000),
                        timedOut: outcome.timedOut
                    )
                }
            }

            let warmup = min(concurrencyLimit, analysisQueue.count)
            for _ in 0..<warmup {
                let item = analysisQueue[nextIndex]
                nextIndex += 1
                enqueueTask(for: item)
            }

            while let maybeUnit = await group.next() {
                if shouldCancel() || Task.isCancelled {
                    cancelledByUser = true
                    group.cancelAll()
                    break
                }
                guard let unit = maybeUnit else { continue }
                processedCount += 1
                analyzedCount += 1
                analysisDurations.append(
                    ScanSlowAnalysisRecord(
                        path: unit.item.path,
                        displayName: unit.item.displayName,
                        detectedType: unit.item.detectedType,
                        durationMs: unit.durationMs
                    )
                )

                if unit.timedOut {
                    timedOutCount += 1
                    failedCount += 1
                    progress(
                        makeProgress(
                            sessionID: sessionID,
                            stage: "focused_analysis",
                            message: "Analysis timed out for \(unit.item.displayName) (\(Int(perItemTimeoutSeconds))s). Skipped.",
                            processed: processedCount,
                            total: analysisQueue.count,
                            currentPath: unit.item.path,
                            discovered: discovery.candidates.count,
                            selected: analysisQueue.count,
                            analyzed: analyzedCount,
                            threatCount: threats.count
                        )
                    )
                    if shouldCancel() || Task.isCancelled {
                        cancelledByUser = true
                        group.cancelAll()
                        break
                    }
                    if nextIndex < analysisQueue.count {
                        let item = analysisQueue[nextIndex]
                        nextIndex += 1
                        enqueueTask(for: item)
                    }
                    continue
                }

                switch unit.report {
                case let .success(report):
                    if let threat = aggregator.makeThreatRecord(item: unit.item, report: report) {
                        threats.append(threat)
                        progress(
                            makeProgress(
                                sessionID: sessionID,
                                stage: "focused_analysis",
                                message: "Analyzing focused candidates: \(processedCount)/\(analysisQueue.count)",
                                processed: processedCount,
                                total: analysisQueue.count,
                                currentPath: unit.item.path,
                                discovered: discovery.candidates.count,
                                selected: analysisQueue.count,
                                analyzed: analyzedCount,
                                threatCount: threats.count,
                                newThreat: threat
                            )
                        )
                    } else {
                        progress(
                            makeProgress(
                                sessionID: sessionID,
                                stage: "focused_analysis",
                                message: "Analyzing focused candidates: \(processedCount)/\(analysisQueue.count)",
                                processed: processedCount,
                                total: analysisQueue.count,
                                currentPath: unit.item.path,
                                discovered: discovery.candidates.count,
                                selected: analysisQueue.count,
                                analyzed: analyzedCount,
                                threatCount: threats.count
                            )
                        )
                    }
                case .failure:
                    failedCount += 1
                    progress(
                        makeProgress(
                            sessionID: sessionID,
                            stage: "focused_analysis",
                            message: "Analysis failed for \(unit.item.displayName). Continuing...",
                            processed: processedCount,
                            total: analysisQueue.count,
                            currentPath: unit.item.path,
                            discovered: discovery.candidates.count,
                            selected: analysisQueue.count,
                            analyzed: analyzedCount,
                            threatCount: threats.count
                        )
                    )
                }

                if shouldCancel() || Task.isCancelled {
                    cancelledByUser = true
                    group.cancelAll()
                    break
                }

                if nextIndex < analysisQueue.count {
                    let item = analysisQueue[nextIndex]
                    nextIndex += 1
                    enqueueTask(for: item)
                }
            }

            if !cancelledByUser, shouldCancel() || Task.isCancelled {
                cancelledByUser = true
                group.cancelAll()
            }
        }
        stageDurationsMs["focused_analysis"] = elapsedMs(since: analysisStarted)

        if cancelledByUser {
            stageDurationsMs["total"] = elapsedMs(since: startedAt)
            let performanceTrace = buildPerformanceTrace(
                mode: mode,
                sessionID: sessionID,
                enumeration: enumeration,
                discovery: discovery,
                selection: selection,
                analyzedCount: analyzedCount,
                analysisDurations: analysisDurations,
                skippedCount: skippedCount,
                stageDurationsMs: stageDurationsMs,
                timedOutCount: timedOutCount,
                startedAt: startedAt
            )
            var notes = [
                "Scan cancelled by user.",
                "Quick mode uses two-stage strategy: fast discovery + focused analysis.",
                "Analysis executed via AnalyzerCoordinator.analyze(...) unified entry."
            ]
            if timedOutCount > 0 {
                notes.append("Focused analysis timeout triggered for \(timedOutCount) item(s).")
            }
            let cancelled = finalizeSession(
                sessionID: sessionID,
                mode: mode,
                startedAt: startedAt,
                plan: plan,
                itemsTotal: discovery.candidates.count,
                analyzedCount: analyzedCount,
                skippedCount: skippedCount,
                failedCount: failedCount,
                threats: threats,
                inaccessiblePaths: enumeration.inaccessiblePaths,
                scanItemsByID: scanItemsByID,
                notes: notes,
                performanceTrace: performanceTrace
            )
            progress(
                makeProgress(
                    sessionID: sessionID,
                    stage: "cancelled",
                    message: "Scan cancelled. \(analyzedCount) focused objects analyzed.",
                    processed: analyzedCount,
                    total: max(1, analysisQueue.count),
                    currentPath: nil,
                    discovered: discovery.candidates.count,
                    selected: analysisQueue.count,
                    analyzed: analyzedCount,
                    threatCount: threats.count
                )
            )
            return cancelled
        }

        stageDurationsMs["total"] = elapsedMs(since: startedAt)
        let performanceTrace = buildPerformanceTrace(
            mode: mode,
            sessionID: sessionID,
            enumeration: enumeration,
            discovery: discovery,
            selection: selection,
            analyzedCount: analyzedCount,
            analysisDurations: analysisDurations,
            skippedCount: skippedCount,
            stageDurationsMs: stageDurationsMs,
            timedOutCount: timedOutCount,
            startedAt: startedAt
        )

        var notes = [
            "Quick mode runs in two stages: fast discovery + focused analysis.",
            "Analysis executed via AnalyzerCoordinator.analyze(...) unified entry.",
            "Dynamic execution is disabled in full-disk scan."
        ]
        if timedOutCount > 0 {
            notes.append("Focused analysis timeout triggered for \(timedOutCount) item(s).")
        }
        let finished = finalizeSession(
            sessionID: sessionID,
            mode: mode,
            startedAt: startedAt,
            plan: plan,
            itemsTotal: discovery.candidates.count,
            analyzedCount: analyzedCount,
            skippedCount: skippedCount,
            failedCount: failedCount,
            threats: threats,
            inaccessiblePaths: enumeration.inaccessiblePaths,
            scanItemsByID: scanItemsByID,
            notes: notes,
            performanceTrace: performanceTrace
        )
        progress(
            makeProgress(
                sessionID: sessionID,
                stage: "completed",
                message: "Full disk scan completed. Threats: \(finished.session.summary.threatCount)",
                processed: analyzedCount,
                total: max(1, analysisQueue.count),
                currentPath: nil,
                discovered: discovery.candidates.count,
                selected: analysisQueue.count,
                analyzed: analyzedCount,
                threatCount: threats.count
            )
        )
        return finished
    }

    private func prioritize(candidates: [DiscoveryCandidate], prefixes: [String]) -> [DiscoveryCandidate] {
        let normalizedPrefixes = prefixes.map { $0.lowercased() }
        return candidates.sorted { lhs, rhs in
            let leftPriority = normalizedPrefixes.firstIndex(where: { lhs.path.lowercased().hasPrefix($0) }) ?? Int.max
            let rightPriority = normalizedPrefixes.firstIndex(where: { rhs.path.lowercased().hasPrefix($0) }) ?? Int.max
            if leftPriority != rightPriority {
                return leftPriority < rightPriority
            }
            if lhs.score != rhs.score {
                return lhs.score > rhs.score
            }
            return lhs.path < rhs.path
        }
    }

    private func riskOrder(_ level: RiskLevel) -> Int {
        switch level {
        case .critical: return 5
        case .high: return 4
        case .medium: return 3
        case .low: return 2
        case .info: return 1
        }
    }

    private func makeSessionID(startedAt: Date, mode: FullDiskScanMode) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return "fullscan-\(mode.rawValue)-\(formatter.string(from: startedAt))"
    }

    private func resolveBundleIdentifierIfNeeded(path: String, type: SupportedFileType) -> String? {
        guard type == .appBundle else { return nil }
        let appURL = URL(fileURLWithPath: path)
        guard fileManager.fileExists(atPath: appURL.path) else { return nil }
        let infoPlistURL = appURL.appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: infoPlistURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        else {
            return nil
        }
        return plist["CFBundleIdentifier"] as? String
    }

    private func finalizeSession(
        sessionID: String,
        mode: FullDiskScanMode,
        startedAt: Date,
        plan: ScanScopePlan,
        itemsTotal: Int,
        analyzedCount: Int,
        skippedCount: Int,
        failedCount: Int,
        threats: [ThreatRecord],
        inaccessiblePaths: [String],
        scanItemsByID: [String: ScanItem],
        notes: [String],
        performanceTrace: ScanPerformanceTrace?
    ) -> FullDiskScanRunResult {
        let summary = aggregator.buildSummary(threats: threats)
        let completedAt = Date()

        let session = ScanSession(
            sessionID: sessionID,
            mode: mode,
            startedAt: startedAt,
            completedAt: completedAt,
            rootScopes: plan.roots,
            totalCandidates: itemsTotal,
            analyzedCount: analyzedCount,
            skippedCount: skippedCount,
            failedCount: failedCount,
            summary: summary,
            threats: threats.sorted(by: { lhs, rhs in
                if lhs.riskLevel == rhs.riskLevel {
                    return lhs.path < rhs.path
                }
                return riskOrder(lhs.riskLevel) > riskOrder(rhs.riskLevel)
            }),
            inaccessiblePaths: inaccessiblePaths,
            notes: notes,
            performanceTrace: performanceTrace
        )

        _ = historyStore.append(session)
        return FullDiskScanRunResult(session: session, scanItemsByID: scanItemsByID)
    }

    private func makeCancelledResult(
        sessionID: String,
        mode: FullDiskScanMode,
        startedAt: Date,
        plan: ScanScopePlan,
        inaccessiblePaths: [String] = [],
        message: String
    ) -> FullDiskScanRunResult {
        let session = ScanSession(
            sessionID: sessionID,
            mode: mode,
            startedAt: startedAt,
            completedAt: Date(),
            rootScopes: plan.roots,
            totalCandidates: 0,
            analyzedCount: 0,
            skippedCount: 0,
            failedCount: 0,
            summary: ScanSummary(
                threatCount: 0,
                criticalCount: 0,
                highCount: 0,
                mediumCount: 0,
                lowCount: 0,
                infoCount: 0,
                persistenceCount: 0,
                quarantinedCount: 0,
                ignoredCount: 0
            ),
            threats: [],
            inaccessiblePaths: inaccessiblePaths,
            notes: [message],
            performanceTrace: nil
        )
        _ = historyStore.append(session)
        return FullDiskScanRunResult(session: session, scanItemsByID: [:])
    }

    private func buildPerformanceTrace(
        mode: FullDiskScanMode,
        sessionID: String,
        enumeration: ScanEnumerationOutput,
        discovery: DiscoveryPhaseOutput,
        selection: CandidateSelectionOutput,
        analyzedCount: Int,
        analysisDurations: [ScanSlowAnalysisRecord],
        skippedCount: Int,
        stageDurationsMs: [String: Int],
        timedOutCount: Int,
        startedAt: Date
    ) -> ScanPerformanceTrace {
        let totalPruned = enumeration.pruningStats.values.reduce(0, +)
        let avgDuration = analysisDurations.isEmpty
            ? 0
            : analysisDurations.reduce(0, { $0 + $1.durationMs }) / analysisDurations.count
        let slowest = Array(analysisDurations.sorted(by: { $0.durationMs > $1.durationMs }).prefix(12))

        var combinedSelectionStats = selection.stats
        for (key, value) in discovery.stats {
            combinedSelectionStats["discovery.\(key)"] = value
        }
        combinedSelectionStats["skipped.count"] = skippedCount
        combinedSelectionStats["analysis.timeout.count"] = timedOutCount
        combinedSelectionStats["analysis.timeout.seconds"] = Int(focusedAnalysisTimeoutSeconds(for: mode))

        var trace = ScanPerformanceTrace(
            mode: mode,
            totalEnumerated: enumeration.visitedEntries,
            totalCandidates: discovery.candidates.count,
            totalEscalated: selection.selected.count,
            totalAnalyzed: analyzedCount,
            skippedByPruning: totalPruned,
            skippedByType: discovery.skippedByType,
            avgAnalysisDurationMs: avgDuration,
            elapsedTimeMs: Int(Date().timeIntervalSince(startedAt) * 1000),
            directoryPruningStats: enumeration.pruningStats,
            candidateSelectionStats: combinedSelectionStats,
            stageDurationsMs: stageDurationsMs,
            slowestAnalyses: slowest,
            exportedTracePath: nil
        )
        if let url = performanceTraceStore.write(sessionID: sessionID, trace: trace) {
            trace.exportedTracePath = url.path
        }
        return trace
    }

    private func focusedAnalysisTimeoutSeconds(for mode: FullDiskScanMode) -> TimeInterval {
        mode == .quick ? quickFocusedAnalysisTimeoutSeconds : deepFocusedAnalysisTimeoutSeconds
    }

    private static func runTimedFocusedAnalysis(
        coordinator: AnalyzerCoordinator,
        item: ScanItem,
        request: AnalysisRequest,
        timeoutSeconds: TimeInterval,
        shouldCancel: @escaping @Sendable () -> Bool
    ) async -> TimedAnalysisOutcome {
        let worker = Task.detached(priority: .utility) {
            await coordinator.analyze(
                fileURL: URL(fileURLWithPath: item.path),
                request: request,
                stopToken: nil,
                progress: { _ in }
            )
        }

        return await withCheckedContinuation { continuation in
            let gate = TimedAnalysisCompletionGate()

            Task.detached(priority: .utility) {
                let report = await worker.value
                gate.finish(
                    continuation,
                    outcome: TimedAnalysisOutcome(report: report, timedOut: false)
                )
            }

            Task.detached(priority: .utility) {
                while !Task.isCancelled {
                    if gate.isCompleted {
                        return
                    }
                    if shouldCancel() {
                        worker.cancel()
                        gate.finish(
                            continuation,
                            outcome: TimedAnalysisOutcome(
                                report: .failure(.fileIssue("Focused analysis cancelled by user.")),
                                timedOut: false
                            )
                        )
                        return
                    }
                    try? await Task.sleep(nanoseconds: 150_000_000)
                }
            }

            Task.detached(priority: .utility) {
                let bounded = max(1, timeoutSeconds)
                let timeoutNanoseconds = UInt64(bounded * 1_000_000_000)
                try? await Task.sleep(nanoseconds: timeoutNanoseconds)
                worker.cancel()
                gate.finish(
                    continuation,
                    outcome: TimedAnalysisOutcome(
                        report: .failure(.fileIssue("Focused analysis timeout after \(Int(timeoutSeconds)) seconds.")),
                        timedOut: true
                    )
                )
            }
        }
    }

    private func makeProgress(
        sessionID: String,
        stage: String,
        message: String,
        processed: Int,
        total: Int,
        currentPath: String?,
        discovered: Int,
        selected: Int,
        analyzed: Int,
        threatCount: Int,
        newThreat: ThreatRecord? = nil
    ) -> FullDiskScanProgressEvent {
        FullDiskScanProgressEvent(
            sessionID: sessionID,
            stage: stage,
            message: message,
            processed: processed,
            total: total,
            currentPath: currentPath,
            discoveredCount: discovered,
            selectedCount: selected,
            analyzedCount: analyzed,
            threatCount: threatCount,
            newThreat: newThreat
        )
    }

    private func elapsedMs(since date: Date) -> Int {
        Int(Date().timeIntervalSince(date) * 1000)
    }
}
