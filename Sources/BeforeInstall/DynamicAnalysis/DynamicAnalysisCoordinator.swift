import Foundation

final class DynamicAnalysisCoordinator: DynamicAnalyzer, @unchecked Sendable {
    let analyzerName = "DynamicAnalysisCoordinator"
    private let commandRunner: CommandRunning
    private let isolatedRunner: IsolatedRunner
    private let processMonitor: ProcessMonitor
    private let fileMonitor: FileSystemMonitor
    private let networkMonitor: NetworkMonitor
    private let fileManager = FileManager.default

    init(commandRunner: CommandRunning) {
        self.commandRunner = commandRunner
        isolatedRunner = IsolatedRunner()
        processMonitor = ProcessMonitor(commandRunner: commandRunner)
        fileMonitor = FileSystemMonitor()
        networkMonitor = NetworkMonitor(commandRunner: commandRunner)
    }

    func analyze(
        fileURL: URL,
        basicInfo: FileBasicInfo,
        request: AnalysisRequest,
        stopToken: DynamicStopToken?,
        progress: @escaping @Sendable (DynamicProgressEvent) -> Void
    ) async -> DynamicAnalysisReport {
        var logs: [String] = []
        var warnings: [String] = []
        var suspiciousIndicators: [String] = []

        let timelineBuilder = TimelineBuilder()
        let processTreeBuilder = ProcessTreeBuilder()

        // Explicitly mark observation boundaries so downstream consumers understand visibility limits.
        let limitationNotes = [
            "This version is a restricted dynamic observation mode and not a full malware sandbox.",
            "macOS permission boundaries limit full visibility for system-wide process/file/network events.",
            "Dynamic conclusions only reflect behavior observed in this specific run window."
        ]

        let fallbackSources = [
            "Process snapshots from /bin/ps",
            "Open-file/network sampling from /usr/sbin/lsof",
            "Pre/post file snapshot diff from monitored paths"
        ]

        var session = DynamicAnalysisSession(
            sessionID: UUID().uuidString,
            samplePath: fileURL.path,
            startTime: Date(),
            endTime: nil,
            events: [],
            collectionBoundaries: limitationNotes,
            fallbackSources: fallbackSources
        )

        func log(_ message: String) {
            let line = "[\(timestampLabel())] \(message)"
            logs.append(line)
            progress(DynamicProgressEvent(message: line, timestamp: Date()))
        }

        func emitEvent(
            category: AnalysisEventCategory,
            processID: Int? = nil,
            parentProcessID: Int? = nil,
            processName: String? = nil,
            executablePath: String? = nil,
            action: String,
            target: String,
            details: [String: String] = [:],
            riskScoreDelta: Int = 0,
            rawSource: String
        ) {
            session.events.append(
                AnalysisEvent(
                    category: category,
                    processID: processID,
                    parentProcessID: parentProcessID,
                    processName: processName,
                    executablePath: executablePath,
                    action: action,
                    target: target,
                    details: details,
                    riskScoreDelta: riskScoreDelta,
                    rawSource: rawSource
                )
            )
        }

        emitEvent(
            category: .unknown,
            action: "analysis_started",
            target: fileURL.lastPathComponent,
            details: [
                "mode": request.mode.rawValue,
                "depth": request.depth.rawValue,
                "duration": String(request.dynamicDurationSeconds),
                "manualInteraction": String(request.manualDynamicInteraction)
            ],
            rawSource: "dynamic_coordinator"
        )
        log("Preparing isolated workspace...")

        let workspace: IsolatedWorkspace
        do {
            workspace = try isolatedRunner.prepareWorkspace()
        } catch {
            let message = "Workspace creation failed: \(error.localizedDescription)"
            warnings.append(message)
            emitEvent(
                category: .unknown,
                action: "workspace_prepare_failed",
                target: "workspace",
                details: ["error": error.localizedDescription],
                riskScoreDelta: 12,
                rawSource: "isolated_runner"
            )
            session.endTime = Date()
            session.events = timelineBuilder.build(events: session.events)
            let issues = FailureIssueClassifier.classify(warnings: warnings)
            return DynamicAnalysisReport(
                overview: DynamicRunOverview(
                    status: .failed,
                    launchSucceeded: false,
                    durationSeconds: request.dynamicDurationSeconds,
                    actualDuration: 0,
                    crashed: false,
                    mainProcessID: nil,
                    hasChildProcesses: false,
                    hasNetworkActivity: false,
                    hasFileWriteActivity: false,
                    hasPersistenceAttempt: false
                ),
                workspacePath: nil,
                limitationNotes: limitationNotes,
                dynamicResults: session,
                sessionLogs: logs,
                launchResult: nil,
                processObservations: [],
                fileObservations: [],
                networkObservations: [],
                networkRecords: [],
                networkSummary: nil,
                fileSystemDiff: nil,
                processTreeRoots: [],
                behaviorTimeline: timelineBuilder.buildLegacyTimeline(events: session.events),
                highRiskChains: [],
                suspiciousIndicators: [],
                summaryLines: ["Dynamic analysis failed before launch."],
                warnings: warnings,
                failureIssues: issues
            )
        }

        defer {
            isolatedRunner.cleanupWorkspace(workspace)
        }

        let monitoredPaths = fileMonitor.monitoredPaths(workspaceHome: workspace.homeURL.path)
        let preSnapshot = fileMonitor.captureSnapshot(paths: monitoredPaths)

        let launchTarget = resolveLaunchTarget(
            for: fileURL,
            detectedType: basicInfo.fileType,
            log: &logs,
            warnings: &warnings
        )
        let launchURL = launchTarget.url
        let launchType = launchTarget.type

        log("Launching target in restricted mode: \(launchURL.lastPathComponent)")
        emitEvent(
            category: .unknown,
            action: "launch_attempted",
            target: launchURL.lastPathComponent,
            details: ["detectedType": launchType.rawValue],
            rawSource: "runtime_launcher"
        )

        let launchContext = isolatedRunner.launch(
            fileURL: launchURL,
            detectedType: launchType,
            request: request,
            workspace: workspace
        )

        if let launch = launchContext.launchResult {
            emitEvent(
                category: .unknown,
                processID: launch.runningApplicationPID,
                processName: launchURL.lastPathComponent,
                action: "launch_result",
                target: launch.launchMode,
                details: [
                    "launchSucceeded": String(launch.launchSucceeded),
                    "hideAttempted": String(launch.hideAttempted),
                    "hideSucceeded": String(launch.hideSucceeded ?? false),
                    "foregroundLikely": String(launch.appLikelyActivatedForeground ?? false),
                    "windowLikely": String(launch.appLikelyDisplayedWindow ?? false)
                ],
                riskScoreDelta: (launch.appLikelyActivatedForeground == true || launch.appLikelyDisplayedWindow == true) ? 2 : 0,
                rawSource: "background_launch_service"
            )
        }

        if let warning = launchContext.result.warning {
            warnings.append(warning)
            log("Launch note: \(warning)")
            emitEvent(
                category: .unknown,
                action: "launch_warning",
                target: launchURL.lastPathComponent,
                details: ["warning": warning],
                riskScoreDelta: 3,
                rawSource: "runtime_launcher"
            )
        }

        guard launchContext.result.launchSucceeded, let rootPID = launchContext.result.mainPID else {
            emitEvent(
                category: .unknown,
                action: "launch_failed",
                target: launchURL.lastPathComponent,
                details: ["type": launchType.rawValue],
                riskScoreDelta: 15,
                rawSource: "runtime_launcher"
            )

            let postSnapshot = fileMonitor.captureSnapshot(paths: monitoredPaths)
            let diff = fileMonitor.diff(before: preSnapshot, after: postSnapshot)

            let fileObservations = makeFileObservations(
                created: diff.createdPaths,
                modified: diff.modifiedPaths,
                deleted: diff.deletedPaths,
                sampledOpenFiles: []
            )

            let now = Date()
            for file in fileObservations where file.operation != "read" {
                let category = eventCategory(forFileOperation: file.operation)
                emitEvent(
                    category: category,
                    action: "file_\(file.operation)",
                    target: file.path,
                    details: ["sensitive": String(file.isSensitivePath)],
                    riskScoreDelta: file.isSensitivePath ? 8 : 0,
                    rawSource: "filesystem_snapshot_diff"
                )

                if isPersistencePath(file.path) {
                    emitEvent(
                        category: .persistenceAttempt,
                        action: "persistence_path_touched",
                        target: file.path,
                        details: ["via": "launch_failed_diff"],
                        riskScoreDelta: 18,
                        rawSource: "filesystem_snapshot_diff"
                    )
                }
            }

            session.endTime = now
            session.events = timelineBuilder.build(events: session.events)

            let summary = [
                "Target was not executed in this run.",
                "Only pre/post snapshot evidence is available."
            ]

            let issues = FailureIssueClassifier.classify(warnings: warnings)
            return DynamicAnalysisReport(
                overview: DynamicRunOverview(
                    status: .failed,
                    launchSucceeded: false,
                    durationSeconds: request.dynamicDurationSeconds,
                    actualDuration: 0,
                    crashed: false,
                    mainProcessID: nil,
                    hasChildProcesses: false,
                    hasNetworkActivity: false,
                    hasFileWriteActivity: fileObservations.contains(where: { $0.operation == "create" || $0.operation == "modify" || $0.operation == "delete" }),
                    hasPersistenceAttempt: fileObservations.contains(where: { $0.isSensitivePath })
                ),
                workspacePath: workspace.rootURL.path,
                limitationNotes: limitationNotes,
                dynamicResults: session,
                sessionLogs: logs,
                launchResult: launchContext.launchResult,
                processObservations: [],
                fileObservations: fileObservations,
                networkObservations: [],
                networkRecords: [],
                networkSummary: nil,
                fileSystemDiff: FileSystemDiffResult(
                    added: diff.createdPaths,
                    modified: diff.modifiedPaths,
                    deleted: diff.deletedPaths,
                    records: diff.detailedRecords,
                    isIncomplete: diff.isIncomplete,
                    note: "Target did not start; only snapshot diff is available."
                ),
                processTreeRoots: [],
                behaviorTimeline: timelineBuilder.buildLegacyTimeline(events: session.events),
                highRiskChains: [],
                suspiciousIndicators: warnings,
                summaryLines: summary,
                warnings: warnings.uniquePreservingOrder(),
                failureIssues: issues
            )
        }

        log("Process started. PID=\(rootPID)")
        emitEvent(
            category: .processCreated,
            processID: rootPID,
            processName: launchURL.lastPathComponent,
            executablePath: launchURL.path,
            action: "main_process_started",
            target: "PID \(rootPID)",
            rawSource: "runtime_launcher"
        )

        let startedAt = Date()
        let duration = max(5, request.dynamicDurationSeconds)
        let pollingIntervalNanos: UInt64 = request.depth == .deep ? 1_000_000_000 : 2_000_000_000
        let enableAdvancedCorrelation = request.depth == .deep
        var processMap: [Int: ProcessObservation] = [:]
        var openFiles: Set<String> = []
        var networkMap: [String: NetworkObservation] = [:]
        var networkRecords: [NetworkConnectionRecord] = []
        var networkEventSeen = Set<String>()
        var interruptedByUser = false
        var mainProcessGone = false

        while true {
            try? await Task.sleep(nanoseconds: pollingIntervalNanos)

            let elapsed = Int(Date().timeIntervalSince(startedAt))
            let snapshot = processMonitor.snapshotProcesses()
            if !snapshot.contains(where: { $0.pid == rootPID }) {
                mainProcessGone = true
            }
            let descendants = processMonitor.descendantPIDs(rootPID: rootPID, from: snapshot)
            let now = Date()

            for process in snapshot where descendants.contains(process.pid) {
                if processMap[process.pid] == nil {
                    let command = process.commandLine.split(separator: " ").first.map(String.init) ?? process.commandLine
                    let processName = displayProcessName(commandLine: process.commandLine)
                    let execPath = command.hasPrefix("/") ? command : nil

                    processMap[process.pid] = ProcessObservation(
                        pid: process.pid,
                        ppid: process.ppid,
                        command: command,
                        arguments: process.commandLine,
                        executablePath: execPath,
                        firstSeenAt: now,
                        exitStatus: nil
                    )

                    emitEvent(
                        category: .processCreated,
                        processID: process.pid,
                        parentProcessID: process.ppid,
                        processName: processName,
                        executablePath: execPath,
                        action: process.pid == rootPID ? "main_process_snapshot_seen" : "child_process_discovered",
                        target: process.commandLine,
                        rawSource: "ps_snapshot"
                    )

                    let lower = process.commandLine.lowercased()
                    if process.pid != rootPID && isShellLikeCommand(lower) {
                        emitEvent(
                            category: .scriptExecuted,
                            processID: process.pid,
                            parentProcessID: process.ppid,
                            processName: processName,
                            executablePath: execPath,
                            action: "child_shell_spawned",
                            target: process.commandLine,
                            riskScoreDelta: 12,
                            rawSource: "ps_snapshot"
                        )
                    }

                    if lower.contains("curl") || lower.contains("wget") {
                        emitEvent(
                            category: .scriptExecuted,
                            processID: process.pid,
                            parentProcessID: process.ppid,
                            processName: processName,
                            executablePath: execPath,
                            action: "download_command_detected",
                            target: process.commandLine,
                            riskScoreDelta: 14,
                            rawSource: "ps_snapshot"
                        )
                    }

                    if lower.contains("chmod +x") && (lower.contains("&&") || lower.contains(";")) {
                        emitEvent(
                            category: .scriptExecuted,
                            processID: process.pid,
                            parentProcessID: process.ppid,
                            processName: processName,
                            executablePath: execPath,
                            action: "chmod_then_execute_pattern",
                            target: process.commandLine,
                            riskScoreDelta: 14,
                            rawSource: "ps_snapshot"
                        )
                    }

                    if lower.contains("mktemp") && (lower.contains("curl") || lower.contains("wget")) {
                        emitEvent(
                            category: .scriptExecuted,
                            processID: process.pid,
                            parentProcessID: process.ppid,
                            processName: processName,
                            executablePath: execPath,
                            action: "mktemp_download_chain",
                            target: process.commandLine,
                            riskScoreDelta: 16,
                            rawSource: "ps_snapshot"
                        )
                    }

                    if lower.contains("base64") && (lower.contains("| sh") || lower.contains("|bash") || lower.contains("eval")) {
                        emitEvent(
                            category: .scriptExecuted,
                            processID: process.pid,
                            parentProcessID: process.ppid,
                            processName: processName,
                            executablePath: execPath,
                            action: "base64_decode_execute_chain",
                            target: process.commandLine,
                            riskScoreDelta: 18,
                            rawSource: "ps_snapshot"
                        )
                    }

                    if lower.contains("launchctl load") || lower.contains("launchctl bootstrap") {
                        emitEvent(
                            category: .persistenceAttempt,
                            processID: process.pid,
                            parentProcessID: process.ppid,
                            processName: processName,
                            executablePath: execPath,
                            action: "launchctl_persistence_operation",
                            target: process.commandLine,
                            riskScoreDelta: 20,
                            rawSource: "ps_snapshot"
                        )
                    }

                    if lower.contains("rm -rf") && lower.contains("/") {
                        let sensitiveTarget = ["/system", "/library", "/users", "/private", "~/"]
                            .first(where: lower.contains)
                        if let sensitiveTarget {
                            emitEvent(
                                category: .privilegeRelatedAction,
                                processID: process.pid,
                                parentProcessID: process.ppid,
                                processName: processName,
                                executablePath: execPath,
                                action: "destructive_delete_sensitive_path",
                                target: sensitiveTarget,
                                details: ["command": process.commandLine],
                                riskScoreDelta: 24,
                                rawSource: "ps_snapshot"
                            )
                        }
                    }

                    if lower.contains("osascript -e") && lower.contains("do shell script") {
                        emitEvent(
                            category: .scriptExecuted,
                            processID: process.pid,
                            parentProcessID: process.ppid,
                            processName: processName,
                            executablePath: execPath,
                            action: "osascript_shell_bridge",
                            target: process.commandLine,
                            riskScoreDelta: 15,
                            rawSource: "ps_snapshot"
                        )
                    }

                    if lower.contains("launchagents") || lower.contains("launchdaemons") {
                        emitEvent(
                            category: .persistenceAttempt,
                            processID: process.pid,
                            parentProcessID: process.ppid,
                            processName: processName,
                            executablePath: execPath,
                            action: "launch_path_reference",
                            target: process.commandLine,
                            riskScoreDelta: 17,
                            rawSource: "ps_snapshot"
                        )
                    }

                    if lower.contains(".zshrc") || lower.contains(".bash_profile") || lower.contains(".bashrc") {
                        emitEvent(
                            category: .persistenceAttempt,
                            processID: process.pid,
                            parentProcessID: process.ppid,
                            processName: processName,
                            executablePath: execPath,
                            action: "shell_profile_modification_pattern",
                            target: process.commandLine,
                            riskScoreDelta: 12,
                            rawSource: "ps_snapshot"
                        )
                    }

                    if looksLikePrivilegeRelatedAction(lower) {
                        emitEvent(
                            category: .privilegeRelatedAction,
                            processID: process.pid,
                            parentProcessID: process.ppid,
                            processName: processName,
                            executablePath: execPath,
                            action: "privilege_related_command",
                            target: process.commandLine,
                            riskScoreDelta: 10,
                            rawSource: "ps_snapshot"
                        )
                    }
                }

                if isSIPBypassIndicator(process.commandLine) {
                    let signal = "Potential SIP bypass signal in process command: \(process.commandLine)"
                    suspiciousIndicators.append(signal)
                    emitEvent(
                        category: .privilegeRelatedAction,
                        processID: process.pid,
                        parentProcessID: process.ppid,
                        processName: displayProcessName(commandLine: process.commandLine),
                        action: "sip_or_integrity_bypass_indicator",
                        target: process.commandLine,
                        details: ["indicator": signal],
                        riskScoreDelta: 30,
                        rawSource: "heuristic"
                    )
                }
            }

            let activePIDs = descendants.isEmpty ? Set([rootPID]) : descendants
            let files = processMonitor.collectOpenFiles(for: activePIDs)
            files.forEach { openFiles.insert($0) }

            let netRecords = networkMonitor.collectConnectionRecords(for: activePIDs, timestamp: now)
            for record in netRecords {
                let aggregationKey = "\(record.protocolName)|\(record.destination)|\(record.port)"
                if var existing = networkMap[aggregationKey] {
                    existing.count += 1
                    existing.lastSeenAt = now
                    if existing.firstSeenAt == nil {
                        existing.firstSeenAt = now
                    }
                    networkMap[aggregationKey] = existing
                } else {
                    networkMap[aggregationKey] = NetworkObservation(
                        endpoint: record.destination,
                        port: record.port,
                        proto: record.protocolName,
                        count: 1,
                        firstSeenAt: now,
                        lastSeenAt: now
                    )
                }

                let eventKey = "\(record.processID)|\(aggregationKey)"
                if networkEventSeen.insert(eventKey).inserted {
                    networkRecords.append(record)
                    let risk = record.whetherRemote ? 6 : 1
                    emitEvent(
                        category: .networkConnect,
                        processID: record.processID,
                        processName: record.processName,
                        action: "network_connect",
                        target: "\(record.destination):\(record.port)",
                        details: [
                            "protocol": record.protocolName,
                            "remote": String(record.whetherRemote),
                            "dnsDomain": record.dnsDomain ?? ""
                        ],
                        riskScoreDelta: risk,
                        rawSource: "lsof_network"
                    )
                }
            }

            if request.manualDynamicInteraction {
                if stopToken?.shouldStop() == true {
                    interruptedByUser = true
                    log("User ended manual interaction.")
                    emitEvent(
                        category: .unknown,
                        processID: rootPID,
                        processName: launchURL.lastPathComponent,
                        action: "analysis_interrupted_by_user",
                        target: launchURL.lastPathComponent,
                        rawSource: "dynamic_stop_token"
                    )
                    break
                }
            } else {
                if request.depth == .quick, elapsed >= duration {
                    log("Quick dynamic duration reached (\(duration)s).")
                    break
                }

                if request.depth == .deep {
                    if stopToken?.shouldStop() == true {
                        interruptedByUser = true
                        log("User ended deep interaction.")
                        emitEvent(
                            category: .unknown,
                            processID: rootPID,
                            processName: launchURL.lastPathComponent,
                            action: "analysis_interrupted_by_user",
                            target: launchURL.lastPathComponent,
                            rawSource: "dynamic_stop_token"
                        )
                        break
                    }
                    if elapsed >= duration {
                        log("Deep dynamic duration reached (\(duration)s).")
                        break
                    }
                }
            }

            if let process = launchContext.process {
                if !process.isRunning {
                    log("Main process exited early.")
                    break
                }
            } else if mainProcessGone {
                log("Main app process exited early.")
                break
            }
        }

        var terminationSnapshot: ProcessTerminationSnapshot?
        if let process = launchContext.process {
            terminationSnapshot = isolatedRunner.terminateAndWait(process: process)
            if terminationSnapshot?.forcedKill == true {
                warnings.append("Target process did not exit gracefully and was force-killed after timeout.")
            }
        } else {
            terminationSnapshot = isolatedRunner.terminateAndWait(pid: Int32(rootPID))
        }

        let postSnapshot = fileMonitor.captureSnapshot(paths: monitoredPaths)
        let diff = fileMonitor.diff(before: preSnapshot, after: postSnapshot)

        var fileObservations = makeFileObservations(
            created: diff.createdPaths,
            modified: diff.modifiedPaths,
            deleted: diff.deletedPaths,
            sampledOpenFiles: Array(openFiles)
        )

        if fileObservations.isEmpty {
            fileObservations.append(FileObservation(path: launchURL.path, operation: "read", isSensitivePath: false, observedAt: Date()))
        }

        let fileDiffRecordLookup = Dictionary(
            uniqueKeysWithValues: diff.detailedRecords.map { record in
                ("\(record.changeType.rawValue)|\(record.path)", record)
            }
        )
        let isoFormatter = ISO8601DateFormatter()

        for file in fileObservations where file.operation != "read" {
            let category = eventCategory(forFileOperation: file.operation)
            let changeType = fileChangeType(forOperation: file.operation)
            let detailRecord = fileDiffRecordLookup["\(changeType.rawValue)|\(file.path)"]
            let sensitive = detailRecord?.whetherSensitivePath ?? file.isSensitivePath
            var details: [String: String] = [
                "sensitive": String(sensitive),
                "changeType": changeType.rawValue
            ]
            if let size = detailRecord?.fileSize {
                details["fileSize"] = String(size)
            }
            if let modifiedTime = detailRecord?.modifiedTime {
                details["modifiedTime"] = isoFormatter.string(from: modifiedTime)
            }
            if let hash = detailRecord?.hash {
                details["hash"] = hash
            }
            if let detectedType = detailRecord?.detectedType {
                details["detectedType"] = detectedType.rawValue
            }

            emitEvent(
                category: category,
                processID: rootPID,
                processName: launchURL.lastPathComponent,
                action: "file_\(file.operation)",
                target: file.path,
                details: details,
                riskScoreDelta: sensitive ? 8 : 0,
                rawSource: "filesystem_snapshot_diff"
            )

            if sensitive || isPersistencePath(file.path) {
                emitEvent(
                    category: .persistenceAttempt,
                    processID: rootPID,
                    processName: launchURL.lastPathComponent,
                    action: "persistence_path_touched",
                    target: file.path,
                    details: [
                        "operation": file.operation,
                        "detectedType": detailRecord?.detectedType.rawValue ?? SupportedFileType.unknown.rawValue
                    ],
                    riskScoreDelta: 18,
                    rawSource: "filesystem_snapshot_diff"
                )
            }

            if isShellProfilePath(file.path) {
                emitEvent(
                    category: .persistenceAttempt,
                    processID: rootPID,
                    processName: launchURL.lastPathComponent,
                    action: "shell_profile_modified",
                    target: file.path,
                    details: ["operation": file.operation],
                    riskScoreDelta: 14,
                    rawSource: "filesystem_snapshot_diff"
                )
            }
        }

        let processList = processMap.values.sorted { $0.firstSeenAt < $1.firstSeenAt }

        if enableAdvancedCorrelation {
            for file in fileObservations where file.operation == "create" && isTemporaryPath(file.path) {
                guard let observedAt = file.observedAt else { continue }
                if let matched = processList.first(where: {
                    $0.executablePath == file.path || $0.arguments.contains(file.path)
                }) {
                    let gap = abs(matched.firstSeenAt.timeIntervalSince(observedAt))
                    if gap <= 45 {
                        emitEvent(
                            category: .scriptExecuted,
                            processID: matched.pid,
                            parentProcessID: matched.ppid,
                            processName: displayProcessName(commandLine: matched.arguments),
                            executablePath: matched.executablePath,
                            action: "temp_file_created_then_executed",
                            target: file.path,
                            details: [
                                "process": matched.arguments,
                                "gapSeconds": String(Int(gap))
                            ],
                            riskScoreDelta: 22,
                            rawSource: "filesystem_diff_ps_correlation"
                        )
                    }
                }
            }
        }

        for file in fileObservations where isSIPBypassIndicator(file.path) {
            let signal = "Potential SIP bypass artifact path: \(file.path)"
            suspiciousIndicators.append(signal)
            emitEvent(
                category: .privilegeRelatedAction,
                processID: rootPID,
                processName: launchURL.lastPathComponent,
                action: "sip_or_integrity_artifact_path",
                target: file.path,
                details: ["indicator": signal],
                riskScoreDelta: 25,
                rawSource: "filesystem_snapshot_diff"
            )
        }

        suspiciousIndicators.append(contentsOf: detectAbnormalPatterns(
            processCount: processMap.count,
            fileCount: fileObservations.count,
            networkCount: networkMap.count
        ))

        let netList = Array(networkMap.values).sorted { $0.count > $1.count }
        let actualDuration = Date().timeIntervalSince(startedAt)
        let crashed = terminationSnapshot?.wasSignaled ?? false

        emitEvent(
            category: .processExited,
            processID: rootPID,
            processName: launchURL.lastPathComponent,
            action: "main_process_exited",
            target: "PID \(rootPID)",
            details: [
                "didExit": String(terminationSnapshot?.didExit ?? false),
                "forcedKill": String(terminationSnapshot?.forcedKill ?? false)
            ],
            riskScoreDelta: crashed ? 6 : 0,
            rawSource: "runtime_termination"
        )

        if crashed {
            suspiciousIndicators.append("Main process terminated by signal/forced kill.")
            emitEvent(
                category: .unknown,
                processID: rootPID,
                processName: launchURL.lastPathComponent,
                action: "process_crash_or_forced_kill",
                target: launchURL.lastPathComponent,
                riskScoreDelta: 6,
                rawSource: "runtime_termination"
            )
        }

        let status: DynamicStatus
        if interruptedByUser {
            status = .interrupted
        } else if !processList.dropFirst().isEmpty || !netList.isEmpty || fileObservations.contains(where: { $0.operation != "read" }) {
            status = .completed
        } else {
            status = .noObservableActivity
        }

        let overview = DynamicRunOverview(
            status: status,
            launchSucceeded: true,
            durationSeconds: request.manualDynamicInteraction ? Int(actualDuration.rounded()) : request.dynamicDurationSeconds,
            actualDuration: actualDuration,
            crashed: crashed,
            mainProcessID: rootPID,
            hasChildProcesses: processList.count > 1,
            hasNetworkActivity: !netList.isEmpty,
            hasFileWriteActivity: fileObservations.contains(where: { $0.operation == "create" || $0.operation == "modify" || $0.operation == "delete" }),
            hasPersistenceAttempt: diff.detailedRecords.contains(where: { $0.whetherSensitivePath || isPersistencePath($0.path) })
        )

        emitEvent(
            category: .unknown,
            processID: rootPID,
            processName: launchURL.lastPathComponent,
            action: "analysis_finished",
            target: launchURL.lastPathComponent,
            rawSource: "dynamic_coordinator"
        )

        session.endTime = Date()
        session.events = timelineBuilder.build(events: session.events)
        var highRiskChains: [String]
        if request.depth == .deep {
            highRiskChains = buildHighRiskChains(
                sampleName: launchURL.lastPathComponent,
                events: session.events
            )
        } else {
            highRiskChains = []
        }
        let networkSummary = buildNetworkSummary(
            records: networkRecords,
            sessionStart: session.startTime,
            events: session.events
        )
        if let networkSummary, !networkSummary.highlights.isEmpty {
            highRiskChains.append(contentsOf: networkSummary.highlights)
            suspiciousIndicators.append(contentsOf: networkSummary.highlights)
        }
        highRiskChains = highRiskChains.uniquePreservingOrder()

        let processTree = processTreeBuilder.build(
            rootProcessID: rootPID,
            events: session.events,
            processObservations: processList
        )
        let summary = buildSummary(
            overview: overview,
            suspiciousIndicators: suspiciousIndicators,
            session: session,
            highRiskChains: highRiskChains,
            networkSummary: networkSummary
        )

        suspiciousIndicators = suspiciousIndicators.uniquePreservingOrder()
        let issues = FailureIssueClassifier.classify(warnings: warnings)

        return DynamicAnalysisReport(
            overview: overview,
            workspacePath: workspace.rootURL.path,
            limitationNotes: limitationNotes,
            dynamicResults: session,
            sessionLogs: logs,
            launchResult: launchContext.launchResult,
            processObservations: processList,
            fileObservations: fileObservations,
            networkObservations: netList,
            networkRecords: networkRecords.sorted { $0.timestamp < $1.timestamp },
            networkSummary: networkSummary,
            fileSystemDiff: FileSystemDiffResult(
                added: diff.createdPaths,
                modified: diff.modifiedPaths,
                deleted: diff.deletedPaths,
                records: diff.detailedRecords,
                isIncomplete: diff.isIncomplete,
                note: diff.isIncomplete ? "Snapshot diff is incomplete due permission/system limitations." : nil
            ),
            processTreeRoots: processTree,
            behaviorTimeline: timelineBuilder.buildLegacyTimeline(events: session.events),
            highRiskChains: highRiskChains,
            suspiciousIndicators: suspiciousIndicators,
            summaryLines: summary,
            warnings: warnings.uniquePreservingOrder(),
            failureIssues: issues
        )
    }

    func cleanupTemporaryWorkspaces() -> Int {
        isolatedRunner.cleanupAllWorkspaces()
    }

    private func resolveLaunchTarget(
        for fileURL: URL,
        detectedType: SupportedFileType,
        log: inout [String],
        warnings: inout [String]
    ) -> (url: URL, type: SupportedFileType) {
        if detectedType == .dmg,
           let target = firstAppInDMG(fileURL: fileURL)
        {
            log.append("Resolved app from dmg: \(target.path)")
            return (target, .appBundle)
        }

        if detectedType == .pkg {
            warnings.append("Direct execution for pkg is intentionally skipped in dynamic mode v1.")
            return (fileURL, .pkg)
        }

        return (fileURL, detectedType)
    }

    private func firstAppInDMG(fileURL: URL) -> URL? {
        let attach = commandRunner.run(
            executable: "/usr/bin/hdiutil",
            arguments: ["attach", "-readonly", "-nobrowse", "-noautoopen", "-plist", fileURL.path]
        )
        guard case let .success(result) = attach,
              let mountPoint = parseMountPoint(fromPlistText: result.stdout)
        else {
            return nil
        }

        defer {
            _ = commandRunner.run(executable: "/usr/bin/hdiutil", arguments: ["detach", mountPoint, "-force"])
        }

        let root = URL(fileURLWithPath: mountPoint)
        guard let enumerator = fileManager.enumerator(at: root, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else {
            return nil
        }

        let baseDepth = root.pathComponents.count
        for case let url as URL in enumerator {
            let depth = url.pathComponents.count - baseDepth
            if depth > 4 {
                enumerator.skipDescendants()
                continue
            }
            if url.pathExtension.lowercased() == "app" {
                return url
            }
        }

        return nil
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

    private func makeFileObservations(
        created: [String],
        modified: [String],
        deleted: [String],
        sampledOpenFiles: [String]
    ) -> [FileObservation] {
        var observations: [FileObservation] = []

        observations.append(contentsOf: created.map {
            FileObservation(path: $0, operation: "create", isSensitivePath: isSensitivePath($0), observedAt: Date())
        })

        observations.append(contentsOf: modified.map {
            FileObservation(path: $0, operation: "modify", isSensitivePath: isSensitivePath($0), observedAt: Date())
        })

        observations.append(contentsOf: deleted.map {
            FileObservation(path: $0, operation: "delete", isSensitivePath: isSensitivePath($0), observedAt: Date())
        })

        let sampledReads = sampledOpenFiles
            .prefix(80)
            .map { FileObservation(path: $0, operation: "read", isSensitivePath: isSensitivePath($0), observedAt: Date()) }

        observations.append(contentsOf: sampledReads)
        return observations.uniqueByPathAndOperation().sorted { $0.path < $1.path }
    }

    private func isSensitivePath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        let home = FileManager.default.homeDirectoryForCurrentUser.path.lowercased()
        let requiredSensitivePaths = [
            "\(home)/library/launchagents",
            "/library/launchagents",
            "/library/launchdaemons",
            "\(home)/library/application support",
            "\(home)/library/preferences",
            "\(home)/.zshrc",
            "\(home)/.bash_profile",
            "/tmp",
            "/private/tmp"
        ]
        return requiredSensitivePaths.contains { normalized.hasPrefix($0) || normalized == $0 }
    }

    private func isPersistencePath(_ path: String) -> Bool {
        let lower = path.lowercased()
        let markers = [
            "launchagents",
            "launchdaemons",
            "~/library/launchagents",
            "/library/launchagents",
            "/library/launchdaemons",
            "loginitems",
            ".zshrc",
            ".bash_profile",
            ".bashrc"
        ]
        return markers.contains { lower.contains($0) }
    }

    private func isShellProfilePath(_ path: String) -> Bool {
        let lower = path.lowercased()
        return lower.hasSuffix("/.zshrc")
            || lower.hasSuffix("/.bash_profile")
            || lower.hasSuffix("/.bashrc")
            || lower.hasSuffix("/.profile")
    }

    private func displayProcessName(commandLine: String) -> String {
        let token = commandLine.split(separator: " ").first.map(String.init) ?? commandLine
        return URL(fileURLWithPath: token).lastPathComponent
    }

    private func isShellLikeCommand(_ lowerCommandLine: String) -> Bool {
        let markers = ["/bin/sh", "/bin/bash", "/bin/zsh", " sh ", "bash ", "zsh "]
        return markers.contains { lowerCommandLine.contains($0) }
    }

    private func looksLikePrivilegeRelatedAction(_ lowerCommandLine: String) -> Bool {
        let markers = [
            "sudo ",
            "authorizationexecutewithprivileges",
            "osascript",
            "system settings",
            "systempreferences",
            "x-apple.systempreferences",
            "tccutil",
            "security authorizationdb",
            "launchctl asuser"
        ]
        return markers.contains { lowerCommandLine.contains($0) }
    }

    private func isTemporaryPath(_ path: String) -> Bool {
        let lower = path.lowercased()
        return lower.hasPrefix("/tmp/") || lower.hasPrefix("/private/tmp/")
    }

    private func eventCategory(forFileOperation operation: String) -> AnalysisEventCategory {
        switch operation {
        case "create":
            return .fileCreated
        case "modify":
            return .fileModified
        case "delete":
            return .fileDeleted
        default:
            return .unknown
        }
    }

    private func fileChangeType(forOperation operation: String) -> FileSystemChangeType {
        switch operation {
        case "create":
            return .added
        case "modify":
            return .modified
        case "delete":
            return .deleted
        default:
            return .modified
        }
    }

    private func isSIPBypassIndicator(_ text: String) -> Bool {
        let lower = text.lowercased()
        let patterns = [
            "csrutil disable",
            "authenticated-root disable",
            "amfi_get_out_of_my_way",
            "nvram boot-args",
            "mount -uw /",
            "launchdaemon",
            "kmutil",
            "task_for_pid",
            "system integrity protection",
            "tccutil reset all"
        ]
        return patterns.contains { lower.contains($0) }
    }

    private func detectAbnormalPatterns(processCount: Int, fileCount: Int, networkCount: Int) -> [String] {
        var findings: [String] = []
        if processCount >= 10 {
            findings.append("A high number of child processes were observed in a short interval.")
        }
        if fileCount >= 80 {
            findings.append("A high number of file operations were observed in the session window.")
        }
        if networkCount >= 8 {
            findings.append("Frequent network endpoints were observed in a short interval.")
        }
        return findings
    }

    private func buildNetworkSummary(
        records: [NetworkConnectionRecord],
        sessionStart: Date,
        events: [AnalysisEvent]
    ) -> NetworkSummary? {
        guard !records.isEmpty else {
            return nil
        }

        let remoteRecords = records.filter(\.whetherRemote)
        let uniqueDestinations = Set(records.map { "\($0.destination):\($0.port)" })
        let uniqueRemoteIPs = Set(remoteRecords.compactMap(\.destinationIP))
        let firstConnectionAt = records.min(by: { $0.timestamp < $1.timestamp })?.timestamp

        var highlights: [String] = []
        if let firstConnectionAt,
           let firstRemote = remoteRecords.min(by: { $0.timestamp < $1.timestamp }),
           firstConnectionAt.timeIntervalSince(sessionStart) <= 4
        {
            highlights.append("Early outbound connection shortly after start: \(firstRemote.destination):\(firstRemote.port).")
        }

        if uniqueRemoteIPs.count >= 3 {
            highlights.append("Connected to multiple remote IPs in one session (\(uniqueRemoteIPs.count)).")
        }

        let downloadEvents = events.filter { event in
            event.category == .scriptExecuted && (
                event.action.contains("download")
                    || event.action == "mktemp_download_chain"
                    || event.action == "base64_decode_execute_chain"
            )
        }

        if remoteRecords.contains(where: { record in
            downloadEvents.contains(where: { abs(record.timestamp.timeIntervalSince($0.timestamp)) <= 20 })
        }) {
            highlights.append("Remote connection happened near a download-execute chain.")
        }

        let persistenceEvents = events.filter { $0.category == .persistenceAttempt }
        if remoteRecords.contains(where: { record in
            persistenceEvents.contains(where: { abs(record.timestamp.timeIntervalSince($0.timestamp)) <= 30 })
        }) {
            highlights.append("Remote connection occurred around persistence actions.")
        }

        return NetworkSummary(
            totalConnections: records.count,
            remoteConnections: remoteRecords.count,
            uniqueDestinations: uniqueDestinations.sorted(),
            uniqueRemoteIPs: uniqueRemoteIPs.sorted(),
            firstConnectionAt: firstConnectionAt,
            highlights: highlights.uniquePreservingOrder(),
            collectionNotes: [
                "Best-effort metadata from lsof snapshots.",
                "Encrypted payload/content inspection is not available in current mode."
            ]
        )
    }

    private func buildHighRiskChains(sampleName: String, events: [AnalysisEvent]) -> [String] {
        let sorted = events.sorted { $0.timestamp < $1.timestamp }
        var chains: [String] = []

        for script in sorted where script.category == .scriptExecuted {
            guard let network = sorted.first(where: {
                $0.category == .networkConnect
                    && $0.timestamp >= script.timestamp
                    && $0.timestamp.timeIntervalSince(script.timestamp) <= 25
            }) else {
                continue
            }

            let tempFile = sorted.first(where: {
                ($0.category == .fileCreated || $0.category == .fileModified)
                    && ($0.target.lowercased().hasPrefix("/tmp/") || $0.target.lowercased().hasPrefix("/private/tmp/"))
                    && $0.timestamp >= network.timestamp
                    && $0.timestamp.timeIntervalSince(network.timestamp) <= 30
            })

            let persistence = sorted.first(where: {
                $0.category == .persistenceAttempt
                    && $0.timestamp >= network.timestamp
                    && $0.timestamp.timeIntervalSince(network.timestamp) <= 90
            })

            guard let persistence else { continue }
            let scriptNode = script.processName ?? sampleName
            let networkNode = network.target
            let tempNode = tempFile?.target ?? "(no temp artifact)"
            chains.append("\(sampleName) -> \(scriptNode) -> \(networkNode) -> \(tempNode) -> \(persistence.target)")
        }

        if chains.isEmpty {
            let networkThenPersistence = sorted.first(where: { $0.category == .networkConnect }).flatMap { network in
                sorted.first(where: {
                    $0.category == .persistenceAttempt
                        && $0.timestamp >= network.timestamp
                        && $0.timestamp.timeIntervalSince(network.timestamp) <= 90
                }).map { persistence in
                    "\(sampleName) -> \(network.target) -> \(persistence.target)"
                }
            }
            if let networkThenPersistence {
                chains.append(networkThenPersistence)
            }
        }

        return chains.uniquePreservingOrder()
    }

    private func buildSummary(
        overview: DynamicRunOverview,
        suspiciousIndicators: [String],
        session: DynamicAnalysisSession?,
        highRiskChains: [String],
        networkSummary: NetworkSummary?
    ) -> [String] {
        var lines: [String] = []

        if overview.launchSucceeded {
            lines.append("The target started in restricted observation mode.")
        } else {
            lines.append("The target did not start in this dynamic run.")
        }

        if overview.hasChildProcesses {
            lines.append("Additional helper/child processes were observed.")
        }

        if overview.hasFileWriteActivity {
            lines.append("File change activity was observed during runtime.")
        }

        if overview.hasNetworkActivity {
            lines.append("Network activity was observed.")
        }

        if overview.hasPersistenceAttempt {
            lines.append("Writes to persistence-related paths were observed.")
        }

        if let session {
            let highRiskCount = session.highRiskEvents.count
            if highRiskCount > 0 {
                lines.append("Structured event timeline captured \(highRiskCount) risk-elevating events.")
            } else {
                lines.append("Structured event timeline did not capture clear high-risk events in this run.")
            }
        }

        if let networkSummary {
            lines.append("Network metadata captured \(networkSummary.totalConnections) connections (\(networkSummary.remoteConnections) remote).")
        }

        if !highRiskChains.isEmpty {
            lines.append("Correlated high-risk chain(s) detected: \(highRiskChains.count).")
        }

        if !suspiciousIndicators.isEmpty {
            lines.append("Potential high-risk indicators were detected and should be manually reviewed.")
        }

        switch overview.status {
        case .interrupted:
            lines.append("The session was manually interrupted by user action.")
        case .noObservableActivity:
            lines.append("No obvious high-signal behavior was observed in this run window.")
        case .failed:
            lines.append("The dynamic run failed before complete observation.")
        default:
            break
        }

        lines.append("This conclusion is limited to the current runtime window and environment.")
        return lines.uniquePreservingOrder()
    }

    private func timestampLabel() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: Date())
    }
}

private extension Array where Element == FileObservation {
    func uniqueByPathAndOperation() -> [FileObservation] {
        var seen = Set<String>()
        return filter { item in
            let key = "\(item.path)|\(item.operation)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }
}
