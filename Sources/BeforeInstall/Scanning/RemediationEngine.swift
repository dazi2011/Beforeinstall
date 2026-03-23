import Foundation

struct RemediationExecutionResult {
    var updatedThreat: ThreatRecord
    var action: RemediationAction
    var quarantineRecord: QuarantineRecord?
}

final class RemediationEngine {
    private let fileManager = FileManager.default
    private let quarantineManager: QuarantineManager
    private let ignoreStore: IgnoreListStore
    private let historyStore: RemediationHistoryStore

    init(
        quarantineManager: QuarantineManager = QuarantineManager(),
        ignoreStore: IgnoreListStore = IgnoreListStore(),
        historyStore: RemediationHistoryStore = RemediationHistoryStore()
    ) {
        self.quarantineManager = quarantineManager
        self.ignoreStore = ignoreStore
        self.historyStore = historyStore
    }

    func execute(
        sessionID: String,
        actionType: RemediationActionType,
        threat: ThreatRecord,
        hash: String?,
        userConfirmed: Bool
    ) -> RemediationExecutionResult {
        var updatedThreat = threat
        let now = Date()

        guard userConfirmed else {
            let cancelled = makeAction(
                threatID: threat.threatID,
                actionType: actionType,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: true,
                status: .cancelled,
                resultMessage: "User cancelled",
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: threat, action: cancelled)
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: cancelled, quarantineRecord: nil)
        }

        switch actionType {
        case .quarantine:
            return quarantineThreat(sessionID: sessionID, threat: updatedThreat, now: now)
        case .moveToTrash:
            return moveToTrash(sessionID: sessionID, threat: updatedThreat, now: now)
        case .deletePermanently:
            return deletePermanently(sessionID: sessionID, threat: updatedThreat, now: now)
        case .disablePersistence, .removeLaunchAgent:
            return disablePersistence(sessionID: sessionID, threat: updatedThreat, now: now)
        case .ignore:
            return ignoreThreat(sessionID: sessionID, threat: updatedThreat, hash: hash, now: now)
        case .restoreFromQuarantine:
            let action = makeAction(
                threatID: threat.threatID,
                actionType: actionType,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: true,
                status: .failed,
                resultMessage: "Use Quarantine Manager to restore by quarantine record.",
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: threat, action: action)
            updatedThreat.status = .failed
            updatedThreat.lastUpdatedAt = now
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: nil)
        }
    }

    func restoreFromQuarantine(sessionID: String, quarantineID: String) -> (record: QuarantineRecord?, action: RemediationAction) {
        do {
            let restored = try quarantineManager.restore(quarantineID: quarantineID)
            let action = makeAction(
                threatID: quarantineID,
                actionType: .restoreFromQuarantine,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: true,
                status: .succeeded,
                resultMessage: "Restored to \(restored.originalMetadata["restoredPath"] ?? restored.originalPath)",
                timestamp: Date()
            )
            let pseudoThreat = ThreatRecord(
                threatID: quarantineID,
                itemID: quarantineID,
                path: restored.originalPath,
                displayName: URL(fileURLWithPath: restored.originalPath).lastPathComponent,
                detectedType: SupportedFileType.detect(from: URL(fileURLWithPath: restored.originalPath)),
                score: 0,
                verdict: .unknown,
                riskLevel: .info,
                summary: "Restored from quarantine",
                findings: [],
                persistenceIndicators: [],
                networkIndicators: [],
                cleanupRecommendations: [],
                canQuarantine: true,
                canDelete: true,
                canIgnore: true,
                canDisablePersistence: false,
                isSystemSensitive: false,
                requiresExtraConfirmation: false,
                status: .restored,
                lastUpdatedAt: Date(),
                firstSeenAt: Date()
            )
            appendHistory(sessionID: sessionID, threat: pseudoThreat, action: action)
            return (record: restored, action: action)
        } catch {
            let action = makeAction(
                threatID: quarantineID,
                actionType: .restoreFromQuarantine,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: true,
                status: .failed,
                resultMessage: error.localizedDescription,
                timestamp: Date()
            )
            return (record: nil, action: action)
        }
    }

    private func quarantineThreat(sessionID: String, threat: ThreatRecord, now: Date) -> RemediationExecutionResult {
        var updatedThreat = threat
        do {
            let isolationMethod = threat.detectedType == .appBundle ? "sandbox-exec" : "chmod-a-x"
            let record = try quarantineManager.quarantine(
                path: threat.path,
                reason: "Threat remediation (\(threat.riskLevel.rawValue))",
                metadata: [
                    "threatID": threat.threatID,
                    "verdict": threat.verdict.rawValue,
                    "isolationMethod": isolationMethod
                ],
                hash: nil
            )

            var postActionNotes: [String] = []
            if threat.detectedType == .appBundle {
                if let sandboxProfile = writeQuarantineSandboxProfile(for: record, threat: threat) {
                    postActionNotes.append("sandbox profile: \(sandboxProfile.path)")
                }
            } else {
                if stripExecutableBits(atPath: record.quarantinePath) {
                    postActionNotes.append("execute bits removed")
                }
            }

            updatedThreat.status = .quarantined
            updatedThreat.lastUpdatedAt = now
            let action = makeAction(
                threatID: threat.threatID,
                actionType: .quarantine,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: true,
                status: .succeeded,
                resultMessage: postActionNotes.isEmpty ? "Moved to quarantine" : "Moved to quarantine (\(postActionNotes.joined(separator: ", ")))",
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: updatedThreat, action: action)
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: record)
        } catch {
            updatedThreat.status = .failed
            updatedThreat.lastUpdatedAt = now
            let action = makeAction(
                threatID: threat.threatID,
                actionType: .quarantine,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: true,
                status: .failed,
                resultMessage: error.localizedDescription,
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: updatedThreat, action: action)
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: nil)
        }
    }

    private func moveToTrash(sessionID: String, threat: ThreatRecord, now: Date) -> RemediationExecutionResult {
        var updatedThreat = threat
        let url = URL(fileURLWithPath: threat.path)
        do {
            _ = try fileManager.trashItem(at: url, resultingItemURL: nil)
            updatedThreat.status = .movedToTrash
            updatedThreat.lastUpdatedAt = now
            let action = makeAction(
                threatID: threat.threatID,
                actionType: .moveToTrash,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: true,
                status: .succeeded,
                resultMessage: "Moved to Trash",
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: updatedThreat, action: action)
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: nil)
        } catch {
            updatedThreat.status = .failed
            updatedThreat.lastUpdatedAt = now
            let action = makeAction(
                threatID: threat.threatID,
                actionType: .moveToTrash,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: true,
                status: .failed,
                resultMessage: error.localizedDescription,
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: updatedThreat, action: action)
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: nil)
        }
    }

    private func deletePermanently(sessionID: String, threat: ThreatRecord, now: Date) -> RemediationExecutionResult {
        var updatedThreat = threat
        if threat.isSystemSensitive {
            updatedThreat.status = .failed
            updatedThreat.lastUpdatedAt = now
            let action = makeAction(
                threatID: threat.threatID,
                actionType: .deletePermanently,
                requiresConfirmation: true,
                requiresAdmin: true,
                reversible: false,
                status: .failed,
                resultMessage: "Blocked for system-sensitive path.",
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: updatedThreat, action: action)
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: nil)
        }

        do {
            try fileManager.removeItem(at: URL(fileURLWithPath: threat.path))
            updatedThreat.status = .deleted
            updatedThreat.lastUpdatedAt = now
            let action = makeAction(
                threatID: threat.threatID,
                actionType: .deletePermanently,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: false,
                status: .succeeded,
                resultMessage: "Deleted permanently",
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: updatedThreat, action: action)
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: nil)
        } catch {
            updatedThreat.status = .failed
            updatedThreat.lastUpdatedAt = now
            let action = makeAction(
                threatID: threat.threatID,
                actionType: .deletePermanently,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: false,
                status: .failed,
                resultMessage: error.localizedDescription,
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: updatedThreat, action: action)
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: nil)
        }
    }

    private func disablePersistence(sessionID: String, threat: ThreatRecord, now: Date) -> RemediationExecutionResult {
        var updatedThreat = threat
        let path = threat.path
        var notes: [String] = []

        let requiresAdmin = path.hasPrefix("/Library/LaunchDaemons") || path.hasPrefix("/Library/LaunchAgents")
        if requiresAdmin {
            updatedThreat.status = .failed
            updatedThreat.lastUpdatedAt = now
            let action = makeAction(
                threatID: threat.threatID,
                actionType: .disablePersistence,
                requiresConfirmation: true,
                requiresAdmin: true,
                reversible: true,
                status: .failed,
                resultMessage: "Admin privileges required for this persistence path.",
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: updatedThreat, action: action)
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: nil)
        }

        if path.lowercased().contains("launchagents") || path.lowercased().contains("launchdaemons") {
            if let launchctlMessage = bootoutLaunchItemIfPossible(path: path) {
                notes.append(launchctlMessage)
            }
        }

        let quarantineResult = quarantineThreat(sessionID: sessionID, threat: updatedThreat, now: now)
        if quarantineResult.action.status == .succeeded {
            updatedThreat = quarantineResult.updatedThreat
            let action = makeAction(
                threatID: threat.threatID,
                actionType: .disablePersistence,
                requiresConfirmation: true,
                requiresAdmin: false,
                reversible: true,
                status: .succeeded,
                resultMessage: ([notes.joined(separator: " | "), "Persistence disabled and quarantined."].filter { !$0.isEmpty }).joined(separator: " "),
                timestamp: now
            )
            appendHistory(sessionID: sessionID, threat: updatedThreat, action: action)
            return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: quarantineResult.quarantineRecord)
        }

        let failed = makeAction(
            threatID: threat.threatID,
            actionType: .disablePersistence,
            requiresConfirmation: true,
            requiresAdmin: false,
            reversible: true,
            status: .failed,
            resultMessage: "Failed to quarantine persistence item.",
            timestamp: now
        )
        appendHistory(sessionID: sessionID, threat: quarantineResult.updatedThreat, action: failed)
        return RemediationExecutionResult(updatedThreat: quarantineResult.updatedThreat, action: failed, quarantineRecord: nil)
    }

    private func ignoreThreat(sessionID: String, threat: ThreatRecord, hash: String?, now: Date) -> RemediationExecutionResult {
        var updatedThreat = threat
        let record = IgnoreRuleRecord(
            path: threat.path,
            hash: hash,
            bundleIdentifier: nil,
            ruleID: nil,
            createdAt: now
        )
        _ = ignoreStore.append(record)

        updatedThreat.status = .ignored
        updatedThreat.lastUpdatedAt = now

        let action = makeAction(
            threatID: threat.threatID,
            actionType: .ignore,
            requiresConfirmation: true,
            requiresAdmin: false,
            reversible: true,
            status: .succeeded,
            resultMessage: "Added to ignore list",
            timestamp: now
        )
        appendHistory(sessionID: sessionID, threat: updatedThreat, action: action)
        return RemediationExecutionResult(updatedThreat: updatedThreat, action: action, quarantineRecord: nil)
    }

    private func bootoutLaunchItemIfPossible(path: String) -> String? {
        let runner = ShellCommandService()
        let escapedPath = shellEscape(path)
        let userID = getuid()
        let command = "/bin/launchctl bootout gui/\(userID) \(escapedPath)"
        switch runner.runShell(command) {
        case let .success(result):
            if result.exitCode == 0 {
                return "launchctl bootout succeeded."
            }
            return "launchctl bootout returned \(result.exitCode)."
        case let .failure(error):
            return "launchctl bootout failed: \(error.localizedDescription)"
        }
    }

    private func appendHistory(sessionID: String, threat: ThreatRecord, action: RemediationAction) {
        let entry = RemediationLogEntry(
            sessionID: sessionID,
            threatID: threat.threatID,
            path: threat.path,
            actionType: action.actionType,
            status: action.status,
            message: action.resultMessage,
            timestamp: action.timestamp
        )
        _ = historyStore.append(entry)
    }

    private func makeAction(
        threatID: String,
        actionType: RemediationActionType,
        requiresConfirmation: Bool,
        requiresAdmin: Bool,
        reversible: Bool,
        status: RemediationActionStatus,
        resultMessage: String,
        timestamp: Date
    ) -> RemediationAction {
        RemediationAction(
            actionID: UUID().uuidString,
            threatID: threatID,
            actionType: actionType,
            requiresConfirmation: requiresConfirmation,
            requiresAdmin: requiresAdmin,
            reversible: reversible,
            status: status,
            resultMessage: resultMessage,
            timestamp: timestamp
        )
    }

    private func shellEscape(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "'", with: "'\\''")
        return "'\(escaped)'"
    }

    private func writeQuarantineSandboxProfile(for record: QuarantineRecord, threat: ThreatRecord) -> URL? {
        let profileDirectory = AppPaths.quarantineDirectory.appendingPathComponent("SandboxProfiles", isDirectory: true)
        if !fileManager.fileExists(atPath: profileDirectory.path) {
            try? fileManager.createDirectory(at: profileDirectory, withIntermediateDirectories: true)
        }

        let profileURL = profileDirectory.appendingPathComponent("\(record.quarantineID).sb", isDirectory: false)
        let profile = """
        (version 1)
        (allow default)
        (deny file-write*
            (regex #"^/Users/[^/]+/Library/(LaunchAgents|LaunchDaemons)/")
            (subpath "/Library/LaunchAgents")
            (subpath "/Library/LaunchDaemons")
        )
        """
        guard let data = profile.data(using: .utf8) else { return nil }
        do {
            try data.write(to: profileURL, options: .atomic)
            let noteURL = profileDirectory.appendingPathComponent("\(record.quarantineID).txt", isDirectory: false)
            let note = "Threat: \(threat.displayName)\nQuarantinePath: \(record.quarantinePath)\nLaunch with: sandbox-exec -f \(profileURL.path) <AppExecutable>"
            try? note.data(using: .utf8)?.write(to: noteURL, options: .atomic)
            return profileURL
        } catch {
            return nil
        }
    }

    private func stripExecutableBits(atPath path: String) -> Bool {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory) else { return false }
        if isDirectory.boolValue {
            guard let enumerator = fileManager.enumerator(
                at: URL(fileURLWithPath: path),
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles],
                errorHandler: nil
            ) else {
                return false
            }
            var changed = false
            for case let fileURL as URL in enumerator {
                let values = try? fileURL.resourceValues(forKeys: [.isDirectoryKey])
                if values?.isDirectory == true { continue }
                changed = stripExecutableBitsForFile(path: fileURL.path) || changed
            }
            return changed
        }
        return stripExecutableBitsForFile(path: path)
    }

    private func stripExecutableBitsForFile(path: String) -> Bool {
        guard let attrs = try? fileManager.attributesOfItem(atPath: path),
              let mode = attrs[.posixPermissions] as? NSNumber
        else {
            return false
        }
        let original = mode.intValue
        let updated = original & ~0o111
        guard updated != original else { return false }
        do {
            try fileManager.setAttributes([.posixPermissions: NSNumber(value: updated)], ofItemAtPath: path)
            return true
        } catch {
            return false
        }
    }
}
