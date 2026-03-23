import Foundation

struct DiscoveryPhaseOutput: Sendable {
    var candidates: [DiscoveryCandidate]
    var skippedByType: Int
    var stats: [String: Int]
}

struct CandidateSelectionOutput: Sendable {
    var selected: [DiscoveryCandidate]
    var stats: [String: Int]
}

final class LightweightFileProbe {
    private let fileManager = FileManager.default

    func discover(candidates: [DiscoveredCandidate], mode: FullDiskScanMode) -> DiscoveryPhaseOutput {
        var output: [DiscoveryCandidate] = []
        var skippedByType = 0
        var stats: [String: Int] = [:]

        for raw in candidates {
            guard let detectedType = fastDetectedType(for: raw) else {
                skippedByType += 1
                continue
            }

            let location = categorizeLocation(path: raw.path)
            let appSignals = detectedType == .appBundle
                ? quickAppSignals(appPath: raw.path)
                : nil
            let scoring = scoreCandidate(
                path: raw.path,
                type: detectedType,
                location: location,
                isExecutable: raw.isExecutable,
                size: raw.size,
                modifiedAt: raw.modifiedAt,
                appSignals: appSignals
            )

            let escalate = mode == .deep
                ? true
                : shouldEscalateQuick(
                    score: scoring.score,
                    type: detectedType,
                    location: location,
                    isExecutable: raw.isExecutable,
                    appSignals: appSignals
                )

            output.append(
                DiscoveryCandidate(
                    path: raw.path,
                    displayName: URL(fileURLWithPath: raw.path).lastPathComponent,
                    detectedType: detectedType,
                    locationCategory: location,
                    isExecutable: raw.isExecutable,
                    isDirectory: raw.isDirectory,
                    size: raw.size,
                    lastModifiedAt: raw.modifiedAt,
                    score: scoring.score,
                    reasons: scoring.reasons,
                    escalateToFocusedAnalysis: escalate,
                    sourceRoot: raw.sourceRoot
                )
            )

            stats["type.\(detectedType.rawValue)", default: 0] += 1
            stats["location.\(location.rawValue)", default: 0] += 1
            if escalate {
                stats["escalate.true", default: 0] += 1
            } else {
                stats["escalate.false", default: 0] += 1
            }
        }

        return DiscoveryPhaseOutput(candidates: output, skippedByType: skippedByType, stats: stats)
    }

    private func fastDetectedType(for candidate: DiscoveredCandidate) -> SupportedFileType? {
        let url = URL(fileURLWithPath: candidate.path)
        let ext = url.pathExtension.lowercased()

        if candidate.isDirectory {
            if ext == "app" { return .appBundle }
            if ext == "pkg" || ext == "mpkg" { return .pkg }
            return nil
        }

        let byExtension = SupportedFileType.detect(from: url)
        if byExtension != .unknown, byExtension != .archive {
            return byExtension
        }

        if byExtension == .archive {
            // Keep DMG/PKG by extension but skip common archives in quick discovery.
            if ext == "dmg" || ext == "iso" { return .dmg }
            if ext == "pkg" || ext == "mpkg" { return .pkg }
            return nil
        }

        if ext == "plist" {
            return .plist
        }

        if candidate.isExecutable {
            return .machO
        }

        // Extremely cheap shebang probe for small files only.
        if candidate.size <= 64 * 1024,
           let shebangType = detectShebangType(path: candidate.path)
        {
            return shebangType
        }

        return nil
    }

    private func detectShebangType(path: String) -> SupportedFileType? {
        guard let handle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: path)) else { return nil }
        defer { try? handle.close() }

        guard let data = try? handle.read(upToCount: 256),
              let line = String(data: data, encoding: .utf8)?.split(whereSeparator: \.isNewline).first.map(String.init),
              line.hasPrefix("#!")
        else {
            return nil
        }
        let lower = line.lowercased()
        if lower.contains("python") { return .pythonScript }
        if lower.contains("node") || lower.contains("deno") || lower.contains("bun") { return .javaScript }
        if lower.contains("osascript") || lower.contains("applescript") { return .appleScript }
        if lower.contains("bash") || lower.contains("zsh") || lower.contains("/sh") { return .shellScript }
        return .shellScript
    }

    private func scoreCandidate(
        path: String,
        type: SupportedFileType,
        location: LocationCategory,
        isExecutable: Bool,
        size: Int64,
        modifiedAt: Date?,
        appSignals: QuickAppSignals?
    ) -> (score: Int, reasons: [String]) {
        var score = 0
        var reasons: [String] = []

        switch location {
        case .downloads:
            score += 34
            reasons.append("high-risk location: Downloads")
        case .desktop:
            score += 24
            reasons.append("high-risk location: Desktop")
        case .launchAgents, .launchDaemons:
            score += 38
            reasons.append("persistence location")
        case .temporary:
            score += 36
            reasons.append("temporary execution location")
        case .appSupport, .preferences:
            score += 20
            reasons.append("sensitive user library location")
        case .userApplications, .applications:
            score += 14
            reasons.append("application location")
        case .externalVolume:
            score += 16
            reasons.append("external volume")
        case .documents:
            score += 10
            reasons.append("user docs location")
        default:
            score += 2
        }

        switch type {
        case .appBundle:
            score += 14
            reasons.append("app bundle")
            if let appSignals {
                if appSignals.missingCodeSignatureMarker {
                    score += 30
                    reasons.append("missing _CodeSignature marker")
                }
                if appSignals.hasScriptEntrypoint {
                    score += 10
                    reasons.append("bundle contains script-like entrypoint")
                }
            }
        case .pkg:
            score += 24
            reasons.append("installer package")
        case .dmg:
            score += 18
            reasons.append("disk image")
        case .shellScript, .pythonScript, .javaScript, .appleScript:
            score += 24
            reasons.append("script file")
        case .plist:
            score += 20
            reasons.append("plist configuration")
        case .machO, .dylib:
            score += 24
            reasons.append("binary executable")
        case .unknown:
            if isExecutable {
                score += 16
                reasons.append("extensionless executable")
            }
        case .archive:
            break
        }

        if isExecutable {
            score += 10
            reasons.append("executable bit")
        }

        if (location == .downloads || location == .temporary),
           (type.isExecutableLike || type == .pkg || type == .dmg || type == .appBundle)
        {
            score += 22
            reasons.append("high-risk location + executable object")
        }

        if (location == .launchAgents || location == .launchDaemons), type == .plist {
            score += 28
            reasons.append("launchd plist")
        }

        let lower = path.lowercased()
        if lower.contains("postinstall")
            || lower.contains("preinstall")
            || lower.contains("launchagent")
            || lower.contains("daemon")
            || lower.contains("updater")
            || lower.contains("helper")
        {
            score += 8
            reasons.append("suspicious path keyword")
        }

        if type.isScriptType, size <= 256 * 1024 {
            score += 4
            reasons.append("small script (quick prefilter friendly)")
        }

        if let modifiedAt {
            let age = Date().timeIntervalSince(modifiedAt)
            if age <= 24 * 3600 {
                score += 12
                reasons.append("modified in last 24h")
            } else if age <= 72 * 3600 {
                score += 6
                reasons.append("modified in last 72h")
            }
        }

        return (max(0, min(100, score)), reasons.uniquePreservingOrder())
    }

    private func shouldEscalateQuick(
        score: Int,
        type: SupportedFileType,
        location: LocationCategory,
        isExecutable: Bool,
        appSignals: QuickAppSignals?
    ) -> Bool {
        if (location == .launchAgents || location == .launchDaemons), type == .plist {
            return true
        }
        if (location == .downloads || location == .temporary) && (isExecutable || type.isExecutableLike || type.isScriptType || type == .appBundle || type == .pkg || type == .dmg) {
            return true
        }
        if location == .appSupport && (isExecutable || type.isScriptType || type == .plist || type == .appBundle || type == .pkg) {
            return true
        }
        if score >= 70 {
            return true
        }
        if type.isScriptType && score >= 52 {
            return true
        }
        if (type == .pkg || type == .dmg) && score >= 50 {
            return true
        }
        if type == .appBundle {
            if location == .userApplications || location == .externalVolume || location == .desktop {
                return true
            }
            if appSignals?.missingCodeSignatureMarker == true && score >= 56 {
                return true
            }
            return score >= 64
        }
        if isExecutable && score >= 54 {
            return true
        }
        return false
    }

    private func quickAppSignals(appPath: String) -> QuickAppSignals {
        let appURL = URL(fileURLWithPath: appPath)
        let codeSignature = appURL.appendingPathComponent("Contents/_CodeSignature/CodeResources").path
        let missingCodeSignatureMarker = !fileManager.fileExists(atPath: codeSignature)

        let scriptsDir = appURL.appendingPathComponent("Contents/Scripts").path
        let resourcesDir = appURL.appendingPathComponent("Contents/Resources").path
        let hasScriptsDir = fileManager.fileExists(atPath: scriptsDir)

        var hasScriptEntrypoint = hasScriptsDir
        if !hasScriptEntrypoint,
           let resources = try? fileManager.contentsOfDirectory(atPath: resourcesDir)
        {
            hasScriptEntrypoint = resources.contains { name in
                let lower = name.lowercased()
                return lower.hasSuffix(".sh")
                    || lower.hasSuffix(".py")
                    || lower.hasSuffix(".js")
                    || lower.hasSuffix(".scpt")
                    || lower.contains("postinstall")
                    || lower.contains("preinstall")
                    || lower.contains("helper")
                    || lower.contains("loader")
            }
        }

        return QuickAppSignals(
            missingCodeSignatureMarker: missingCodeSignatureMarker,
            hasScriptEntrypoint: hasScriptEntrypoint
        )
    }

    private func categorizeLocation(path: String) -> LocationCategory {
        let lower = path.lowercased()
        let home = fileManager.homeDirectoryForCurrentUser.path.lowercased()
        if lower.hasPrefix("/applications/") { return .applications }
        if lower.hasPrefix("\(home)/applications/") { return .userApplications }
        if lower.hasPrefix("\(home)/downloads/") { return .downloads }
        if lower.hasPrefix("\(home)/desktop/") { return .desktop }
        if lower.hasPrefix("\(home)/documents/") { return .documents }
        if lower.contains("launchagents") { return .launchAgents }
        if lower.contains("launchdaemons") { return .launchDaemons }
        if lower.hasPrefix("\(home)/library/application support/") { return .appSupport }
        if lower.hasPrefix("\(home)/library/preferences/") { return .preferences }
        if lower.hasPrefix("\(home)/library/scripts/") { return .scripts }
        if lower.hasPrefix("\(home)/library/caches/") { return .caches }
        if lower.hasPrefix("/tmp/") || lower.hasPrefix("/private/tmp/") { return .temporary }
        if lower.hasPrefix("/library/") { return .library }
        if lower.hasPrefix("/usr/local/") || lower.hasPrefix("/opt/homebrew/") { return .brew }
        if lower.hasPrefix("/volumes/") { return .externalVolume }
        if lower.hasPrefix(home + "/") { return .userHome }
        return .unknown
    }
}

final class CandidateSelector {
    func select(candidates: [DiscoveryCandidate], mode: FullDiskScanMode) -> CandidateSelectionOutput {
        let sorted = candidates.sorted { lhs, rhs in
            if lhs.score != rhs.score {
                return lhs.score > rhs.score
            }
            return (lhs.lastModifiedAt ?? .distantPast) > (rhs.lastModifiedAt ?? .distantPast)
        }

        var stats: [String: Int] = [:]
        stats["discovered", default: 0] = candidates.count

        switch mode {
        case .deep:
            stats["selected", default: 0] = sorted.count
            stats["selected.deep", default: 0] = sorted.count
            return CandidateSelectionOutput(selected: sorted, stats: stats)
        case .quick:
            let mandatory = sorted.filter(isMandatoryQuickTarget)
            var selected: [DiscoveryCandidate] = []
            var selectedPaths = Set<String>()

            for candidate in mandatory {
                if selectedPaths.insert(candidate.path).inserted {
                    selected.append(candidate)
                }
            }

            let softCap = 220
            let preferred = sorted.filter { $0.escalateToFocusedAnalysis || $0.score >= 56 }
            for candidate in preferred {
                if selectedPaths.contains(candidate.path) { continue }
                selected.append(candidate)
                selectedPaths.insert(candidate.path)
                if selected.count >= softCap {
                    break
                }
            }

            let minimumCoverage = 72
            if selected.count < minimumCoverage {
                for candidate in sorted where !selectedPaths.contains(candidate.path) {
                    selected.append(candidate)
                    selectedPaths.insert(candidate.path)
                    if selected.count >= minimumCoverage {
                        break
                    }
                }
            }

            stats["selected", default: 0] = selected.count
            stats["selected.quick", default: 0] = selected.count
            stats["mandatory.quick", default: 0] = mandatory.count
            stats["soft_cap", default: 0] = softCap
            stats["capped", default: 0] = max(0, preferred.count - softCap)
            stats["minimum_coverage", default: 0] = minimumCoverage
            stats["high_score_70_plus", default: 0] = selected.filter { $0.score >= 70 }.count
            stats["escalation_flag", default: 0] = selected.filter(\.escalateToFocusedAnalysis).count
            return CandidateSelectionOutput(selected: selected, stats: stats)
        }
    }

    private func isMandatoryQuickTarget(_ candidate: DiscoveryCandidate) -> Bool {
        let location = candidate.locationCategory
        let type = candidate.detectedType
        if (location == .launchAgents || location == .launchDaemons), type == .plist {
            return true
        }
        if (location == .downloads || location == .temporary),
           (type.isExecutableLike || type.isScriptType || type == .appBundle || type == .pkg || type == .dmg || candidate.isExecutable)
        {
            return true
        }
        return candidate.score >= 82
    }
}

private struct QuickAppSignals {
    var missingCodeSignatureMarker: Bool
    var hasScriptEntrypoint: Bool
}
