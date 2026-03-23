import Foundation

struct ProfileRuleEvaluationResult {
    var hits: [ThreatIntelHit]
    var ignoredCount: Int
}

final class ProfileRuleEngine: @unchecked Sendable {
    static let shared = ProfileRuleEngine()

    private let fileManager = FileManager.default
    private let queue = DispatchQueue(label: "beforeinstall.profile-rule-engine", qos: .utility)

    private struct ExternalRuleFileCache {
        var path: String
        var modifiedAt: Date
        var profile: ThreatIntelProfileData
    }

    private struct RuleDecision {
        var rule: ConfigRule
        var action: ConfigRuleAction
        var hit: ThreatIntelHit
        var line: Int
        var specificity: Int
    }

    private var externalRuleFileCache: [String: ExternalRuleFileCache] = [:]

    private init() {}

    func evaluate(
        fileURL: URL,
        textContent: String?,
        sha256: String?,
        existingHits: [ThreatIntelHit],
        enableAppSignatureRules: Bool = false
    ) -> ProfileRuleEvaluationResult {
        let parsed = ConfigProfileService.shared.loadActiveParsedProfile()
        guard !parsed.rules.isEmpty else {
            return ProfileRuleEvaluationResult(hits: existingHits, ignoredCount: 0)
        }

        let normalizedText = textContent?.lowercased()
        let normalizedHash = sha256?.lowercased()
        var decisionsByScope: [String: RuleDecision] = [:]

        for (index, rule) in parsed.rules.enumerated().reversed() {
            let ruleHits = evaluateRule(
                rule,
                textContent: normalizedText,
                sha256: normalizedHash,
                fallbackFileURL: fileURL,
                enableAppSignatureRules: enableAppSignatureRules
            )
            guard !ruleHits.isEmpty else {
                continue
            }

            let line = effectiveLineNumber(for: rule, fallback: index + 1)
            let specificity = specificityRank(for: rule.type)
            for hit in ruleHits {
                let scopeKey = conflictScopeKey(for: hit)
                let candidate = RuleDecision(
                    rule: rule,
                    action: rule.action,
                    hit: hit,
                    line: line,
                    specificity: specificity
                )

                if let current = decisionsByScope[scopeKey] {
                    if shouldOverrideDecision(current: current, candidate: candidate) {
                        decisionsByScope[scopeKey] = candidate
                    }
                } else {
                    decisionsByScope[scopeKey] = candidate
                }
            }
        }

        var mergedMap = buildHitMap(existingHits)
        var ignoredCount = 0

        let orderedDecisions = decisionsByScope.values.sorted { lhs, rhs in
            if lhs.line != rhs.line { return lhs.line < rhs.line }
            if lhs.specificity != rhs.specificity { return lhs.specificity > rhs.specificity }
            if lhs.action != rhs.action { return lhs.action == .ignore }
            if lhs.hit.scoreDelta != rhs.hit.scoreDelta { return lhs.hit.scoreDelta > rhs.hit.scoreDelta }
            return lhs.hit.ruleID < rhs.hit.ruleID
        }

        for decision in orderedDecisions {
            let scopeKey = conflictScopeKey(for: decision.hit)
            switch decision.action {
            case .notice:
                if let existing = mergedMap[scopeKey] {
                    mergedMap[scopeKey] = preferredHit(existing, decision.hit)
                } else {
                    mergedMap[scopeKey] = decision.hit
                }
            case .ignore:
                if mergedMap.removeValue(forKey: scopeKey) != nil {
                    ignoredCount += 1
                }
                let extraRemovalKeys = mergedMap.compactMap { key, hit -> String? in
                    matchesIgnore(rule: decision.rule, hit: hit, generatedHits: [decision.hit]) ? key : nil
                }
                if !extraRemovalKeys.isEmpty {
                    ignoredCount += extraRemovalKeys.count
                    extraRemovalKeys.forEach { mergedMap.removeValue(forKey: $0) }
                }
            }
        }

        let mergedHits = mergedMap.values
            .sorted(by: ThreatIntelProfileMatcher.threatHitPriority)
            .map { $0 }
        return ProfileRuleEvaluationResult(hits: mergedHits, ignoredCount: ignoredCount)
    }

    private func evaluateRule(
        _ rule: ConfigRule,
        textContent: String?,
        sha256: String?,
        fallbackFileURL: URL,
        enableAppSignatureRules: Bool
    ) -> [ThreatIntelHit] {
        switch rule.type {
        case .rule:
            guard let textContent, textContent.contains(rule.value.lowercased()) else { return [] }
            return [
                ThreatIntelHit(
                    category: .regexp,
                    ruleID: "config.rule.command",
                    matchedValue: rule.value,
                    scoreDelta: 8,
                    sourceLine: "RULE"
                )
            ]
        case .ruleHash:
            guard let sha256, sha256 == rule.value.lowercased() else { return [] }
            return [
                ThreatIntelHit(
                    category: .hash,
                    ruleID: "config.rule.hash",
                    matchedValue: rule.value.lowercased(),
                    scoreDelta: 28,
                    sourceLine: "RULE-HASH"
                )
            ]
        case .ruleURL:
            guard let textContent else { return [] }
            let normalizedURL = ThreatIntelProfileParser.normalizeURLIndicator(rule.value) ?? rule.value.lowercased()
            let host = ThreatIntelProfileParser.normalizeHost(rule.value)
            guard textContent.contains(normalizedURL.lowercased()) || (host.map(textContent.contains) ?? false) else {
                return []
            }
            return [
                ThreatIntelHit(
                    category: .url,
                    ruleID: "config.rule.url",
                    matchedValue: host ?? normalizedURL.lowercased(),
                    scoreDelta: 16,
                    sourceLine: "RULE-URL"
                )
            ]
        case .ruleIP:
            guard let textContent else { return [] }
            guard let ip = ThreatIntelProfileParser.normalizeIPAddress(rule.value) else { return [] }
            guard textContent.contains(ip) else { return [] }
            return [
                ThreatIntelHit(
                    category: .ip,
                    ruleID: "config.rule.ip",
                    matchedValue: ip,
                    scoreDelta: 18,
                    sourceLine: "RULE-IP"
                )
            ]
        case .ruleRegexp:
            guard let textContent else { return [] }
            guard let regex = try? NSRegularExpression(pattern: rule.value, options: [.caseInsensitive]) else {
                return []
            }
            let range = NSRange(textContent.startIndex..<textContent.endIndex, in: textContent)
            guard let match = regex.firstMatch(in: textContent, options: [], range: range),
                  let matchRange = Range(match.range, in: textContent)
            else {
                return []
            }
            return [
                ThreatIntelHit(
                    category: .regexp,
                    ruleID: "config.rule.regexp",
                    matchedValue: String(textContent[matchRange]),
                    scoreDelta: 14,
                    sourceLine: rule.value
                )
            ]
        case .ruleFile:
            let expandedPath = (rule.value as NSString).expandingTildeInPath
            let candidateURL = URL(fileURLWithPath: expandedPath).standardizedFileURL
            guard fileManager.fileExists(atPath: candidateURL.path) else { return [] }
            return evaluateExternalRuleFile(
                url: candidateURL,
                textContent: textContent,
                sha256: sha256,
                fallbackFileURL: fallbackFileURL,
                enableAppSignatureRules: enableAppSignatureRules
            )
        case .rulePathPrefix:
            return []
        case .app:
            return []
        }
    }

    private func evaluateExternalRuleFile(
        url: URL,
        textContent: String?,
        sha256: String?,
        fallbackFileURL: URL,
        enableAppSignatureRules: Bool
    ) -> [ThreatIntelHit] {
        guard let profile = loadExternalRuleFile(url: url) else { return [] }

        var hits = ThreatIntelProfileMatcher.scanTextContent(
            textContent ?? "",
            sha256: sha256,
            profile: profile,
            maxMatches: 96
        )

        if enableAppSignatureRules, fallbackFileURL.pathExtension.lowercased() == "app" {
            let signatureHits = ThreatIntelScanner.shared.scanAppBundleBinarySignatures(
                appURL: fallbackFileURL,
                maxBinaries: 32,
                maxMatches: 18,
                profileOverride: profile
            )
            hits.append(contentsOf: signatureHits)
        }

        if hits.isEmpty, fallbackFileURL.path == url.path {
            // If the configured RULE-FILE points to the file currently being analyzed,
            // keep behavior deterministic by avoiding self-recursive matching loops.
            return []
        }

        if !hits.isEmpty {
            hits = hits.map { hit in
                var enriched = hit
                enriched.ruleID = "config.rule.file.\(hit.ruleID)"
                return enriched
            }
        }

        return ThreatIntelProfileMatcher.dedupeHits(hits)
    }

    private func loadExternalRuleFile(url: URL) -> ThreatIntelProfileData? {
        queue.sync {
            guard fileManager.fileExists(atPath: url.path) else { return nil }
            guard let text = try? String(contentsOf: url, encoding: .utf8) else {
                return nil
            }

            let modifiedAt = (try? fileManager.attributesOfItem(atPath: url.path)[.modificationDate] as? Date) ?? .distantPast
            if let cached = externalRuleFileCache[url.path], cached.modifiedAt == modifiedAt {
                return cached.profile
            }

            let parsed = ThreatIntelProfileParser.parse(text: text)

            let built = ExternalRuleFileCache(
                path: url.path,
                modifiedAt: modifiedAt,
                profile: parsed
            )
            externalRuleFileCache[url.path] = built
            return parsed
        }
    }

    private func matchesIgnore(rule: ConfigRule, hit: ThreatIntelHit, generatedHits: [ThreatIntelHit]) -> Bool {
        if generatedHits.contains(where: { generated in
            generated.category == hit.category && generated.matchedValue == hit.matchedValue
        }) {
            return true
        }

        let needle = rule.value.lowercased()
        switch rule.type {
        case .ruleHash:
            return hit.category == .hash && hit.matchedValue.lowercased() == needle
        case .ruleIP:
            return hit.category == .ip && hit.matchedValue.lowercased().contains(needle)
        case .ruleURL:
            return hit.category == .url && hit.matchedValue.lowercased().contains(needle)
        case .ruleRegexp, .rule:
            return hit.matchedValue.lowercased().contains(needle)
        case .ruleFile:
            return hit.ruleID.contains("config.rule.file") || hit.sourceLine.lowercased().contains(needle)
        case .rulePathPrefix:
            return false
        case .app:
            return false
        }
    }

    private func effectiveLineNumber(for rule: ConfigRule, fallback: Int) -> Int {
        if rule.lineNumber > 0 {
            return rule.lineNumber
        }
        return max(1, fallback)
    }

    private func specificityRank(for ruleType: ConfigRuleType) -> Int {
        switch ruleType {
        case .ruleHash:
            return 60
        case .ruleIP, .ruleURL:
            return 50
        case .ruleRegexp:
            return 40
        case .ruleFile:
            return 30
        case .rulePathPrefix:
            return 10
        case .rule:
            return 20
        case .app:
            return 0
        }
    }

    private func shouldOverrideDecision(current: RuleDecision, candidate: RuleDecision) -> Bool {
        if candidate.specificity != current.specificity {
            return candidate.specificity > current.specificity
        }
        if candidate.line != current.line {
            return candidate.line < current.line
        }
        if candidate.action != current.action {
            return candidate.action == .ignore
        }
        if candidate.hit.scoreDelta != current.hit.scoreDelta {
            return candidate.hit.scoreDelta > current.hit.scoreDelta
        }
        return candidate.hit.ruleID < current.hit.ruleID
    }

    private func conflictScopeKey(for hit: ThreatIntelHit) -> String {
        let normalizedValue = hit.matchedValue
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return "\(hit.category.rawValue)|\(normalizedValue)"
    }

    private func buildHitMap(_ hits: [ThreatIntelHit]) -> [String: ThreatIntelHit] {
        var map: [String: ThreatIntelHit] = [:]
        for hit in ThreatIntelProfileMatcher.dedupeHits(hits) {
            let key = conflictScopeKey(for: hit)
            if let existing = map[key] {
                map[key] = preferredHit(existing, hit)
            } else {
                map[key] = hit
            }
        }
        return map
    }

    private func preferredHit(_ lhs: ThreatIntelHit, _ rhs: ThreatIntelHit) -> ThreatIntelHit {
        if lhs.scoreDelta != rhs.scoreDelta {
            return lhs.scoreDelta > rhs.scoreDelta ? lhs : rhs
        }
        if lhs.category != rhs.category {
            return lhs.category.rawValue < rhs.category.rawValue ? lhs : rhs
        }
        return lhs.ruleID <= rhs.ruleID ? lhs : rhs
    }
}
