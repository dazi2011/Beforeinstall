import Foundation

struct ThreatIntelProfileRegexRule {
    var source: String
    var regex: NSRegularExpression
    var scoreDelta: Int
}

struct ThreatIntelSignatureByteRule {
    var source: String
    var bytes: [UInt8?]
}

struct ThreatIntelProfileData {
    var ipIndicators: Set<String>
    var urlIndicators: Set<String>
    var hostIndicators: Set<String>
    var regexRules: [ThreatIntelProfileRegexRule]
    var hashIndicators: Set<String>
    var signatureRules: [ThreatIntelSignatureByteRule]

    static let empty = ThreatIntelProfileData(
        ipIndicators: [],
        urlIndicators: [],
        hostIndicators: [],
        regexRules: [],
        hashIndicators: [],
        signatureRules: []
    )
}

enum ThreatIntelProfileParser {
    private enum ProfileSection {
        case none
        case ip
        case url
        case regexp
        case hash
        case signatureByte
    }

    static func parse(text: String) -> ThreatIntelProfileData {
        var section: ProfileSection = .none
        var ips = Set<String>()
        var urls = Set<String>()
        var hosts = Set<String>()
        var regexRules: [ThreatIntelProfileRegexRule] = []
        var hashes = Set<String>()
        var signatures: [ThreatIntelSignatureByteRule] = []

        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") {
                continue
            }

            switch line.lowercased() {
            case "[ip]":
                section = .ip
                continue
            case "[url]":
                section = .url
                continue
            case "[regexp]":
                section = .regexp
                continue
            case "[hash]":
                section = .hash
                continue
            case "[signature byte]":
                section = .signatureByte
                continue
            default:
                break
            }

            switch section {
            case .ip:
                if let ip = normalizeIPAddress(line) {
                    ips.insert(ip)
                    hosts.insert(ip)
                }
            case .url:
                if let normalized = normalizeURLIndicator(line) {
                    urls.insert(normalized)
                    if let host = normalizeHost(normalized) {
                        hosts.insert(host)
                    }
                }
            case .regexp:
                if let rule = buildRegexRule(from: line) {
                    regexRules.append(rule)
                }
            case .hash:
                if let hash = normalizeHash(line) {
                    hashes.insert(hash)
                }
            case .signatureByte:
                if let signature = parseSignatureRule(line) {
                    signatures.append(signature)
                }
            case .none:
                continue
            }
        }

        return ThreatIntelProfileData(
            ipIndicators: ips,
            urlIndicators: urls,
            hostIndicators: hosts,
            regexRules: regexRules,
            hashIndicators: hashes,
            signatureRules: signatures
        )
    }

    static func normalizeIPAddress(_ raw: String) -> String? {
        let value = raw.trimmingCharacters(in: CharacterSet(charactersIn: "\"'()[]{}<> ,;\t")).lowercased()
        guard let match = value.range(of: #"^(?:\d{1,3}\.){3}\d{1,3}$"#, options: .regularExpression) else {
            return nil
        }
        let candidate = String(value[match])
        let octets = candidate.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4, octets.allSatisfy({ 0...255 ~= $0 }) else {
            return nil
        }
        return candidate
    }

    static func normalizeURLIndicator(_ raw: String) -> String? {
        let cleaned = raw
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'()[]{}<> ,;\t"))
            .replacingOccurrences(of: "hxxp://", with: "http://")
            .replacingOccurrences(of: "hxxps://", with: "https://")
            .replacingOccurrences(of: "[.]", with: ".")
            .lowercased()

        guard !cleaned.isEmpty else { return nil }

        if cleaned.hasPrefix("http://") || cleaned.hasPrefix("https://") {
            return cleaned
        }

        if cleaned.contains("/") {
            return "http://\(cleaned)"
        }

        if normalizeHost(cleaned) != nil {
            return "http://\(cleaned)"
        }

        return nil
    }

    static func normalizeHash(_ raw: String) -> String? {
        let cleaned = raw.trimmingCharacters(in: CharacterSet(charactersIn: "\"'()[]{}<> ,;\t")).lowercased()
        guard !cleaned.isEmpty else { return nil }
        guard cleaned.range(of: #"^[a-f0-9]{32,128}$"#, options: .regularExpression) != nil else {
            return nil
        }
        return cleaned
    }

    static func parseSignatureRule(_ raw: String) -> ThreatIntelSignatureByteRule? {
        let normalized = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return nil }

        let tokens = normalized.split(whereSeparator: \.isWhitespace).map(String.init)
        guard !tokens.isEmpty else { return nil }

        var bytes: [UInt8?] = []
        for token in tokens {
            let upper = token.uppercased()
            if upper == "??" || upper == "**" {
                bytes.append(nil)
                continue
            }
            guard upper.count == 2, let value = UInt8(upper, radix: 16) else {
                return nil
            }
            bytes.append(value)
        }

        guard !bytes.isEmpty else { return nil }
        return ThreatIntelSignatureByteRule(source: normalized, bytes: bytes)
    }

    static func extractHosts(from text: String) -> [String] {
        let pattern = #"((https?|ftp):\/\/[^\s"'<>]+)|\b((?:\d{1,3}\.){3}\d{1,3})\b|\b([a-z0-9][a-z0-9\.-]+\.[a-z]{2,})\b"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return []
        }

        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        var hosts: [String] = []
        for match in regex.matches(in: text, options: [], range: range) {
            guard let matchRange = Range(match.range, in: text) else { continue }
            let token = String(text[matchRange])
            if let host = normalizeHost(token) {
                hosts.append(host)
            }
        }

        return hosts.uniquePreservingOrder()
    }

    static func normalizeHost(_ value: String) -> String? {
        let trimmed = value
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'()[]{}<> ,;\t"))
            .replacingOccurrences(of: "hxxp://", with: "http://")
            .replacingOccurrences(of: "hxxps://", with: "https://")
            .replacingOccurrences(of: "[.]", with: ".")
            .lowercased()
        guard !trimmed.isEmpty else { return nil }

        if let url = URL(string: trimmed), let host = url.host?.lowercased(), !host.isEmpty {
            return host
        }

        if trimmed.contains("/") {
            let host = trimmed.split(separator: "/").first.map(String.init) ?? trimmed
            let stripped = host.split(separator: ":").first.map(String.init) ?? host
            return stripped
        }

        let candidate = trimmed.split(separator: ":").first.map(String.init) ?? trimmed
        if candidate.range(of: #"^(?:\d{1,3}\.){3}\d{1,3}$"#, options: .regularExpression) != nil {
            return normalizeIPAddress(candidate)
        }

        if candidate.contains(".") {
            return candidate
        }

        return nil
    }

    static func buildRegexRule(from rawPattern: String) -> ThreatIntelProfileRegexRule? {
        guard !rawPattern.isEmpty else { return nil }
        do {
            let regex = try NSRegularExpression(pattern: rawPattern, options: [.caseInsensitive])
            let lower = rawPattern.lowercased()
            let score: Int
            if lower.contains("launch") || lower.contains("daemon") || lower.contains("dyld_insert_libraries") {
                score = 18
            } else if lower.contains("curl") || lower.contains("wget") || lower.contains("exec") || lower.contains("shell") {
                score = 14
            } else {
                score = 10
            }
            return ThreatIntelProfileRegexRule(source: rawPattern, regex: regex, scoreDelta: score)
        } catch {
            return nil
        }
    }
}

enum ThreatIntelProfileMatcher {
    static func scanTextContent(
        _ text: String,
        sha256: String?,
        profile: ThreatIntelProfileData,
        maxMatches: Int
    ) -> [ThreatIntelHit] {
        guard maxMatches > 0 else { return [] }

        var hits: [ThreatIntelHit] = []
        let lower = text.lowercased()

        if let hashHit = matchHash(sha256, profile: profile).first {
            hits.append(hashHit)
        }

        let hostCandidates = ThreatIntelProfileParser.extractHosts(from: lower)
        for host in hostCandidates {
            if isLowSignalReferenceHost(host) {
                continue
            }
            if profile.ipIndicators.contains(host) {
                hits.append(
                    ThreatIntelHit(
                        category: .ip,
                        ruleID: "intel.ip.known_malicious",
                        matchedValue: host,
                        scoreDelta: 18,
                        sourceLine: host
                    )
                )
                continue
            }

            if let matchedHost = profile.hostIndicators.first(where: { indicator in
                host == indicator || host.hasSuffix(".\(indicator)")
            }) {
                hits.append(
                    ThreatIntelHit(
                        category: .url,
                        ruleID: "intel.url.known_malicious_host",
                        matchedValue: matchedHost,
                        scoreDelta: 8,
                        sourceLine: matchedHost
                    )
                )
            }
        }

        if !profile.urlIndicators.isEmpty {
            for indicator in profile.urlIndicators {
                if isLowSignalReferenceURL(indicator) {
                    continue
                }
                if lower.contains(indicator) {
                    hits.append(
                        ThreatIntelHit(
                            category: .url,
                            ruleID: "intel.url.known_malicious_url",
                            matchedValue: indicator,
                            scoreDelta: 10,
                            sourceLine: indicator
                        )
                    )
                }
                if hits.count >= maxMatches * 2 {
                    break
                }
            }
        }

        let searchRange = NSRange(lower.startIndex..<lower.endIndex, in: lower)
        for rule in profile.regexRules {
            if let match = rule.regex.firstMatch(in: lower, options: [], range: searchRange),
               let range = Range(match.range, in: lower)
            {
                let snippet = String(lower[range]).trimmingCharacters(in: .whitespacesAndNewlines)
                hits.append(
                    ThreatIntelHit(
                        category: .regexp,
                        ruleID: "intel.regexp.command_combo",
                        matchedValue: snippet.isEmpty ? rule.source : snippet,
                        scoreDelta: rule.scoreDelta,
                        sourceLine: rule.source
                    )
                )
            }
            if hits.count >= maxMatches * 3 {
                break
            }
        }

        return dedupeHits(hits)
            .sorted(by: threatHitPriority)
            .prefix(maxMatches)
            .map { $0 }
    }

    static func matchHash(_ sha256: String?, profile: ThreatIntelProfileData) -> [ThreatIntelHit] {
        guard let sha256 = sha256?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !sha256.isEmpty else {
            return []
        }

        guard profile.hashIndicators.contains(sha256) else { return [] }

        return [
            ThreatIntelHit(
                category: .hash,
                ruleID: "intel.hash.known_malicious",
                matchedValue: sha256,
                scoreDelta: 35,
                sourceLine: sha256
            )
        ]
    }

    static func scanBinarySignatureBytes(
        _ data: Data,
        profile: ThreatIntelProfileData,
        maxMatches: Int
    ) -> [ThreatIntelHit] {
        guard maxMatches > 0 else { return [] }
        guard !profile.signatureRules.isEmpty else { return [] }
        guard !data.isEmpty else { return [] }

        var hits: [ThreatIntelHit] = []
        for rule in profile.signatureRules {
            if binaryData(data, matches: rule.bytes) {
                hits.append(
                    ThreatIntelHit(
                        category: .signatureByte,
                        ruleID: "intel.signature.byte_fragment",
                        matchedValue: rule.source,
                        scoreDelta: 32,
                        sourceLine: rule.source
                    )
                )
            }
            if hits.count >= maxMatches {
                break
            }
        }

        return hits
    }

    static func dedupeHits(_ hits: [ThreatIntelHit]) -> [ThreatIntelHit] {
        var seen = Set<String>()
        return hits.filter { hit in
            let key = "\(hit.category.rawValue)|\(hit.ruleID)|\(hit.matchedValue)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }

    static func threatHitPriority(lhs: ThreatIntelHit, rhs: ThreatIntelHit) -> Bool {
        if lhs.scoreDelta != rhs.scoreDelta {
            return lhs.scoreDelta > rhs.scoreDelta
        }
        if lhs.category != rhs.category {
            return categoryRank(lhs.category) > categoryRank(rhs.category)
        }
        return lhs.matchedValue < rhs.matchedValue
    }

    private static func categoryRank(_ category: ThreatIntelHitCategory) -> Int {
        switch category {
        case .hash:
            return 5
        case .signatureByte:
            return 4
        case .regexp:
            return 3
        case .url:
            return 2
        case .ip:
            return 1
        }
    }

    private static func isLowSignalReferenceHost(_ host: String) -> Bool {
        let normalized = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else { return true }

        let safeHosts: Set<String> = [
            "w3.org", "www.w3.org",
            "apple.com", "www.apple.com",
            "ogp.me", "schema.org"
        ]

        if safeHosts.contains(normalized) {
            return true
        }

        if normalized.hasSuffix(".local") || normalized == "localhost" {
            return true
        }

        return false
    }

    private static func isLowSignalReferenceURL(_ value: String) -> Bool {
        let lower = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !lower.isEmpty else { return true }

        if lower.contains("/2000/svg")
            || lower.contains("/1999/xhtml")
            || lower.contains("propertylist-1.0.dtd")
            || lower.contains("/tr/rec-html40/")
        {
            return true
        }

        if let host = ThreatIntelProfileParser.normalizeHost(lower), isLowSignalReferenceHost(host) {
            return true
        }

        return false
    }

    private static func binaryData(_ data: Data, matches pattern: [UInt8?]) -> Bool {
        guard !pattern.isEmpty, data.count >= pattern.count else { return false }
        let bytes = [UInt8](data)

        for start in 0...(bytes.count - pattern.count) {
            var matched = true
            for (offset, expected) in pattern.enumerated() {
                if let expected, bytes[start + offset] != expected {
                    matched = false
                    break
                }
            }
            if matched {
                return true
            }
        }

        return false
    }
}
