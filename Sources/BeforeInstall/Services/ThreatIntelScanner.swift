import Foundation

enum ThreatIntelHitCategory: String, Sendable {
    case ip
    case url
    case regexp
    case hash
    case signatureByte
}

struct ThreatIntelHit: Sendable {
    var category: ThreatIntelHitCategory
    var ruleID: String
    var matchedValue: String
    var scoreDelta: Int
    var sourceLine: String
}

struct ScriptDictionaryMatch: Sendable {
    var ruleID: String
    var pattern: String
    var category: String
    var scoreDelta: Int
    var isCombo: Bool
}

final class ThreatIntelScanner: @unchecked Sendable {
    static let shared = ThreatIntelScanner()

    private struct ProfileCache {
        var path: String
        var modifiedAt: Date
        var profile: ThreatIntelProfileData
    }

    private let fileManager = FileManager.default
    private let queue = DispatchQueue(label: "beforeinstall.threat-intel-scanner", qos: .utility)

    private var profileCache: ProfileCache?

    private init() {}

    func scanTextContent(
        _ text: String,
        sha256: String?,
        maxMatches: Int = 64,
        profileOverride: ThreatIntelProfileData? = nil
    ) -> [ThreatIntelHit] {
        guard maxMatches > 0 else { return [] }
        guard let profile = resolveProfile(profileOverride: profileOverride) else { return [] }
        return ThreatIntelProfileMatcher.scanTextContent(
            text,
            sha256: sha256,
            profile: profile,
            maxMatches: maxMatches
        )
    }

    func scanBinarySignatureBytes(
        _ data: Data,
        maxMatches: Int = 12,
        profileOverride: ThreatIntelProfileData? = nil
    ) -> [ThreatIntelHit] {
        guard let profile = resolveProfile(profileOverride: profileOverride) else { return [] }
        return ThreatIntelProfileMatcher.scanBinarySignatureBytes(
            data,
            profile: profile,
            maxMatches: maxMatches
        )
    }

    func scanAppBundleBinarySignatures(
        appURL: URL,
        maxBinaries: Int = 24,
        maxMatches: Int = 18,
        profileOverride: ThreatIntelProfileData? = nil
    ) -> [ThreatIntelHit] {
        guard maxBinaries > 0, maxMatches > 0 else { return [] }
        guard let profile = resolveProfile(profileOverride: profileOverride) else { return [] }

        let binaryTargets = collectAppBinaries(appURL: appURL, maxCount: maxBinaries)
        guard !binaryTargets.isEmpty else { return [] }

        var hits: [ThreatIntelHit] = []
        for binaryURL in binaryTargets {
            guard let data = readBinaryPrefix(from: binaryURL, maxBytes: 2 * 1024 * 1024) else { continue }
            let localHits = ThreatIntelProfileMatcher.scanBinarySignatureBytes(
                data,
                profile: profile,
                maxMatches: maxMatches
            )
            for hit in localHits {
                var enriched = hit
                enriched.matchedValue = "\(binaryURL.lastPathComponent): \(hit.matchedValue)"
                hits.append(enriched)
                if hits.count >= maxMatches {
                    return ThreatIntelProfileMatcher.dedupeHits(hits)
                }
            }
        }

        return ThreatIntelProfileMatcher.dedupeHits(hits)
    }

    func matchHash(_ sha256: String?, profileOverride: ThreatIntelProfileData? = nil) -> [ThreatIntelHit] {
        guard let profile = resolveProfile(profileOverride: profileOverride) else { return [] }
        return ThreatIntelProfileMatcher.matchHash(sha256, profile: profile)
    }

    func scanScriptContent(_ text: String, maxMatches: Int = 32) -> [ScriptDictionaryMatch] {
        let hits = scanTextContent(text, sha256: nil, maxMatches: maxMatches * 2)
        return hits
            .filter { $0.category == .regexp }
            .prefix(maxMatches)
            .map { hit in
                ScriptDictionaryMatch(
                    ruleID: hit.ruleID,
                    pattern: hit.sourceLine,
                    category: "regexp",
                    scoreDelta: hit.scoreDelta,
                    isCombo: true
                )
            }
    }

    func matchKnownMaliciousServers(in text: String, maxMatches: Int = 20) -> [String] {
        let hits = scanTextContent(text, sha256: nil, maxMatches: maxMatches * 3)
        return hits
            .filter { $0.category == .ip || $0.category == .url }
            .map(\.matchedValue)
            .uniquePreservingOrder()
            .prefix(maxMatches)
            .map { $0 }
    }

    private func loadProfileCacheIfNeeded() -> ProfileCache? {
        queue.sync {
            guard let url = try? ThreatIntelDictionaryManager.shared.ensureRuleFileReady() else {
                return nil
            }

            guard fileManager.fileExists(atPath: url.path) else { return nil }

            let modified = (try? fileManager.attributesOfItem(atPath: url.path)[.modificationDate] as? Date) ?? .distantPast
            if let cache = profileCache, cache.path == url.path, cache.modifiedAt == modified {
                return cache
            }

            guard let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
            let parsed = ThreatIntelProfileParser.parse(text: text)

            let rebuilt = ProfileCache(
                path: url.path,
                modifiedAt: modified,
                profile: parsed
            )
            profileCache = rebuilt
            return rebuilt
        }
    }

    private func resolveProfile(profileOverride: ThreatIntelProfileData?) -> ThreatIntelProfileData? {
        if let profileOverride {
            return profileOverride
        }
        return loadProfileCacheIfNeeded()?.profile
    }

    private func collectAppBinaries(appURL: URL, maxCount: Int) -> [URL] {
        var binaries: [URL] = []
        let roots = [
            appURL.appendingPathComponent("Contents/MacOS", isDirectory: true),
            appURL.appendingPathComponent("Contents/Frameworks", isDirectory: true),
            appURL.appendingPathComponent("Contents/PlugIns", isDirectory: true)
        ]

        for root in roots where fileManager.fileExists(atPath: root.path) {
            guard let enumerator = fileManager.enumerator(
                at: root,
                includingPropertiesForKeys: [.isDirectoryKey, .isExecutableKey],
                options: [.skipsHiddenFiles],
                errorHandler: nil
            ) else {
                continue
            }

            for case let item as URL in enumerator {
                var isDirectory: ObjCBool = false
                guard fileManager.fileExists(atPath: item.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
                    continue
                }

                if fileManager.isExecutableFile(atPath: item.path) || item.pathExtension.lowercased() == "dylib" {
                    binaries.append(item)
                }

                if binaries.count >= maxCount {
                    return binaries.uniquePreservingOrder()
                }
            }
        }

        return binaries.uniquePreservingOrder()
    }

    private func readBinaryPrefix(from url: URL, maxBytes: Int) -> Data? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        return try? handle.read(upToCount: maxBytes)
    }
}
