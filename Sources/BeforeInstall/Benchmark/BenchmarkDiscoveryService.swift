import Foundation

final class BenchmarkDiscoveryService {
    enum DiscoveryError: LocalizedError {
        case invalidRoot(String)
        case inaccessibleDirectory(String)

        var errorDescription: String? {
            switch self {
            case let .invalidRoot(message), let .inaccessibleDirectory(message):
                return message
            }
        }
    }

    private let fileManager = FileManager.default

    private struct GroupRule {
        var rootDirectory: String
        var subtypeDirectory: String
        var groupName: String
        var subtypeName: String
        var sourceKind: BenchmarkSampleSourceKind
    }

    private let groupRules: [GroupRule] = [
        GroupRule(rootDirectory: "clean", subtypeDirectory: "shell", groupName: "clean", subtypeName: "shell", sourceKind: .file),
        GroupRule(rootDirectory: "clean", subtypeDirectory: "python", groupName: "clean", subtypeName: "python", sourceKind: .file),
        GroupRule(rootDirectory: "clean", subtypeDirectory: "applescript", groupName: "clean", subtypeName: "applescript", sourceKind: .file),
        GroupRule(rootDirectory: "clean", subtypeDirectory: "js", groupName: "clean", subtypeName: "js", sourceKind: .file),
        GroupRule(rootDirectory: "clean", subtypeDirectory: "plist", groupName: "clean", subtypeName: "plist", sourceKind: .file),
        GroupRule(rootDirectory: "clean", subtypeDirectory: "app", groupName: "clean", subtypeName: "app", sourceKind: .file),
        GroupRule(rootDirectory: "clean", subtypeDirectory: "pkg", groupName: "clean", subtypeName: "pkg", sourceKind: .file),
        GroupRule(rootDirectory: "noisy_benign", subtypeDirectory: "shell", groupName: "noisy_benign", subtypeName: "shell", sourceKind: .file),
        GroupRule(rootDirectory: "noisy_benign", subtypeDirectory: "python", groupName: "noisy_benign", subtypeName: "python", sourceKind: .file),
        GroupRule(rootDirectory: "noisy_benign", subtypeDirectory: "applescript", groupName: "noisy_benign", subtypeName: "applescript", sourceKind: .file),
        GroupRule(rootDirectory: "noisy_benign", subtypeDirectory: "js", groupName: "noisy_benign", subtypeName: "js", sourceKind: .file),
        GroupRule(rootDirectory: "noisy_benign", subtypeDirectory: "pkg", groupName: "noisy_benign", subtypeName: "pkg", sourceKind: .file),
        GroupRule(rootDirectory: "noisy_benign", subtypeDirectory: "app", groupName: "noisy_benign", subtypeName: "app", sourceKind: .file),
        GroupRule(rootDirectory: "suspicious", subtypeDirectory: "shell", groupName: "suspicious", subtypeName: "shell", sourceKind: .file),
        GroupRule(rootDirectory: "suspicious", subtypeDirectory: "python", groupName: "suspicious", subtypeName: "python", sourceKind: .file),
        GroupRule(rootDirectory: "suspicious", subtypeDirectory: "applescript", groupName: "suspicious", subtypeName: "applescript", sourceKind: .file),
        GroupRule(rootDirectory: "suspicious", subtypeDirectory: "js", groupName: "suspicious", subtypeName: "js", sourceKind: .file),
        GroupRule(rootDirectory: "suspicious", subtypeDirectory: "hybrid", groupName: "suspicious", subtypeName: "hybrid", sourceKind: .file),
        GroupRule(rootDirectory: "replay", subtypeDirectory: "clean", groupName: "replay_clean", subtypeName: "jsonReplay", sourceKind: .replayJSON),
        GroupRule(rootDirectory: "replay", subtypeDirectory: "suspicious", groupName: "replay_suspicious", subtypeName: "jsonReplay", sourceKind: .replayJSON),
        GroupRule(rootDirectory: "replay", subtypeDirectory: "malicious", groupName: "replay_malicious", subtypeName: "jsonReplay", sourceKind: .replayJSON)
    ]

    func discover(rootURL: URL) throws -> BenchmarkDiscoveryResult {
        let root = rootURL.standardizedFileURL

        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw DiscoveryError.invalidRoot("Benchmark root directory is invalid: \(root.path)")
        }

        let expectations = loadExpectations(rootURL: root)
        var warnings: [String] = []
        if expectations.labelMap.isEmpty {
            warnings.append("labels/expected_labels.json missing or empty.")
        }

        let missingRequiredDirectories = groupRules.compactMap { rule -> String? in
            let directoryURL = root.appendingPathComponent(rule.rootDirectory, isDirectory: true)
                .appendingPathComponent(rule.subtypeDirectory, isDirectory: true)
            var isDir: ObjCBool = false
            let exists = fileManager.fileExists(atPath: directoryURL.path, isDirectory: &isDir)
            return (exists && isDir.boolValue) ? nil : "\(rule.rootDirectory)/\(rule.subtypeDirectory)"
        }

        var samples: [BenchmarkSample] = []
        var knownSampleIDs = Set<String>()

        for rule in groupRules {
            if Task.isCancelled { throw CancellationError() }

            let subtypeRoot = root
                .appendingPathComponent(rule.rootDirectory, isDirectory: true)
                .appendingPathComponent(rule.subtypeDirectory, isDirectory: true)

            var isSubtypeDir: ObjCBool = false
            guard fileManager.fileExists(atPath: subtypeRoot.path, isDirectory: &isSubtypeDir), isSubtypeDir.boolValue else {
                continue
            }

            guard let candidates = discoverCandidates(in: subtypeRoot, benchmarkRoot: root, rule: rule) else {
                warnings.append("Cannot read directory: \(subtypeRoot.path)")
                continue
            }

            for sampleURL in candidates {
                if Task.isCancelled { throw CancellationError() }

                let metadataURL = resolveMetadataURL(for: sampleURL)
                let metadata = metadataURL.flatMap(loadMetadata)
                let normalizedSubtype = inferSubtype(for: sampleURL, rule: rule, metadataSubtype: metadata?.subtype)
                let fixtureKind = inferFixtureKind(for: sampleURL, rule: rule)
                let isDirectorySample = (try? sampleURL.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true

                var sampleID = metadata?.sampleID ?? defaultSampleID(for: sampleURL)
                if knownSampleIDs.contains(sampleID) {
                    let fallbackID = sampleID + "__" + relativePath(root: root, child: sampleURL).replacingOccurrences(of: "/", with: "_")
                    warnings.append("Duplicate sample_id '\(sampleID)' detected; using fallback '\(fallbackID)'.")
                    sampleID = fallbackID
                }
                knownSampleIDs.insert(sampleID)

                let expectedVerdict = expectations.labelMap[sampleID] ?? metadata?.expectedVerdict
                let expectedScoreRange = expectations.rangeMap[sampleID] ?? metadata?.expectedScoreRange
                let expectation = (expectedVerdict == nil && expectedScoreRange == nil)
                    ? nil
                    : BenchmarkExpectation(expectedVerdict: expectedVerdict, expectedScoreRange: expectedScoreRange)

                samples.append(
                    BenchmarkSample(
                        sampleID: sampleID,
                        absolutePath: sampleURL.path,
                        relativePath: relativePath(root: root, child: sampleURL),
                        group: metadata?.group ?? rule.groupName,
                        subtype: normalizedSubtype,
                        fixtureKind: fixtureKind,
                        metadataPath: metadataURL.map { relativePath(root: root, child: $0) },
                        expectation: expectation,
                        sourceKind: rule.sourceKind,
                        isDirectorySample: isDirectorySample
                    )
                )
            }
        }

        samples.sort {
            if $0.group == $1.group {
                return $0.sampleID < $1.sampleID
            }
            return $0.group < $1.group
        }

        return BenchmarkDiscoveryResult(
            samples: samples,
            warnings: warnings,
            missingRequiredDirectories: missingRequiredDirectories
        )
    }

    private var excludedEntryNames: Set<String> {
        ["labels", "docs", "results"]
    }

    private func discoverCandidates(
        in subtypeRoot: URL,
        benchmarkRoot: URL,
        rule: GroupRule
    ) -> [URL]? {
        guard let enumerator = fileManager.enumerator(
            at: subtypeRoot,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isPackageKey],
            options: [.skipsHiddenFiles]
        ) else {
            return nil
        }

        var candidates: [URL] = []
        var seenPaths = Set<String>()

        for case let itemURL as URL in enumerator {
            if Task.isCancelled {
                break
            }

            let name = itemURL.lastPathComponent
            if name.hasPrefix(".") {
                continue
            }

            let components = relativePath(root: benchmarkRoot, child: itemURL)
                .split(separator: "/")
                .map { String($0).lowercased() }
            if components.contains(where: { excludedEntryNames.contains($0) }) {
                enumerator.skipDescendants()
                continue
            }

            let values = try? itemURL.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isPackageKey])
            let isDirectory = values?.isDirectory == true
            let isFile = values?.isRegularFile == true

            if isDirectory {
                if shouldTreatDirectoryAsSample(itemURL, subtypeRoot: subtypeRoot, rule: rule, isPackage: values?.isPackage == true) {
                    if seenPaths.insert(itemURL.path).inserted {
                        candidates.append(itemURL)
                    }
                    enumerator.skipDescendants()
                }
                continue
            }

            guard isFile else {
                continue
            }

            if isMetadataCarrierFile(itemURL, rule: rule) {
                continue
            }

            if shouldIncludeFile(itemURL, rule: rule) {
                if seenPaths.insert(itemURL.path).inserted {
                    candidates.append(itemURL)
                }
            }
        }

        return candidates.sorted { $0.path < $1.path }
    }

    private func shouldTreatDirectoryAsSample(
        _ directoryURL: URL,
        subtypeRoot: URL,
        rule: GroupRule,
        isPackage: Bool
    ) -> Bool {
        guard rule.sourceKind == .file else {
            return false
        }

        let extensionName = directoryURL.pathExtension.lowercased()
        if rule.subtypeName == "applescript", extensionName == "scptd" {
            return true
        }

        guard ["app", "pkg", "hybrid"].contains(rule.subtypeName) else {
            return false
        }

        if isPackage || extensionName == "app" || extensionName == "pkg" || extensionName == "mpkg" {
            return true
        }

        return directoryURL.deletingLastPathComponent().path == subtypeRoot.path
    }

    private func shouldIncludeFile(_ fileURL: URL, rule: GroupRule) -> Bool {
        let ext = fileURL.pathExtension.lowercased()

        if rule.sourceKind == .replayJSON {
            return ext == "json"
        }

        switch rule.subtypeName {
        case "shell":
            return ["sh", "zsh", "bash", "command"].contains(ext)
        case "python":
            return ext == "py"
        case "applescript":
            return ["applescript", "scpt"].contains(ext)
        case "js":
            return ["js", "mjs", "cjs"].contains(ext)
        case "plist":
            return ext == "plist"
        default:
            return true
        }
    }

    private func isMetadataCarrierFile(_ fileURL: URL, rule: GroupRule) -> Bool {
        let lowercaseName = fileURL.lastPathComponent.lowercased()
        if lowercaseName.hasSuffix(".meta.json") {
            return true
        }

        guard fileURL.pathExtension.lowercased() == "json" else {
            return false
        }

        if rule.sourceKind == .replayJSON {
            return false
        }

        let siblingBaseURL = fileURL.deletingPathExtension()
        return fileManager.fileExists(atPath: siblingBaseURL.path)
    }

    private func resolveMetadataURL(for sampleURL: URL) -> URL? {
        let directMeta = URL(fileURLWithPath: sampleURL.path + ".meta.json")
        if fileManager.fileExists(atPath: directMeta.path) {
            return directMeta
        }

        if sampleURL.pathExtension.lowercased() != "json" {
            let directJSON = URL(fileURLWithPath: sampleURL.path + ".json")
            if fileManager.fileExists(atPath: directJSON.path) {
                return directJSON
            }
        }

        let parentURL = sampleURL.deletingLastPathComponent()
        let baseName = sampleURL.deletingPathExtension().lastPathComponent

        let sidecarMeta = parentURL.appendingPathComponent(baseName + ".meta.json", isDirectory: false)
        if fileManager.fileExists(atPath: sidecarMeta.path) {
            return sidecarMeta
        }

        let sidecarJSON = parentURL.appendingPathComponent(baseName + ".json", isDirectory: false)
        if fileManager.fileExists(atPath: sidecarJSON.path), sidecarJSON.path != sampleURL.path {
            return sidecarJSON
        }

        return nil
    }

    private func defaultSampleID(for sampleURL: URL) -> String {
        if sampleURL.hasDirectoryPath {
            return sampleURL.deletingPathExtension().lastPathComponent
        }
        let name = sampleURL.lastPathComponent
        return String(name.split(separator: ".").first ?? Substring(name))
    }

    private func relativePath(root: URL, child: URL) -> String {
        let rootPath = root.standardizedFileURL.path
        let childPath = child.standardizedFileURL.path
        guard childPath.hasPrefix(rootPath) else {
            return child.lastPathComponent
        }

        var relative = String(childPath.dropFirst(rootPath.count))
        if relative.hasPrefix("/") {
            relative.removeFirst()
        }
        return relative
    }

    private func loadMetadata(from url: URL) -> SampleMetadata? {
        guard let data = try? Data(contentsOf: url) else {
            return nil
        }
        return try? JSONDecoder().decode(SampleMetadata.self, from: data)
    }

    private func loadExpectations(rootURL: URL) -> (labelMap: [String: String], rangeMap: [String: BenchmarkScoreRange]) {
        let labelsURL = rootURL.appendingPathComponent("labels/expected_labels.json", isDirectory: false)
        let rangesURL = rootURL.appendingPathComponent("labels/expected_score_ranges.json", isDirectory: false)

        var labelMap: [String: String] = [:]
        var rangeMap: [String: BenchmarkScoreRange] = [:]

        if let data = try? Data(contentsOf: labelsURL) {
            mergeExpectations(from: data, labelMap: &labelMap, rangeMap: &rangeMap)
        }

        if let data = try? Data(contentsOf: rangesURL),
           let decoded = try? JSONDecoder().decode([String: [Int]].self, from: data) {
            for (sampleID, value) in decoded {
                if let range = BenchmarkScoreRange(array: value) {
                    rangeMap[sampleID] = range
                }
            }
        }

        return (labelMap, rangeMap)
    }

    private func mergeExpectations(
        from data: Data,
        labelMap: inout [String: String],
        rangeMap: inout [String: BenchmarkScoreRange]
    ) {
        guard let object = try? JSONSerialization.jsonObject(with: data) else {
            return
        }

        if let dictionary = object as? [String: Any] {
            for (key, value) in dictionary {
                switch value {
                case let verdict as String:
                    labelMap[key] = verdict
                case let expectation as [String: Any]:
                    if let verdict = expectation["expected_verdict"] as? String ?? expectation["verdict"] as? String {
                        labelMap[key] = verdict
                    }
                    if let range = parseScoreRange(expectation["expected_score_range"]) {
                        rangeMap[key] = range
                    }
                default:
                    continue
                }
            }
            return
        }

        guard let array = object as? [[String: Any]] else {
            return
        }

        for item in array {
            guard let sampleID = item["sample_id"] as? String else {
                continue
            }
            if let verdict = item["expected_verdict"] as? String ?? item["verdict"] as? String {
                labelMap[sampleID] = verdict
            }
            if let range = parseScoreRange(item["expected_score_range"]) {
                rangeMap[sampleID] = range
            }
        }
    }

    private func parseScoreRange(_ value: Any?) -> BenchmarkScoreRange? {
        if let values = value as? [Int], values.count == 2 {
            return BenchmarkScoreRange(array: values)
        }
        if let values = value as? [NSNumber], values.count == 2 {
            return BenchmarkScoreRange(array: [values[0].intValue, values[1].intValue])
        }
        return nil
    }

    private func inferSubtype(for sampleURL: URL, rule: GroupRule, metadataSubtype: String?) -> String {
        if let metadataSubtype, !metadataSubtype.isEmpty {
            return metadataSubtype
        }

        let ext = sampleURL.pathExtension.lowercased()
        if rule.subtypeName == "app", ext == "json" {
            return "manifestFixture"
        }
        if rule.subtypeName == "pkg", ext == "json" {
            return "descriptorFixture"
        }
        if rule.subtypeName == "hybrid", ext == "json" {
            return "manifestFixture"
        }
        return rule.subtypeName
    }

    private func inferFixtureKind(for sampleURL: URL, rule: GroupRule) -> String? {
        if rule.sourceKind == .replayJSON {
            return "replay_json"
        }

        let ext = sampleURL.pathExtension.lowercased()
        let isDirectory = (try? sampleURL.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true

        if rule.subtypeName == "app" && ext == "json" {
            return "manifest_fixture"
        }
        if rule.subtypeName == "pkg" && ext == "json" {
            return "descriptor_fixture"
        }
        if rule.subtypeName == "hybrid" && ext == "json" {
            return "hybrid_manifest_fixture"
        }
        if rule.subtypeName == "app" && (ext == "app" || isDirectory) {
            return "app_bundle_fixture"
        }
        if rule.subtypeName == "pkg" && isDirectory {
            return "pkg_directory_fixture"
        }
        if rule.subtypeName == "hybrid" && isDirectory {
            return "hybrid_directory_fixture"
        }
        if isDirectory {
            return "directory_fixture"
        }
        return "file_fixture"
    }
}

private struct SampleMetadata: Codable {
    var sampleID: String?
    var group: String?
    var subtype: String?
    var expectedVerdict: String?
    var expectedScoreRange: BenchmarkScoreRange?

    enum CodingKeys: String, CodingKey {
        case sampleID = "sample_id"
        case group
        case subtype = "language_or_type"
        case expectedVerdict = "expected_verdict"
        case expectedScoreRange = "expected_score_range"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sampleID = try container.decodeIfPresent(String.self, forKey: .sampleID)
        group = try container.decodeIfPresent(String.self, forKey: .group)
        subtype = try container.decodeIfPresent(String.self, forKey: .subtype)
        expectedVerdict = try container.decodeIfPresent(String.self, forKey: .expectedVerdict)

        if let array = try container.decodeIfPresent([Int].self, forKey: .expectedScoreRange) {
            expectedScoreRange = BenchmarkScoreRange(array: array)
        } else {
            expectedScoreRange = nil
        }
    }
}
