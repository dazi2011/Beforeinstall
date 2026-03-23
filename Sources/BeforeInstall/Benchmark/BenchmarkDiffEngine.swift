import Foundation

final class BenchmarkDiffEngine {
    func generate(currentRun: BenchmarkRun, previousRun: BenchmarkRun?) -> BenchmarkDiffSummary? {
        guard let previousRun else {
            return nil
        }

        let currentSampleMap = Dictionary(uniqueKeysWithValues: currentRun.samples.map { ($0.sampleID, $0) })
        let previousSampleMap = Dictionary(uniqueKeysWithValues: previousRun.samples.map { ($0.sampleID, $0) })

        let currentIDs = Set(currentSampleMap.keys)
        let previousIDs = Set(previousSampleMap.keys)
        let sharedIDs = currentIDs.intersection(previousIDs)

        let currentResultMap = Dictionary(uniqueKeysWithValues: currentRun.results.map { ($0.sampleID, $0) })
        let previousResultMap = Dictionary(uniqueKeysWithValues: previousRun.results.map { ($0.sampleID, $0) })

        var scoreIncreased: [String] = []
        var scoreDecreased: [String] = []
        var verdictChanges: [BenchmarkVerdictChange] = []
        var topScoreChanges: [BenchmarkScoreDelta] = []
        var newFalsePositives: [String] = []
        var newFalseNegatives: [String] = []

        for sampleID in sharedIDs.sorted() {
            guard let currentResult = currentResultMap[sampleID],
                  let previousResult = previousResultMap[sampleID],
                  let sample = currentSampleMap[sampleID] else {
                continue
            }

            let delta = currentResult.score - previousResult.score
            if delta > 0 {
                scoreIncreased.append(sampleID)
            } else if delta < 0 {
                scoreDecreased.append(sampleID)
            }

            let normalizedCurrentVerdict = normalizeVerdict(currentResult.verdict)
            let normalizedPreviousVerdict = normalizeVerdict(previousResult.verdict)
            if normalizedCurrentVerdict != normalizedPreviousVerdict {
                verdictChanges.append(
                    BenchmarkVerdictChange(
                        sampleID: sampleID,
                        group: sample.group,
                        previousVerdict: normalizedPreviousVerdict,
                        currentVerdict: normalizedCurrentVerdict,
                        previousScore: previousResult.score,
                        currentScore: currentResult.score
                    )
                )
            }

            if delta != 0 {
                topScoreChanges.append(
                    BenchmarkScoreDelta(
                        sampleID: sampleID,
                        group: sample.group,
                        previousScore: previousResult.score,
                        currentScore: currentResult.score,
                        delta: delta,
                        previousVerdict: normalizedPreviousVerdict,
                        currentVerdict: normalizedCurrentVerdict
                    )
                )
            }

            if isCleanLikeGroup(sample.group) {
                let wasLowRisk = !isPositiveVerdict(normalizedPreviousVerdict)
                let nowHighRisk = isPositiveVerdict(normalizedCurrentVerdict)
                if wasLowRisk && nowHighRisk {
                    newFalsePositives.append(sampleID)
                }
            }

            if isReplayMaliciousGroup(sample.group, expected: sample.expectation?.expectedVerdict) {
                let wasDetected = isPositiveVerdict(normalizedPreviousVerdict)
                let nowMissed = !isPositiveVerdict(normalizedCurrentVerdict)
                if wasDetected && nowMissed {
                    newFalseNegatives.append(sampleID)
                }
            }
        }

        topScoreChanges.sort { lhs, rhs in
            if abs(lhs.delta) == abs(rhs.delta) {
                return lhs.sampleID < rhs.sampleID
            }
            return abs(lhs.delta) > abs(rhs.delta)
        }

        let notes: [String] = [
            "shared_samples=\(sharedIDs.count)",
            "verdict_changes=\(verdictChanges.count)",
            "score_increased=\(scoreIncreased.count)",
            "score_decreased=\(scoreDecreased.count)",
            "new_false_positives=\(newFalsePositives.count)",
            "new_false_negatives=\(newFalseNegatives.count)"
        ]

        return BenchmarkDiffSummary(
            previousRunID: previousRun.runID,
            comparedAt: Date(),
            addedSamples: currentIDs.subtracting(previousIDs).sorted(),
            removedSamples: previousIDs.subtracting(currentIDs).sorted(),
            scoreIncreasedSamples: scoreIncreased,
            scoreDecreasedSamples: scoreDecreased,
            verdictChanges: verdictChanges,
            newlyRaisedFalsePositives: newFalsePositives,
            newlyRaisedFalseNegatives: newFalseNegatives,
            topScoreChanges: Array(topScoreChanges.prefix(20)),
            notes: notes
        )
    }

    func buildMarkdown(diff: BenchmarkDiffSummary) -> String {
        var lines: [String] = []
        lines.append("# Benchmark Regression Diff")
        lines.append("")
        lines.append("- Previous Run: \(diff.previousRunID ?? "none")")
        lines.append("- Compared At: \(iso8601(diff.comparedAt))")
        lines.append("- Added Samples: \(diff.addedSamples.count)")
        lines.append("- Removed Samples: \(diff.removedSamples.count)")
        lines.append("- Score Increased: \(diff.scoreIncreasedSamples.count)")
        lines.append("- Score Decreased: \(diff.scoreDecreasedSamples.count)")
        lines.append("- Verdict Changes: \(diff.verdictChanges.count)")
        lines.append("- New False Positives: \(diff.newlyRaisedFalsePositives.count)")
        lines.append("- New False Negatives: \(diff.newlyRaisedFalseNegatives.count)")

        lines.append("")
        lines.append("## New False Positives")
        if diff.newlyRaisedFalsePositives.isEmpty {
            lines.append("- None")
        } else {
            for sampleID in diff.newlyRaisedFalsePositives {
                lines.append("- \(sampleID)")
            }
        }

        lines.append("")
        lines.append("## New False Negatives")
        if diff.newlyRaisedFalseNegatives.isEmpty {
            lines.append("- None")
        } else {
            for sampleID in diff.newlyRaisedFalseNegatives {
                lines.append("- \(sampleID)")
            }
        }

        lines.append("")
        lines.append("## Top Score Changes")
        lines.append("| sample_id | group | previous_score | current_score | delta | previous_verdict | current_verdict |")
        lines.append("| --- | --- | ---: | ---: | ---: | --- | --- |")
        let meaningfulScoreChanges = diff.topScoreChanges.filter { $0.delta != 0 }
        if meaningfulScoreChanges.isEmpty {
            lines.append("| - | - | - | - | - | - | - |")
        } else {
            for item in meaningfulScoreChanges {
                lines.append("| \(item.sampleID) | \(item.group) | \(item.previousScore) | \(item.currentScore) | \(item.delta) | \(item.previousVerdict) | \(item.currentVerdict) |")
            }
        }

        lines.append("")
        lines.append("## Verdict Changes")
        if diff.verdictChanges.isEmpty {
            lines.append("- None")
        } else {
            for change in diff.verdictChanges.prefix(30) {
                lines.append("- \(change.sampleID): \(change.previousVerdict) -> \(change.currentVerdict) (\(change.previousScore) -> \(change.currentScore))")
            }
        }

        if !diff.notes.isEmpty {
            lines.append("")
            lines.append("## Notes")
            for note in diff.notes {
                lines.append("- \(note)")
            }
        }

        return lines.joined(separator: "\n")
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

    private func isPositiveVerdict(_ verdict: String) -> Bool {
        verdict == "suspicious" || verdict == "malicious"
    }

    private func isCleanLikeGroup(_ group: String) -> Bool {
        group == "clean" || group == "noisy_benign"
    }

    private func isReplayMaliciousGroup(_ group: String, expected: String?) -> Bool {
        if group == "replay_malicious" {
            return true
        }
        let normalizedExpected = normalizeVerdict(expected)
        return normalizedExpected == "malicious"
    }

    private func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
