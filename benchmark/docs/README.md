# Synthetic Benchmark Fixtures for macOS Security Rating

## Purpose
This benchmark is designed to validate detection, scoring, and verdict logic using **harmless synthetic fixtures** only.
No fixture in this set should perform real malware behavior.

## Group Design
- `clean/`: Clearly benign samples with low-risk behavior.
- `noisy_benign/`: Benign samples that contain risky-looking strings/patterns to test false-positive resistance.
- `suspicious/`: Non-executable simulations of suspicious techniques (string-only, dry-run, sandbox-only).
- `replay/`: JSON event replays for behavior-engine testing without executing anything.
  - `replay/clean`: benign traces.
  - `replay/suspicious`: suspicious-but-blocked traces.
  - `replay/malicious`: synthetic high-risk chains represented as inert events.

## Safety Guarantees
- No real persistence setup.
- No writing into macOS sensitive system paths.
- No live payload downloads.
- No remote code execution.
- Suspicious commands are represented as strings, echo output, or replay data only.

## Metadata Contract
Every sample has a sidecar metadata file (`<sample>.<ext>.meta.json`) with:
- `sample_id`
- `group`
- `language_or_type`
- `summary`
- `expected_verdict`
- `expected_score_range`
- `why`

## Label Files
- `labels/expected_labels.json`: expected verdict per sample.
- `labels/expected_score_ranges.json`: expected score range per sample.
- `labels/benchmark_index.json`: full index with sample path, meta path, and core fields.
