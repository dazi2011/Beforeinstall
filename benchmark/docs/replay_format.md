# Replay Format Specification

This benchmark uses JSON event replays so dynamic analysis engines can be tested without executing real samples.
The format is designed for timeline reconstruction, process-tree building, and risk scoring regression.

## Top-Level Fields
- `sample_id`: unique replay sample identifier.
- `group`: one of `clean`, `suspicious`, `malicious`.
- `summary`: concise scenario description.
- `events`: ordered event list (ascending timestamps recommended).
- `expected_verdict`: expected classifier outcome.
- `expected_score_range`: expected numeric score interval `[min, max]`.
- `expected_top_findings`: key rule/findings expected to trigger.

## Event Fields
Each event record should contain:
- `timestamp`: ISO-8601 UTC time (`YYYY-MM-DDTHH:MM:SSZ`).
- `category`: behavior category (examples below).
- `processID`: current process ID for the event.
- `parentProcessID`: parent process ID for process-tree construction.
- `processName`: short process name.
- `executablePath`: executable path string seen by collector.
- `action`: normalized action verb.
- `target`: object/resource destination (file path, URL, command, etc.).
- `details`: human-readable context.
- `riskScoreDeltaHint` (optional): suggested relative scoring contribution.
- `rawSource` (optional): raw telemetry channel/source tag.

## Supported Category Set
Current fixtures intentionally cover these categories:
- `processCreated`
- `processExited`
- `fileCreated`
- `fileModified`
- `fileDeleted`
- `networkConnect`
- `persistenceAttempt`
- `scriptExecuted`
- `privilegeRelatedAction`

## Design Principles
- Keep each sample focused on one clear risk chain for deterministic scoring.
- Preserve realistic parent-child process relationships.
- Use reserved test IANA IP ranges (`198.51.100.0/24`, `203.0.113.0/24`) and example domains.
- Treat malicious group entries as telemetry fixtures only, not executable malware artifacts.
- Prefer mirror paths (for example `benchmark/sandbox_sensitive_mirror/...`) for persistence-like targets.
