# BeforeInstall

Chinese version: [README.zh-CN.md](README.zh-CN.md)

BeforeInstall is a macOS tool for pre-install and runtime-behavior risk analysis.

## Current Status

This project is still under active development and is not fully stable yet.

## Main Features

- Baseline analysis for most file types
- Full-disk scan (Quick/Deep) with risk filtering
- Restricted runtime behavior observation (dynamic analysis)
- Risk summary and report export
- Optional Random-Forest model inference (WIP) in Settings

## Installation

### Option 1: Install release package

1. Download and open the release package.
2. Move `BeforeInstall.app` to `Applications`.
3. If blocked by macOS, go to `System Settings > Privacy & Security` and click `Open Anyway`.

### Option 2: Build from source

Requirements:

- macOS 13+
- Xcode with Swift 6 toolchain

Build:

```bash
open BeforeInstall.xcodeproj
```

Then run the `BeforeInstall` target in Xcode.

## First-Run Permissions (Important)

For better full-disk scan coverage, grant permission manually:

- `System Settings > Privacy & Security > Full Disk Access`
- Enable access for `BeforeInstall`

Without this, some paths may be skipped or only partially scanned.

## Disclaimer

- Prediction and risk scoring results are **not guaranteed to be accurate**.
- The Random-Forest inference option is marked **(WIP)** and may produce more aggressive predictions.
- Treat the output as decision support, not as the only basis for security decisions.

## Project Notes

- The current UI is rough. The author is not strong at UI design yet and will improve it gradually.
- The author is busy recently, so update speed may be slower for a while.
- Issues and improvement suggestions are welcome.
