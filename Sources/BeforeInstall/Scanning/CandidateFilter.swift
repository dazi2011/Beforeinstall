import Foundation
import CryptoKit

final class CandidateFilter {
    private let fileManager = FileManager.default
    private let commandRunner: CommandRunning

    init(commandRunner: CommandRunning = ShellCommandService()) {
        self.commandRunner = commandRunner
    }

    func toScanItems(_ candidates: [DiscoveredCandidate], mode: FullDiskScanMode) -> [ScanItem] {
        var items: [ScanItem] = []
        for candidate in candidates {
            guard let item = makeScanItem(from: candidate, mode: mode) else { continue }
            items.append(item)
        }
        return items
    }

    private func makeScanItem(from candidate: DiscoveredCandidate, mode: FullDiskScanMode) -> ScanItem? {
        let path = candidate.path
        let url = URL(fileURLWithPath: path)
        let detectedType = normalizedType(for: candidate, mode: mode)
        guard shouldInclude(type: detectedType, isExecutable: candidate.isExecutable) else {
            return nil
        }

        let hash = computeHashIfNeeded(
            path: path,
            type: detectedType,
            isExecutable: candidate.isExecutable,
            size: candidate.size,
            location: categorizeLocation(path: path),
            mode: mode
        )
        return ScanItem(
            itemID: UUID().uuidString,
            path: path,
            displayName: url.lastPathComponent,
            fileType: detectedType,
            detectedType: detectedType,
            size: candidate.size,
            hash: hash,
            locationCategory: categorizeLocation(path: path),
            isExecutable: candidate.isExecutable,
            isDirectorySample: candidate.isDirectory,
            sourceVolume: resolveSourceVolume(path: path),
            lastModifiedAt: candidate.modifiedAt
        )
    }

    private func shouldInclude(type: SupportedFileType, isExecutable: Bool) -> Bool {
        switch type {
        case .appBundle, .pkg, .dmg, .shellScript, .pythonScript, .javaScript, .appleScript, .plist, .dylib, .machO:
            return true
        case .archive:
            return false
        case .unknown:
            return isExecutable
        }
    }

    private func normalizedType(for candidate: DiscoveredCandidate, mode: FullDiskScanMode) -> SupportedFileType {
        if mode == .quick {
            return fastType(for: candidate)
        }

        let url = URL(fileURLWithPath: candidate.path)
        let ext = url.pathExtension.lowercased()
        if candidate.isDirectory {
            if ext == "app" { return .appBundle }
            if ext == "pkg" || ext == "mpkg" { return .pkg }
        } else {
            if ext == "dmg" || ext == "iso" { return .dmg }
            if ext == "pkg" || ext == "mpkg" { return .pkg }
        }

        let byExtension = SupportedFileType.detect(from: url)
        if byExtension == .archive {
            if let byHeader = detectByFileHeader(path: candidate.path), byHeader == .dmg || byHeader == .pkg {
                return byHeader
            }
        }
        if byExtension != .unknown {
            return byExtension
        }
        if let byHeader = detectByFileHeader(path: candidate.path) {
            return byHeader
        }
        if candidate.isExecutable {
            return .machO
        }
        return .unknown
    }

    private func fastType(for candidate: DiscoveredCandidate) -> SupportedFileType {
        let url = URL(fileURLWithPath: candidate.path)
        let ext = url.pathExtension.lowercased()
        if candidate.isDirectory {
            if ext == "app" { return .appBundle }
            if ext == "pkg" || ext == "mpkg" { return .pkg }
            return .unknown
        }

        if ext == "dmg" || ext == "iso" { return .dmg }
        if ext == "pkg" || ext == "mpkg" { return .pkg }
        if ext == "plist" { return .plist }
        if ext == "dylib" || ext == "so" { return .dylib }
        if ext == "sh" || ext == "zsh" || ext == "bash" || ext == "command" { return .shellScript }
        if ext == "py" { return .pythonScript }
        if ext == "js" || ext == "mjs" || ext == "cjs" { return .javaScript }
        if ext == "applescript" || ext == "scpt" || ext == "scptd" { return .appleScript }
        if ext == "bin" || ext == "out" || ext == "exe" { return .machO }

        if candidate.isExecutable {
            return .machO
        }
        return .unknown
    }

    private func detectByFileHeader(path: String) -> SupportedFileType? {
        guard case let .success(result) = commandRunner.run(executable: "/usr/bin/file", arguments: ["-b", path]) else {
            return nil
        }
        let lower = result.stdout.lowercased()
        if lower.contains("apple disk image") {
            return .dmg
        }
        if lower.contains("xar archive") {
            return .pkg
        }
        if lower.contains("mach-o") && lower.contains("dynamically linked shared library") {
            return .dylib
        }
        if lower.contains("mach-o") {
            return .machO
        }
        if lower.contains("shell script") {
            return .shellScript
        }
        if lower.contains("python script") {
            return .pythonScript
        }
        if lower.contains("javascript") || lower.contains("node.js") {
            return .javaScript
        }
        if lower.contains("applescript") {
            return .appleScript
        }
        if lower.contains("property list") || lower.contains("plist") {
            return .plist
        }
        return nil
    }

    private func computeHashIfNeeded(
        path: String,
        type: SupportedFileType,
        isExecutable: Bool,
        size: Int64,
        location: LocationCategory,
        mode: FullDiskScanMode
    ) -> String? {
        guard size > 0 else { return nil }
        let shouldHash: Bool
        switch mode {
        case .deep:
            switch type {
            case .appBundle, .pkg:
                shouldHash = false
            case .shellScript, .pythonScript, .javaScript, .appleScript, .plist, .dylib, .machO, .dmg:
                shouldHash = true
            case .archive:
                shouldHash = false
            case .unknown:
                shouldHash = isExecutable
            }
        case .quick:
            switch type {
            case .machO, .dylib, .shellScript, .pythonScript, .javaScript, .appleScript:
                shouldHash = size <= 2 * 1024 * 1024
            case .plist:
                shouldHash = location == .launchAgents || location == .launchDaemons
            case .pkg, .appBundle, .dmg, .archive:
                shouldHash = false
            case .unknown:
                shouldHash = isExecutable && size <= 2 * 1024 * 1024
            }
        }
        guard shouldHash else { return nil }

        let maxBytes = min(size, Int64(4 * 1024 * 1024))
        guard maxBytes > 0 else { return nil }
        guard let handle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: path)),
              let data = try? handle.read(upToCount: Int(maxBytes))
        else {
            return nil
        }
        try? handle.close()

        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
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

    private func resolveSourceVolume(path: String) -> String {
        let components = path.split(separator: "/").map(String.init)
        if components.count >= 2, components.first == "Volumes" {
            return components[1]
        }
        return "System"
    }
}
