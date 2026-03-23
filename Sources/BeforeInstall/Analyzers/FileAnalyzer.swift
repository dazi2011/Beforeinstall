import Foundation

protocol Analyzer {
    var analyzerName: String { get }
}

protocol StaticAnalyzer: Analyzer {
    var supportedTypes: Set<SupportedFileType> { get }
    func analyze(fileURL: URL, basicInfo: FileBasicInfo) async -> AnalysisResult
}

protocol DynamicAnalyzer: Analyzer {
    func analyze(
        fileURL: URL,
        basicInfo: FileBasicInfo,
        request: AnalysisRequest,
        stopToken: DynamicStopToken?,
        progress: @escaping @Sendable (DynamicProgressEvent) -> Void
    ) async -> DynamicAnalysisReport
}

func parseKeyValueLines(_ text: String) -> [String: String] {
    var result: [String: String] = [:]
    text.split(whereSeparator: \ .isNewline).forEach { line in
        let raw = String(line)
        if let index = raw.firstIndex(of: "=") {
            let key = String(raw[..<index]).trimmingCharacters(in: .whitespacesAndNewlines)
            let value = String(raw[raw.index(after: index)...]).trimmingCharacters(in: .whitespacesAndNewlines)
            if !key.isEmpty {
                result[key] = value
            }
        }
    }
    return result
}

func extractPlistXML(from text: String) -> String? {
    guard let startRange = text.range(of: "<?xml"),
          let endRange = text.range(of: "</plist>", options: .backwards)
    else {
        return nil
    }

    let xml = String(text[startRange.lowerBound..<endRange.upperBound])
    return xml.trimmingCharacters(in: .whitespacesAndNewlines)
}

func flattenPlistValue(_ value: Any) -> String {
    switch value {
    case let boolValue as Bool:
        return boolValue ? "true" : "false"
    case let stringValue as String:
        return stringValue
    case let numberValue as NSNumber:
        return numberValue.stringValue
    case let arrayValue as [Any]:
        return arrayValue.map { flattenPlistValue($0) }.joined(separator: ", ")
    case let dictValue as [String: Any]:
        let pairs = dictValue.keys.sorted().map { key in
            "\(key): \(flattenPlistValue(dictValue[key] ?? ""))"
        }
        return "{\(pairs.joined(separator: "; "))}"
    default:
        return String(describing: value)
    }
}

extension Array where Element: Hashable {
    func uniquePreservingOrder() -> [Element] {
        var seen = Set<Element>()
        return filter { element in
            if seen.contains(element) {
                return false
            }
            seen.insert(element)
            return true
        }
    }
}

final class FileTypeDetector {
    private let fileManager = FileManager.default
    private let commandRunner: CommandRunning

    init(commandRunner: CommandRunning) {
        self.commandRunner = commandRunner
    }

    func detect(fileURL: URL) -> FileTypeDetection {
        let isExecutable = fileManager.isExecutableFile(atPath: fileURL.path)
        let headerData = readHeaderData(fileURL: fileURL)
        let shebang = extractShebang(from: headerData)
        let magicMatch = detectByMagic(headerData: headerData)
        let textFeatureMatch = detectByTextFeatures(headerData: headerData)
        let headerDescription = readFileHeaderDescription(fileURL: fileURL)
        let headerMatch = detectByFileHeader(headerDescription: headerDescription)
        let bundleMatch = detectByBundleStructure(fileURL: fileURL)
        let extensionMatch = detectByExtension(fileURL: fileURL)
        let machOCheck = detectMachO(headerData: headerData, headerDescription: headerDescription)

        let resolved: (type: SupportedFileType, source: FileTypeEvidenceSource, detail: String)

        if let magicMatch {
            resolved = (magicMatch.type, .magicBytes, magicMatch.detail)
        } else if let shebang {
            resolved = (shebang.type, .shebang, "Shebang matched: \(shebang.line)")
        } else if let textFeatureMatch {
            resolved = (textFeatureMatch.type, .fileHeader, "Text feature matched: \(textFeatureMatch.detail)")
        } else if let bundleMatch {
            resolved = (bundleMatch.type, .bundleStructure, bundleMatch.detail)
        } else if let extensionMatch,
                  shouldPreferExtension(match: extensionMatch, headerMatch: headerMatch)
        {
            resolved = (extensionMatch.type, .fileExtension, extensionMatch.detail)
        } else if let headerMatch {
            resolved = (headerMatch.type, .fileHeader, "file(1) matched: \(headerMatch.description)")
        } else if let extensionMatch {
            resolved = (extensionMatch.type, .fileExtension, extensionMatch.detail)
        } else if isExecutable {
            resolved = (.machO, .executablePermission, "Executable bit is set")
        } else if machOCheck.isMachO {
            resolved = (machOCheck.type, .machOCheck, machOCheck.detail)
        } else {
            resolved = (.unknown, .unknown, "No reliable type signal")
        }

        return FileTypeDetection(
            detectedType: resolved.type,
            source: resolved.source,
            detail: resolved.detail,
            shebang: shebang?.line,
            magicDescription: magicMatch?.detail,
            headerDescription: headerDescription,
            isExecutable: isExecutable,
            isMachO: machOCheck.isMachO
        )
    }

    private func shouldPreferExtension(
        match: (type: SupportedFileType, detail: String),
        headerMatch: (type: SupportedFileType, description: String)?
    ) -> Bool {
        switch match.type {
        case .dmg, .pkg, .appBundle:
            // Keep installer/media types stable even when file(1) falls back to generic archive text.
            if let headerMatch, headerMatch.type != .archive {
                return headerMatch.type == match.type
            }
            return true
        case .plist:
            return headerMatch == nil || headerMatch?.type == .plist
        default:
            return false
        }
    }

    private func readHeaderData(fileURL: URL, maxBytes: Int = 4096) -> Data {
        guard let handle = try? FileHandle(forReadingFrom: fileURL) else {
            return Data()
        }
        defer { try? handle.close() }
        return (try? handle.read(upToCount: maxBytes)) ?? Data()
    }

    private func extractShebang(from data: Data) -> (line: String, type: SupportedFileType)? {
        guard !data.isEmpty,
              let text = String(data: data, encoding: .utf8)
        else {
            return nil
        }

        guard let firstLine = text.split(whereSeparator: \.isNewline).map(String.init).first,
              firstLine.hasPrefix("#!")
        else {
            return nil
        }

        let line = firstLine.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = line.lowercased()

        if lower.contains("python") {
            return (line, .pythonScript)
        }

        if lower.contains("osascript") || lower.contains("applescript") {
            return (line, .appleScript)
        }

        if lower.contains("node") || lower.contains("deno") || lower.contains("bun") || lower.contains("javascript") {
            return (line, .javaScript)
        }

        if lower.contains("bash") || lower.contains("zsh") || lower.contains("/sh") || lower.contains("ksh") || lower.contains("dash") || lower.contains("fish") {
            return (line, .shellScript)
        }

        return (line, .shellScript)
    }

    private func detectByMagic(headerData: Data) -> (type: SupportedFileType, detail: String)? {
        guard !headerData.isEmpty else {
            return nil
        }

        if headerData.starts(with: [0x78, 0x61, 0x72, 0x21]) {
            return (.pkg, "xar! magic")
        }

        if headerData.starts(with: [0x50, 0x4B, 0x03, 0x04]) ||
            headerData.starts(with: [0x50, 0x4B, 0x05, 0x06]) ||
            headerData.starts(with: [0x1F, 0x8B]) ||
            headerData.starts(with: [0x42, 0x5A, 0x68]) ||
            headerData.starts(with: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) ||
            headerData.starts(with: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])
        {
            return (.archive, "Archive magic bytes")
        }

        if headerData.count > 262 {
            let tarMarker = headerData.subdata(in: 257..<262)
            if String(data: tarMarker, encoding: .utf8) == "ustar" {
                return (.archive, "TAR ustar marker")
            }
        }

        if headerData.starts(with: Array("bplist00".utf8)) {
            return (.plist, "Binary plist header")
        }

        if let xmlPrefix = String(data: headerData.prefix(256), encoding: .utf8)?.lowercased(),
           xmlPrefix.contains("<?xml"),
           xmlPrefix.contains("<plist")
        {
            return (.plist, "XML plist header")
        }

        return nil
    }

    private func detectByTextFeatures(headerData: Data) -> (type: SupportedFileType, detail: String)? {
        guard let text = String(data: headerData, encoding: .utf8)?.lowercased() else {
            return nil
        }

        if text.contains("do shell script") || text.contains("tell application \"finder\"") || text.contains("tell application \"terminal\"") {
            return (.appleScript, "AppleScript text feature")
        }

        if text.contains("import os") || text.contains("import subprocess") || text.contains("def ") || text.contains("if __name__ == \"__main__\"") {
            return (.pythonScript, "Python text feature")
        }

        if text.contains("require('child_process')")
            || text.contains("require(\"child_process\")")
            || text.contains("const ")
            || text.contains("let ")
            || text.contains("process.")
        {
            return (.javaScript, "JavaScript text feature")
        }

        if text.contains("curl ") || text.contains("wget ") || text.contains("launchctl ") || text.contains("chmod +x") {
            return (.shellScript, "Shell command text feature")
        }

        return nil
    }

    private func readFileHeaderDescription(fileURL: URL) -> String? {
        guard case let .success(result) = commandRunner.run(executable: "/usr/bin/file", arguments: ["-b", fileURL.path]) else {
            return nil
        }

        let desc = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return desc.isEmpty ? nil : desc
    }

    private func detectByFileHeader(headerDescription: String?) -> (type: SupportedFileType, description: String)? {
        guard let desc = headerDescription else {
            return nil
        }

        let lower = desc.lowercased()
        if lower.contains("apple disk image") {
            return (.dmg, desc)
        }
        if lower.contains("xar archive") {
            return (.pkg, desc)
        }
        if lower.contains("shell script") {
            return (.shellScript, desc)
        }
        if lower.contains("python script") {
            return (.pythonScript, desc)
        }
        if lower.contains("javascript") || lower.contains("node.js") {
            return (.javaScript, desc)
        }
        if lower.contains("applescript") {
            return (.appleScript, desc)
        }
        if lower.contains("property list") || lower.contains("plist") {
            return (.plist, desc)
        }
        if lower.contains("archive") {
            return (.archive, desc)
        }
        return nil
    }

    private func detectByBundleStructure(fileURL: URL) -> (type: SupportedFileType, detail: String)? {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: fileURL.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return nil
        }

        let infoPlist = fileURL.appendingPathComponent("Contents/Info.plist")
        let macOSDir = fileURL.appendingPathComponent("Contents/MacOS")

        guard fileManager.fileExists(atPath: infoPlist.path) else {
            return nil
        }

        if fileManager.fileExists(atPath: macOSDir.path) {
            return (.appBundle, "Bundle structure matched (Contents/Info.plist + Contents/MacOS)")
        }

        return (.appBundle, "Bundle structure matched (Contents/Info.plist)")
    }

    private func detectByExtension(fileURL: URL) -> (type: SupportedFileType, detail: String)? {
        let type = SupportedFileType.detect(from: fileURL)
        guard type != .unknown else {
            return nil
        }
        return (type, "Extension matched: .\(fileURL.pathExtension.lowercased())")
    }

    private func detectMachO(headerData: Data, headerDescription: String?) -> (isMachO: Bool, type: SupportedFileType, detail: String) {
        if headerData.count >= 16 {
            let bytes = Array(headerData.prefix(16))
            let prefix = Array(bytes.prefix(4))

            if prefix == [0xCA, 0xFE, 0xBA, 0xBE] ||
                prefix == [0xBE, 0xBA, 0xFE, 0xCA] ||
                prefix == [0xCA, 0xFE, 0xBA, 0xBF] ||
                prefix == [0xBF, 0xBA, 0xFE, 0xCA]
            {
                return (true, .machO, "Universal Mach-O magic")
            }

            if let byteOrder = machOByteOrder(prefix: prefix),
               let fileType = readUInt32(headerData, offset: 12, byteOrder: byteOrder)
            {
                if fileType == 0x6 {
                    return (true, .dylib, "Mach-O header (MH_DYLIB)")
                }
                return (true, .machO, "Mach-O header (type=\(fileType))")
            }
        }

        if let headerDescription {
            let lower = headerDescription.lowercased()
            if lower.contains("mach-o") && lower.contains("dynamically linked shared library") {
                return (true, .dylib, "file(1) indicates Mach-O shared library")
            }
            if lower.contains("mach-o") {
                return (true, .machO, "file(1) indicates Mach-O")
            }
        }

        return (false, .unknown, "Not Mach-O")
    }

    private func machOByteOrder(prefix: [UInt8]) -> ByteOrder? {
        if prefix == [0xCE, 0xFA, 0xED, 0xFE] || prefix == [0xCF, 0xFA, 0xED, 0xFE] {
            return .little
        }
        if prefix == [0xFE, 0xED, 0xFA, 0xCE] || prefix == [0xFE, 0xED, 0xFA, 0xCF] {
            return .big
        }
        return nil
    }

    private func readUInt32(_ data: Data, offset: Int, byteOrder: ByteOrder) -> UInt32? {
        guard data.count >= offset + 4 else {
            return nil
        }
        let slice = data.subdata(in: offset..<(offset + 4))
        let bytes = Array(slice)
        switch byteOrder {
        case .little:
            return UInt32(bytes[0]) | UInt32(bytes[1]) << 8 | UInt32(bytes[2]) << 16 | UInt32(bytes[3]) << 24
        case .big:
            return UInt32(bytes[3]) | UInt32(bytes[2]) << 8 | UInt32(bytes[1]) << 16 | UInt32(bytes[0]) << 24
        }
    }

    private enum ByteOrder {
        case little
        case big
    }
}
