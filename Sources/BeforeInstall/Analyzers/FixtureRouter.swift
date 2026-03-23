import Foundation

enum FixtureRoute: String, Sendable {
    case none
    case appBundle
    case pkgFixture
    case hybridFixture
    case manifestFixture
    case descriptorFixture

    var overrideType: SupportedFileType? {
        switch self {
        case .appBundle:
            return .appBundle
        case .pkgFixture:
            return .pkg
        case .hybridFixture:
            return .archive
        case .manifestFixture, .descriptorFixture, .none:
            return nil
        }
    }
}

final class FixtureRouter {
    private let fileManager = FileManager.default

    func route(fileURL: URL, detectedType: SupportedFileType) -> FixtureRoute {
        let standardized = fileURL.standardizedFileURL
        var isDirectory: ObjCBool = false
        let exists = fileManager.fileExists(atPath: standardized.path, isDirectory: &isDirectory)

        if exists, isDirectory.boolValue {
            return routeDirectory(standardized, detectedType: detectedType)
        }

        if standardized.pathExtension.lowercased() == "json" {
            let parent = standardized.deletingLastPathComponent().lastPathComponent.lowercased()
            if parent == "app" || parent == "hybrid" {
                return .manifestFixture
            }
            if parent == "pkg" {
                return .descriptorFixture
            }
        }

        return .none
    }

    private func routeDirectory(_ directoryURL: URL, detectedType: SupportedFileType) -> FixtureRoute {
        if detectedType == .appBundle || directoryURL.pathExtension.lowercased() == "app" {
            return .appBundle
        }

        let hasInfoPlist = fileManager.fileExists(atPath: directoryURL.appendingPathComponent("Contents/Info.plist").path)
        let hasMacOS = fileManager.fileExists(atPath: directoryURL.appendingPathComponent("Contents/MacOS").path)
        if hasInfoPlist || hasMacOS {
            return .appBundle
        }

        let hasScripts = fileManager.fileExists(atPath: directoryURL.appendingPathComponent("scripts").path)
        let hasPayload = fileManager.fileExists(atPath: directoryURL.appendingPathComponent("payload").path)
        let hasPackageInfo = fileManager.fileExists(atPath: directoryURL.appendingPathComponent("PackageInfo.json").path)
        if hasScripts && (hasPayload || hasPackageInfo) {
            return .pkgFixture
        }

        let hasNestedApp = containsNestedDirectory(directoryURL, extension: "app")
        let hasNestedPkg = containsNestedDirectory(directoryURL, extension: "pkg")
        let hasRootCommand = containsRootScript(directoryURL)

        if (hasNestedApp || hasNestedPkg) && (hasScripts || hasRootCommand) {
            return .hybridFixture
        }
        if hasNestedApp {
            return .hybridFixture
        }

        return .none
    }

    private func containsNestedDirectory(_ root: URL, extension ext: String) -> Bool {
        guard let enumerator = fileManager.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles],
            errorHandler: nil
        ) else {
            return false
        }

        let baseDepth = root.pathComponents.count
        for case let url as URL in enumerator {
            let depth = url.pathComponents.count - baseDepth
            if depth > 3 {
                enumerator.skipDescendants()
                continue
            }
            if url.pathExtension.lowercased() == ext {
                return true
            }
        }
        return false
    }

    private func containsRootScript(_ root: URL) -> Bool {
        guard let items = try? fileManager.contentsOfDirectory(at: root, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
            return false
        }

        return items.contains { item in
            let ext = item.pathExtension.lowercased()
            return ["sh", "command", "py", "js", "applescript", "scpt"].contains(ext)
        }
    }
}
