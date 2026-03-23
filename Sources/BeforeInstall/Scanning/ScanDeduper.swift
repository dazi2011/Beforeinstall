import Foundation

final class ScanDeduper {
    private let fileManager = FileManager.default

    func dedupe(_ items: [ScanItem]) -> [ScanItem] {
        var seenPaths = Set<String>()
        var seenResourceIDs = Set<String>()
        var seenHashes = Set<String>()
        var output: [ScanItem] = []

        for item in items {
            let standardizedPath = URL(fileURLWithPath: item.path).standardizedFileURL.path
            if seenPaths.contains(standardizedPath) {
                continue
            }

            if let resourceID = fileResourceIdentity(path: standardizedPath),
               seenResourceIDs.contains(resourceID) {
                continue
            }

            if let hash = item.hash, shouldUseHashForDedupe(item: item) {
                if seenHashes.contains(hash) {
                    continue
                }
                seenHashes.insert(hash)
            }

            seenPaths.insert(standardizedPath)
            if let resourceID = fileResourceIdentity(path: standardizedPath) {
                seenResourceIDs.insert(resourceID)
            }
            output.append(item)
        }

        return output
    }

    private func shouldUseHashForDedupe(item: ScanItem) -> Bool {
        item.isExecutable || item.fileType.isExecutableLike || item.fileType == .plist
    }

    private func fileResourceIdentity(path: String) -> String? {
        let url = URL(fileURLWithPath: path)
        if let values = try? url.resourceValues(forKeys: [.fileResourceIdentifierKey]),
           let resourceID = values.fileResourceIdentifier {
            return String(describing: resourceID)
        }

        guard let attrs = try? fileManager.attributesOfItem(atPath: path),
              let inode = attrs[.systemFileNumber] as? NSNumber,
              let dev = attrs[.systemNumber] as? NSNumber
        else {
            return nil
        }
        return "\(dev.intValue):\(inode.intValue)"
    }
}
