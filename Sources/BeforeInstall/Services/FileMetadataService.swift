import Foundation

enum FileMetadataError: LocalizedError {
    case fileNotFound
    case unreadable
    case attributesFailed(String)

    var errorDescription: String? {
        switch self {
        case .fileNotFound:
            return "文件不存在"
        case .unreadable:
            return "没有权限读取该文件"
        case let .attributesFailed(message):
            return "无法读取文件属性：\(message)"
        }
    }
}

final class FileMetadataService {
    private let fileManager = FileManager.default

    func basicInfo(for fileURL: URL, detectedType: SupportedFileType? = nil) -> Result<FileBasicInfo, FileMetadataError> {
        guard fileManager.fileExists(atPath: fileURL.path) else {
            return .failure(.fileNotFound)
        }

        guard fileManager.isReadableFile(atPath: fileURL.path) else {
            return .failure(.unreadable)
        }

        do {
            let attributes = try fileManager.attributesOfItem(atPath: fileURL.path)
            let size = (attributes[.size] as? NSNumber)?.int64Value ?? 0
            let created = attributes[.creationDate] as? Date
            let modified = attributes[.modificationDate] as? Date
            let resolvedType = detectedType ?? SupportedFileType.detect(from: fileURL)

            let info = FileBasicInfo(
                fileName: fileURL.lastPathComponent,
                fullPath: fileURL.path,
                fileType: resolvedType,
                fileSizeBytes: size,
                createdAt: created,
                modifiedAt: modified
            )
            return .success(info)
        } catch {
            return .failure(.attributesFailed(error.localizedDescription))
        }
    }

    func makeFallbackInfo(for fileURL: URL, detectedType: SupportedFileType = .unknown) -> FileBasicInfo {
        return FileBasicInfo(
            fileName: fileURL.lastPathComponent,
            fullPath: fileURL.path,
            fileType: detectedType,
            fileSizeBytes: 0,
            createdAt: nil,
            modifiedAt: nil
        )
    }
}
