import SwiftUI
import UniformTypeIdentifiers

struct DropZoneView: View {
    let hintText: String
    let supportText: String
    let buttonText: String
    let onDropFiles: ([URL]) -> Void
    let onSelectFiles: () -> Void

    @State private var isTargeted = false
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.appFontScale) private var appFontScale

    var body: some View {
        VStack(spacing: metrics.groupSpacing) {
            Image(systemName: "tray.and.arrow.down")
                .font(.system(size: metrics.iconSize, weight: .medium))
                .foregroundStyle(Color.accentColor)

            Text(hintText)
                .appFont(.headline, metrics: metrics)

            Text(supportText)
                .appFont(.footnote, metrics: metrics)
                .foregroundStyle(.secondary)

            Button(buttonText) {
                onSelectFiles()
            }
            .buttonStyle(.borderedProminent)
            .frame(minHeight: metrics.controlHeight)
        }
        .frame(maxWidth: .infinity)
        .frame(minHeight: metrics.scaled(180))
        .padding(metrics.cardPadding)
        .background(
            RoundedRectangle(cornerRadius: metrics.cornerRadius)
                .fill(isTargeted ? Color.accentColor.opacity(0.12) : Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: metrics.cornerRadius)
                .stroke(
                    isTargeted
                    ? Color.accentColor
                    : Color(nsColor: colorScheme == .dark ? .separatorColor : .tertiaryLabelColor),
                    style: StrokeStyle(lineWidth: 1.5, dash: [6])
                )
        )
        .onDrop(of: [UTType.fileURL.identifier], isTargeted: $isTargeted) { providers in
            guard !providers.isEmpty else { return false }
            loadDroppedFileURLs(from: providers)
            return true
        }
    }

    private func loadDroppedFileURLs(from providers: [NSItemProvider]) {
        let group = DispatchGroup()
        let collector = URLCollector()

        for provider in providers where provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            group.enter()
            provider.loadDataRepresentation(forTypeIdentifier: UTType.fileURL.identifier) { data, _ in
                defer { group.leave() }
                guard let data,
                      let raw = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                      let url = URL(string: raw)
                else {
                    return
                }
                collector.append(url)
            }
        }

        group.notify(queue: .main) {
            let deduped = collector.snapshot()
                .map { $0.standardizedFileURL }
                .uniquePreservingOrder()
            guard !deduped.isEmpty else { return }
            onDropFiles(deduped)
        }
    }

    private final class URLCollector: @unchecked Sendable {
        private let lock = NSLock()
        private var urls: [URL] = []

        func append(_ url: URL) {
            lock.lock()
            urls.append(url)
            lock.unlock()
        }

        func snapshot() -> [URL] {
            lock.lock()
            let value = urls
            lock.unlock()
            return value
        }
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: appFontScale)
    }
}
