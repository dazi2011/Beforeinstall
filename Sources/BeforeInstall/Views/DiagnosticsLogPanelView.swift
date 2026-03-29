import SwiftUI

struct DiagnosticsLogPanelView: View {
    @ObservedObject var settings: AppSettingsStore
    @ObservedObject private var logService = DiagnosticsLogService.shared
    @Environment(\.dismiss) private var dismiss
    @Environment(\.appFontScale) private var appFontScale
    @State private var includeDebug = false
    @State private var exportMessage: String?

    private var entries: [DiagnosticLogEntry] {
        let base = includeDebug ? logService.entries : logService.entries.filter { $0.level != .debug }
        return base.sorted { $0.timestamp > $1.timestamp }
    }

    var body: some View {
        ZStack {
            AppLiquidGlassBackdrop()

            VStack(alignment: .leading, spacing: metrics.groupSpacing) {
                HStack {
                    Text(settings.language == .zhHans ? "运行日志" : "Runtime Logs")
                        .appFont(.headline, metrics: metrics)

                    Spacer()

                    Toggle(settings.language == .zhHans ? "包含 debug" : "Include debug", isOn: $includeDebug)
                        .toggleStyle(.checkbox)
                        .appFont(.caption, metrics: metrics)

                    Button(settings.language == .zhHans ? "导出" : "Export") {
                        do {
                            let url = try logService.export(includeDebug: includeDebug)
                            exportMessage = (settings.language == .zhHans ? "已导出：" : "Exported: ") + url.path
                        } catch {
                            exportMessage = (settings.language == .zhHans ? "导出失败：" : "Export failed: ") + error.localizedDescription
                        }
                    }
                    .appSecondaryButtonStyle()

                    Button(settings.language == .zhHans ? "关闭" : "Close") {
                        dismiss()
                    }
                    .appPrimaryButtonStyle()
                }

                Text(settings.language == .zhHans
                     ? "记录自本次 App 启动以来的关键操作。"
                     : "Entries include key operations since this app launch.")
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)

                if let exportMessage, !exportMessage.isEmpty {
                    Text(exportMessage)
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }

                if entries.isEmpty {
                    Text(settings.language == .zhHans ? "暂无日志记录。" : "No log entries.")
                        .appFont(.footnote, metrics: metrics)
                        .foregroundStyle(.secondary)
                } else {
                    Table(entries.prefix(1200)) {
                        TableColumn(settings.language == .zhHans ? "时间" : "Time") { entry in
                            Text(formatDate(entry.timestamp))
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(settings.language == .zhHans ? "级别" : "Level") { entry in
                            Text(levelName(entry.level))
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(settings.language == .zhHans ? "分类" : "Category") { entry in
                            Text(entry.category)
                                .appFont(.caption, metrics: metrics)
                        }
                        TableColumn(settings.language == .zhHans ? "消息" : "Message") { entry in
                            Text(entry.message)
                                .appFont(.caption, metrics: metrics)
                                .lineLimit(2)
                        }
                    }
                    .frame(minHeight: 360)
                }
            }
            .padding(metrics.cardPadding)
            .frame(minWidth: 920, minHeight: 580)
        }
        .appWindowGlassBackground()
    }

    private func levelName(_ level: LogLevel) -> String {
        switch (level, settings.language) {
        case (.debug, .zhHans): return "调试"
        case (.info, .zhHans): return "信息"
        case (.warning, .zhHans): return "警告"
        case (.error, .zhHans): return "错误"
        case (.debug, .en): return "Debug"
        case (.info, .en): return "Info"
        case (.warning, .en): return "Warning"
        case (.error, .en): return "Error"
        }
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: appFontScale)
    }
}
