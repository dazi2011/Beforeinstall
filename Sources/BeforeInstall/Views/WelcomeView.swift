import SwiftUI

struct WelcomeView: View {
    @ObservedObject var settings: AppSettingsStore
    @Binding var isPresented: Bool
    @State private var permissionStatusText: String?
    @State private var permissionItems: [PermissionHealthItem] = []
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.appFontScale) private var appFontScale

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.groupSpacing) {
            Text(Localizer.text("welcome.title", language: settings.language))
                .appFont(.headline, metrics: metrics)
                .fontWeight(.bold)

            Text(Localizer.text("welcome.subtitle", language: settings.language))
                .appFont(.body, metrics: metrics)
                .foregroundStyle(.secondary)

            Text(Localizer.text("welcome.capability", language: settings.language))
                .appFont(.footnote, metrics: metrics)

            if fullDiskStatus == .granted {
                Text(Localizer.text("welcome.permissionAlreadyGrantedIntro", language: settings.language))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            } else {
                Text(Localizer.text("welcome.permissionNote", language: settings.language))
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.orange)

                GroupBox(Localizer.text("welcome.permissionHealth", language: settings.language)) {
                    VStack(alignment: .leading, spacing: metrics.rowSpacing) {
                        ForEach(permissionItems) { item in
                            permissionRow(item)
                        }

                        Text(Localizer.text("welcome.permissionDetectionNote", language: settings.language))
                            .appFont(.caption, metrics: metrics)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.top, metrics.compactPadding * 0.4)
                }
                .appFont(.body, metrics: metrics)

                Button(Localizer.text("welcome.openFullDisk", language: settings.language)) {
                    PermissionGuidanceService.openFullDiskAccess()
                    permissionStatusText = Localizer.text("welcome.openedSystemSettings", language: settings.language)
                    refreshPermissionItems(withDelay: true)
                }
                .buttonStyle(.borderedProminent)
            }

            if let permissionStatusText {
                Text(permissionStatusText)
                    .appFont(.footnote, metrics: metrics)
                    .foregroundStyle(.secondary)
            }

            HStack {
                Spacer()
                Button(Localizer.text("welcome.continue", language: settings.language)) {
                    settings.markWelcomeShownAtLeastOnce()
                    isPresented = false
                }
                .buttonStyle(.borderedProminent)
                .appFont(.body, metrics: metrics)
            }
        }
        .frame(width: 860, alignment: .topLeading)
        .fixedSize(horizontal: false, vertical: true)
        .padding(metrics.cardPadding)
        .appFont(.body, metrics: metrics)
        .onAppear {
            refreshPermissionItems(withDelay: false)
        }
        .onChange(of: settings.language) { _ in
            refreshPermissionItems(withDelay: false)
        }
        .onChange(of: scenePhase) { phase in
            if phase == .active {
                refreshPermissionItems(withDelay: false)
            }
        }
        .onDisappear {
            settings.markWelcomeShownAtLeastOnce()
        }
    }

    private var fullDiskStatus: PermissionHealthStatus {
        permissionItems.first(where: { $0.id == "full_disk" })?.status ?? .unknown
    }

    private func refreshPermissionItems(withDelay: Bool) {
        if withDelay {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                permissionItems = PermissionGuidanceService.permissionHealthItems(
                    language: settings.language,
                    includeAccessibility: false,
                    includeAutomation: false
                )
            }
        } else {
            permissionItems = PermissionGuidanceService.permissionHealthItems(
                language: settings.language,
                includeAccessibility: false,
                includeAutomation: false
            )
        }
    }

    private func permissionRow(_ item: PermissionHealthItem) -> some View {
        HStack(alignment: .top, spacing: metrics.rowSpacing) {
            Image(systemName: statusSymbol(item.status))
                .foregroundStyle(statusColor(item.status))
                .frame(width: metrics.scaled(16))
                .appFont(.body, metrics: metrics)

            VStack(alignment: .leading, spacing: metrics.compactPadding * 0.2) {
                HStack(spacing: 6) {
                    Text(item.title)
                        .appFont(.body, metrics: metrics)
                        .fontWeight(.semibold)
                    Text(statusLabel(item.status))
                        .appFont(.caption, metrics: metrics)
                        .foregroundStyle(statusColor(item.status))
                }
                Text(item.impact)
                    .appFont(.caption, metrics: metrics)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if item.status == .notGranted {
                Button(Localizer.text("welcome.permissionAction", language: settings.language)) {
                    PermissionGuidanceService.performAction(item.action)
                    refreshPermissionItems(withDelay: true)
                }
                .buttonStyle(.bordered)
                .appFont(.body, metrics: metrics)
            }
        }
    }

    private func statusSymbol(_ status: PermissionHealthStatus) -> String {
        switch status {
        case .granted:
            return "checkmark.circle.fill"
        case .notGranted:
            return "xmark.circle.fill"
        case .unknown:
            return "questionmark.circle.fill"
        }
    }

    private func statusColor(_ status: PermissionHealthStatus) -> Color {
        switch status {
        case .granted:
            return .green
        case .notGranted:
            return .orange
        case .unknown:
            return .secondary
        }
    }

    private func statusLabel(_ status: PermissionHealthStatus) -> String {
        switch status {
        case .granted:
            return Localizer.text("welcome.permissionGrantedMark", language: settings.language)
        case .notGranted:
            return Localizer.text("welcome.permissionMissingMark", language: settings.language)
        case .unknown:
            return Localizer.text("welcome.permissionUnknownMark", language: settings.language)
        }
    }

    private var metrics: AppScaleMetrics {
        AppScaleMetrics(fontScale: appFontScale)
    }
}
