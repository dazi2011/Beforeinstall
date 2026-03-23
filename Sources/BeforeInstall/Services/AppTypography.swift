import SwiftUI

enum AppTextStyle {
    case title
    case headline
    case body
    case caption
    case footnote
    case monospacedBody
    case monospacedCaption

    fileprivate var baseSize: CGFloat {
        switch self {
        case .title:
            return 30
        case .headline:
            return 18
        case .body:
            return 14
        case .caption:
            return 12
        case .footnote:
            return 11
        case .monospacedBody:
            return 12
        case .monospacedCaption:
            return 11
        }
    }

    fileprivate var weight: Font.Weight {
        switch self {
        case .title:
            return .bold
        case .headline:
            return .semibold
        case .body, .caption, .footnote, .monospacedBody, .monospacedCaption:
            return .regular
        }
    }

    fileprivate var design: Font.Design {
        switch self {
        case .monospacedBody, .monospacedCaption:
            return .monospaced
        case .title, .headline, .body, .caption, .footnote:
            return .default
        }
    }
}

enum AppLayoutTier {
    case normal
    case large
    case extraLarge

    static func from(fontScale: CGFloat) -> AppLayoutTier {
        if fontScale >= 1.25 {
            return .extraLarge
        }
        if fontScale >= 1.10 {
            return .large
        }
        return .normal
    }
}

enum AppFont {
    static func font(_ style: AppTextStyle, scale: CGFloat) -> Font {
        let normalized = normalizedScale(scale)
        return .system(
            size: style.baseSize * normalized,
            weight: style.weight,
            design: style.design
        )
    }

    private static func normalizedScale(_ scale: CGFloat) -> CGFloat {
        min(max(scale, 0.85), 1.40)
    }
}

struct AppScaleMetrics {
    let fontScale: CGFloat

    init(fontScale: CGFloat) {
        self.fontScale = min(max(fontScale, 0.85), 1.40)
    }

    var layoutTier: AppLayoutTier {
        AppLayoutTier.from(fontScale: fontScale)
    }

    var sectionSpacing: CGFloat {
        scaled(16)
    }

    var groupSpacing: CGFloat {
        scaled(12)
    }

    var rowSpacing: CGFloat {
        scaled(8)
    }

    var cardPadding: CGFloat {
        scaled(20)
    }

    var compactPadding: CGFloat {
        scaled(10)
    }

    var controlHeight: CGFloat {
        scaled(34)
    }

    var iconSize: CGFloat {
        scaled(28)
    }

    var cornerRadius: CGFloat {
        scaled(12)
    }

    func scaled(_ base: CGFloat) -> CGFloat {
        base * layoutScale
    }

    private var layoutScale: CGFloat {
        switch layoutTier {
        case .normal:
            return max(0.92, fontScale)
        case .large:
            return max(1.0, min(1.18, fontScale * 1.03))
        case .extraLarge:
            return min(1.32, fontScale * 1.06)
        }
    }
}

private struct AppFontScaleKey: EnvironmentKey {
    static let defaultValue: CGFloat = 1.0
}

extension EnvironmentValues {
    var appFontScale: CGFloat {
        get { self[AppFontScaleKey.self] }
        set { self[AppFontScaleKey.self] = newValue }
    }
}

extension View {
    func appFont(_ style: AppTextStyle, scale: CGFloat) -> some View {
        font(AppFont.font(style, scale: scale))
    }

    func appFont(_ style: AppTextStyle, metrics: AppScaleMetrics) -> some View {
        font(AppFont.font(style, scale: metrics.fontScale))
    }
}

struct AdaptiveStack<Content: View>: View {
    let tier: AppLayoutTier
    let spacing: CGFloat
    let content: () -> Content

    init(tier: AppLayoutTier, spacing: CGFloat, @ViewBuilder content: @escaping () -> Content) {
        self.tier = tier
        self.spacing = spacing
        self.content = content
    }

    var body: some View {
        Group {
            if tier == .normal {
                HStack(alignment: .top, spacing: spacing) {
                    content()
                }
            } else {
                VStack(alignment: .leading, spacing: spacing) {
                    content()
                }
            }
        }
    }
}
