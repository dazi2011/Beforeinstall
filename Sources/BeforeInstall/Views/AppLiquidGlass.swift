import SwiftUI

struct AppLiquidGlassBackdrop: View {
    var body: some View {
        Rectangle()
            .fill(.clear)
        .ignoresSafeArea()
    }
}

struct AppLiquidGlassGroupBoxStyle: GroupBoxStyle {
    let metrics: AppScaleMetrics

    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading, spacing: metrics.rowSpacing) {
            configuration.label
                .appFont(.body, metrics: metrics)
                .fontWeight(.semibold)
                .foregroundStyle(.primary)

            configuration.content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(metrics.cardPadding)
        .appGlassPanel(metrics: metrics)
    }
}

private struct AppGlassPanelModifier: ViewModifier {
    let metrics: AppScaleMetrics
    let tint: Color?
    let interactive: Bool
    let cornerRadius: CGFloat?
    let fallbackFillOpacity: Double
    let emphasized: Bool

    @Environment(\.colorScheme) private var colorScheme

    @ViewBuilder
    func body(content: Content) -> some View {
        let radius = cornerRadius ?? metrics.cornerRadius
        let shape = RoundedRectangle(cornerRadius: radius, style: .continuous)

        if #available(macOS 26.0, *) {
            content
                .glassEffect(glass, in: shape)
                .overlay {
                    shape.strokeBorder(strokeColor, lineWidth: strokeWidth)
                }
                .shadow(
                    color: shadowColor,
                    radius: metrics.scaled(emphasized ? 18 : 14),
                    x: 0,
                    y: metrics.scaled(emphasized ? 10 : 7)
                )
        } else {
            content
                .background {
                    shape.fill(fallbackFill)
                }
                .overlay {
                    shape.strokeBorder(strokeColor, lineWidth: strokeWidth)
                }
                .shadow(
                    color: shadowColor,
                    radius: metrics.scaled(emphasized ? 18 : 14),
                    x: 0,
                    y: metrics.scaled(emphasized ? 10 : 7)
                )
        }
    }

    private var fallbackFill: Color {
        Color(nsColor: colorScheme == .dark ? .controlBackgroundColor : .windowBackgroundColor)
            .opacity(emphasized ? min(fallbackFillOpacity + 0.04, 1.0) : fallbackFillOpacity)
    }

    private var strokeColor: Color {
        colorScheme == .dark
        ? Color.white.opacity(emphasized ? 0.18 : 0.12)
        : Color.white.opacity(emphasized ? 0.82 : 0.68)
    }

    private var strokeWidth: CGFloat {
        emphasized ? 1.2 : 1
    }

    private var shadowColor: Color {
        Color.black.opacity(colorScheme == .dark ? 0.22 : 0.08)
    }

    @available(macOS 26.0, *)
    private var glass: Glass {
        var value = Glass.regular
        if let tint {
            value = value.tint(tint)
        }
        if interactive {
            value = value.interactive()
        }
        return value
    }
}

private struct AppGlassBadgeModifier: ViewModifier {
    let tint: Color
    let metrics: AppScaleMetrics

    func body(content: Content) -> some View {
        content
            .padding(.horizontal, metrics.scaled(10))
            .padding(.vertical, metrics.scaled(4))
            .appGlassPanel(
                metrics: metrics,
                interactive: true,
                cornerRadius: metrics.scaled(999),
                fallbackFillOpacity: 0.96,
                emphasized: true
            )
    }
}

private struct AppPrimaryButtonStyleModifier: ViewModifier {
    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content
                .buttonStyle(.glass)
                .fontWeight(.semibold)
        } else {
            content
                .buttonStyle(.bordered)
                .fontWeight(.semibold)
        }
    }
}

private struct AppSecondaryButtonStyleModifier: ViewModifier {
    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content.buttonStyle(.glass)
        } else {
            content.buttonStyle(.bordered)
        }
    }
}

extension View {
    func appLiquidGlassScene(metrics: AppScaleMetrics) -> some View {
        ZStack {
            AppLiquidGlassBackdrop()
            self
        }
        .appWindowGlassBackground()
        .groupBoxStyle(AppLiquidGlassGroupBoxStyle(metrics: metrics))
    }

    @ViewBuilder
    func appWindowGlassBackground() -> some View {
        if #available(macOS 26.0, *) {
            self
                .backgroundExtensionEffect()
                .containerBackground(.windowBackground, for: .window)
        } else if #available(macOS 15.0, *) {
            self.containerBackground(.windowBackground, for: .window)
        } else {
            self.background(Color(nsColor: .windowBackgroundColor))
        }
    }

    func appGlassPanel(
        metrics: AppScaleMetrics,
        tint: Color? = nil,
        interactive: Bool = false,
        cornerRadius: CGFloat? = nil,
        fallbackFillOpacity: Double = 0.92,
        emphasized: Bool = false
    ) -> some View {
        modifier(
            AppGlassPanelModifier(
                metrics: metrics,
                tint: tint,
                interactive: interactive,
                cornerRadius: cornerRadius,
                fallbackFillOpacity: fallbackFillOpacity,
                emphasized: emphasized
            )
        )
    }

    @ViewBuilder
    func appGlassCluster(spacing: CGFloat? = nil) -> some View {
        if #available(macOS 26.0, *) {
            GlassEffectContainer(spacing: spacing) {
                self
            }
        } else {
            self
        }
    }

    func appGlassBadge(tint: Color, metrics: AppScaleMetrics) -> some View {
        modifier(AppGlassBadgeModifier(tint: tint, metrics: metrics))
    }

    @ViewBuilder
    func appLiquidPalettePickerStyle() -> some View {
        if #available(macOS 14.0, *) {
            self
                .pickerStyle(.palette)
                .paletteSelectionEffect(.automatic)
        } else {
            self.pickerStyle(.segmented)
        }
    }

    func appPrimaryButtonStyle() -> some View {
        modifier(AppPrimaryButtonStyleModifier())
    }

    func appSecondaryButtonStyle() -> some View {
        modifier(AppSecondaryButtonStyleModifier())
    }
}
