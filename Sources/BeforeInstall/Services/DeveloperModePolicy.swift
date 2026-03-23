import Foundation

enum BuildChannel: String, Sendable {
    case debug
    case internalBuild
    case release
}

enum DeveloperModePolicy {
    static var buildChannel: BuildChannel {
        #if DEBUG
        return .debug
        #elseif INTERNAL_BUILD
        return .internalBuild
        #else
        return .release
        #endif
    }

    static var shouldEnableDeveloperModeByDefault: Bool {
        false
    }

    static var buildLabel: String {
        switch buildChannel {
        case .debug:
            return "Debug"
        case .internalBuild:
            return "Internal"
        case .release:
            return "Release"
        }
    }
}
