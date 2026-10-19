import Foundation

/// Sign-in hook for Red-XAI Accounts (OIDC, authorization code + PKCE; contract in red-xai-accounts
/// docs/API.md). Not live yet: the stub says "coming soon". Age rules (13 and up) are enforced by Red-XAI
/// Accounts and the store, not by RottenCore.
public protocol AccountProvider {
    var isAvailable: Bool { get }
    var displayName: String? { get }
    func signIn() async throws
    func signOut() async
}

public struct AccountsComingSoon: Error, LocalizedError {
    public var errorDescription: String? { "Red-XAI Accounts sign-in is coming soon." }
}

public final class RedXAIAccountsStub: AccountProvider {
    public init() {}
    public var isAvailable: Bool { false }
    public var displayName: String? { nil }
    public func signIn() async throws { throw AccountsComingSoon() }
    public func signOut() async {}
}

/// Appearance: dark by default, with system and light options.
public enum Theme: String, CaseIterable, Identifiable {
    case dark, system, light
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .dark: return "Dark"
        case .system: return "System"
        case .light: return "Light"
        }
    }
}
