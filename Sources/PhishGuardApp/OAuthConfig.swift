import Foundation

/// OAuth2 configuration for supported providers.
enum OAuthConfig {

    enum Provider: String {
        case google
        case microsoft
    }

    // MARK: - Google

    /// Register at console.cloud.google.com -> Credentials -> OAuth client ID (iOS type)
    /// Replace with your real client ID to enable "Sign in with Google"
    static let googleClientID = "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com"
    static let googleAuthURL = URL(string: "https://accounts.google.com/o/oauth2/v2/auth")!
    static let googleTokenURL = URL(string: "https://oauth2.googleapis.com/token")!
    static let googleScopes = "https://mail.google.com/"
    /// Redirect scheme is the reversed client ID (e.g. com.googleusercontent.apps.YOUR_ID)
    static var googleRedirectScheme: String {
        googleClientID.components(separatedBy: ".").reversed().joined(separator: ".")
    }
    static var googleRedirectURI: String {
        "\(googleRedirectScheme):/oauth2callback"
    }

    // MARK: - Microsoft

    /// Register at portal.azure.com -> App registrations -> add redirect URI
    static let microsoftClientID = "YOUR_MICROSOFT_CLIENT_ID"
    static let microsoftAuthURL = URL(string: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize")!
    static let microsoftTokenURL = URL(string: "https://login.microsoftonline.com/common/oauth2/v2.0/token")!
    static let microsoftScopes = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
    static let microsoftRedirectScheme = "msauth.com.phishguard.app"
    static var microsoftRedirectURI: String {
        "\(microsoftRedirectScheme)://auth"
    }

    // MARK: - Helpers

    static func authURL(for provider: Provider) -> URL {
        switch provider {
        case .google: return googleAuthURL
        case .microsoft: return microsoftAuthURL
        }
    }

    static func tokenURL(for provider: Provider) -> URL {
        switch provider {
        case .google: return googleTokenURL
        case .microsoft: return microsoftTokenURL
        }
    }

    static func clientID(for provider: Provider) -> String {
        switch provider {
        case .google: return googleClientID
        case .microsoft: return microsoftClientID
        }
    }

    static func scopes(for provider: Provider) -> String {
        switch provider {
        case .google: return googleScopes
        case .microsoft: return microsoftScopes
        }
    }

    static func redirectURI(for provider: Provider) -> String {
        switch provider {
        case .google: return googleRedirectURI
        case .microsoft: return microsoftRedirectURI
        }
    }

    static func redirectScheme(for provider: Provider) -> String {
        switch provider {
        case .google: return googleRedirectScheme
        case .microsoft: return microsoftRedirectScheme
        }
    }

    /// Returns true if a real (non-placeholder) client ID is configured for the provider.
    static func isConfigured(for provider: Provider) -> Bool {
        let clientID = clientID(for: provider)
        return !clientID.contains("YOUR_") && !clientID.isEmpty
    }
}
