import AuthenticationServices
import CryptoKit
import Foundation

/// Result of a successful OAuth2 authentication.
struct OAuthTokens {
    let accessToken: String
    let refreshToken: String?
    let expiresIn: Int?
}

/// Handles OAuth2 authentication flows using ASWebAuthenticationSession with PKCE.
@MainActor
final class OAuthManager: NSObject, ObservableObject {

    @Published var isAuthenticating = false

    /// Authenticates with the given provider via browser-based OAuth2 + PKCE.
    func authenticate(provider: OAuthConfig.Provider) async throws -> OAuthTokens {
        isAuthenticating = true
        defer { isAuthenticating = false }

        // Generate PKCE code verifier and challenge
        let codeVerifier = generateCodeVerifier()
        let codeChallenge = generateCodeChallenge(from: codeVerifier)

        // Build the authorization URL
        let authURL = buildAuthURL(provider: provider, codeChallenge: codeChallenge)
        let redirectScheme = OAuthConfig.redirectScheme(for: provider)

        // Open browser for user authentication
        let callbackURL = try await startWebAuthSession(url: authURL, callbackScheme: redirectScheme)

        // Extract the authorization code from callback
        guard let code = extractAuthCode(from: callbackURL) else {
            throw OAuthError.missingAuthCode
        }

        // Exchange code for tokens
        return try await exchangeCodeForTokens(provider: provider, code: code, codeVerifier: codeVerifier)
    }

    /// Refreshes an expired access token using a refresh token.
    func refreshAccessToken(provider: OAuthConfig.Provider, refreshToken: String) async throws -> OAuthTokens {
        let tokenURL = OAuthConfig.tokenURL(for: provider)
        let clientID = OAuthConfig.clientID(for: provider)

        var params = [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": clientID,
        ]

        // Microsoft requires scope on refresh
        if provider == .microsoft {
            params["scope"] = OAuthConfig.scopes(for: provider)
        }

        return try await postTokenRequest(url: tokenURL, params: params)
    }

    // MARK: - PKCE

    private func generateCodeVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func generateCodeChallenge(from verifier: String) -> String {
        let data = Data(verifier.utf8)
        let hash = SHA256.hash(data: data)
        return Data(hash)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    // MARK: - URL Building

    private func buildAuthURL(provider: OAuthConfig.Provider, codeChallenge: String) -> URL {
        var components = URLComponents(url: OAuthConfig.authURL(for: provider), resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: OAuthConfig.clientID(for: provider)),
            URLQueryItem(name: "redirect_uri", value: OAuthConfig.redirectURI(for: provider)),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: OAuthConfig.scopes(for: provider)),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "access_type", value: "offline"),
            URLQueryItem(name: "prompt", value: "consent"),
        ]
        return components.url!
    }

    // MARK: - Web Auth Session

    private func startWebAuthSession(url: URL, callbackScheme: String) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: callbackScheme
            ) { callbackURL, error in
                if let error = error {
                    if (error as NSError).code == ASWebAuthenticationSessionError.canceledLogin.rawValue {
                        continuation.resume(throwing: OAuthError.userCancelled)
                    } else {
                        continuation.resume(throwing: OAuthError.webAuthFailed(error.localizedDescription))
                    }
                    return
                }
                guard let callbackURL = callbackURL else {
                    continuation.resume(throwing: OAuthError.missingCallback)
                    return
                }
                continuation.resume(returning: callbackURL)
            }

            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = false
            session.start()
        }
    }

    // MARK: - Token Exchange

    private func extractAuthCode(from url: URL) -> String? {
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        return components?.queryItems?.first(where: { $0.name == "code" })?.value
    }

    private func exchangeCodeForTokens(
        provider: OAuthConfig.Provider,
        code: String,
        codeVerifier: String
    ) async throws -> OAuthTokens {
        let tokenURL = OAuthConfig.tokenURL(for: provider)
        let clientID = OAuthConfig.clientID(for: provider)
        let redirectURI = OAuthConfig.redirectURI(for: provider)

        let params = [
            "grant_type": "authorization_code",
            "code": code,
            "client_id": clientID,
            "redirect_uri": redirectURI,
            "code_verifier": codeVerifier,
        ]

        return try await postTokenRequest(url: tokenURL, params: params)
    }

    private func postTokenRequest(url: URL, params: [String: String]) async throws -> OAuthTokens {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let body = params.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }
            .joined(separator: "&")
        request.httpBody = body.data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.tokenExchangeFailed("Invalid response")
        }

        guard httpResponse.statusCode == 200 else {
            let errorBody = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw OAuthError.tokenExchangeFailed("HTTP \(httpResponse.statusCode): \(errorBody)")
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let accessToken = json["access_token"] as? String else {
            throw OAuthError.tokenExchangeFailed("Missing access_token in response")
        }

        return OAuthTokens(
            accessToken: accessToken,
            refreshToken: json["refresh_token"] as? String,
            expiresIn: json["expires_in"] as? Int
        )
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding

extension OAuthManager: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        NSApp.keyWindow ?? NSApp.windows.first ?? ASPresentationAnchor()
    }
}

// MARK: - Errors

enum OAuthError: LocalizedError {
    case userCancelled
    case missingAuthCode
    case missingCallback
    case webAuthFailed(String)
    case tokenExchangeFailed(String)
    case noRefreshToken

    var errorDescription: String? {
        switch self {
        case .userCancelled: return "Sign-in was cancelled"
        case .missingAuthCode: return "No authorization code received"
        case .missingCallback: return "No callback URL received"
        case .webAuthFailed(let msg): return "Authentication failed: \(msg)"
        case .tokenExchangeFailed(let msg): return "Token exchange failed: \(msg)"
        case .noRefreshToken: return "No refresh token available"
        }
    }
}
