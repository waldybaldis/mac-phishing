import Foundation
import Security

/// Simple wrapper around the macOS Keychain for storing credentials.
enum KeychainHelper {

    private static let service = "com.phishguard.app"

    /// Saves data to the Keychain under the given key.
    @discardableResult
    static func save(key: String, data: Data) -> Bool {
        // Delete any existing item first
        delete(key: key)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Saves a string to the Keychain.
    @discardableResult
    static func save(key: String, string: String) -> Bool {
        guard let data = string.data(using: .utf8) else { return false }
        return save(key: key, data: data)
    }

    /// Loads data from the Keychain for the given key.
    static func load(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    /// Loads a string from the Keychain.
    static func loadString(key: String) -> String? {
        guard let data = load(key: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Deletes an item from the Keychain.
    @discardableResult
    static func delete(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    // MARK: - Convenience for OAuth tokens

    static func saveTokens(accountId: String, accessToken: String, refreshToken: String?) {
        save(key: "\(accountId).accessToken", string: accessToken)
        if let refreshToken = refreshToken {
            save(key: "\(accountId).refreshToken", string: refreshToken)
        }
    }

    static func loadAccessToken(accountId: String) -> String? {
        loadString(key: "\(accountId).accessToken")
    }

    static func loadRefreshToken(accountId: String) -> String? {
        loadString(key: "\(accountId).refreshToken")
    }

    static func savePassword(accountId: String, password: String) {
        save(key: "\(accountId).password", string: password)
    }

    static func loadPassword(accountId: String) -> String? {
        loadString(key: "\(accountId).password")
    }

    static func deleteCredentials(accountId: String) {
        delete(key: "\(accountId).accessToken")
        delete(key: "\(accountId).refreshToken")
        delete(key: "\(accountId).password")
    }
}
