import Foundation
import Security

/// Simple wrapper around the macOS Keychain for storing credentials.
/// All credentials are stored in a single Keychain item as a JSON dictionary
/// so that only one password prompt is needed on app launch.
enum KeychainHelper {

    private static let service = "com.phishguard.app"
    private static let vaultKey = "credentials"

    // MARK: - Vault (single Keychain item holding all credentials)

    private static func loadVault() -> [String: String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultKey,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let dict = try? JSONDecoder().decode([String: String].self, from: data) else {
            return [:]
        }
        return dict
    }

    private static func saveVault(_ vault: [String: String]) {
        guard let data = try? JSONEncoder().encode(vault) else { return }

        // Delete existing item first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultKey,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultKey,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    // MARK: - Public API (unchanged interface)

    @discardableResult
    static func save(key: String, data: Data) -> Bool {
        guard let string = String(data: data, encoding: .utf8) else { return false }
        return save(key: key, string: string)
    }

    @discardableResult
    static func save(key: String, string: String) -> Bool {
        var vault = loadVault()
        vault[key] = string
        saveVault(vault)
        return true
    }

    static func load(key: String) -> Data? {
        guard let string = loadString(key: key) else { return nil }
        return string.data(using: .utf8)
    }

    static func loadString(key: String) -> String? {
        let vault = loadVault()
        return vault[key]
    }

    @discardableResult
    static func delete(key: String) -> Bool {
        var vault = loadVault()
        vault.removeValue(forKey: key)
        saveVault(vault)
        return true
    }

    // MARK: - Convenience for OAuth tokens

    static func saveTokens(accountId: String, accessToken: String, refreshToken: String?) {
        var vault = loadVault()
        vault["\(accountId).accessToken"] = accessToken
        if let refreshToken = refreshToken {
            vault["\(accountId).refreshToken"] = refreshToken
        }
        saveVault(vault)
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
        var vault = loadVault()
        vault.removeValue(forKey: "\(accountId).accessToken")
        vault.removeValue(forKey: "\(accountId).refreshToken")
        vault.removeValue(forKey: "\(accountId).password")
        saveVault(vault)
    }
}
