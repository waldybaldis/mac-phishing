import Foundation
import CryptoKit
import Security
#if canImport(IOKit)
import IOKit
#endif
#if canImport(UIKit)
import UIKit
#endif

/// Stores credentials in an encrypted file in Application Support.
/// This avoids macOS Keychain password prompts that occur with ad-hoc signed apps
/// (each rebuild changes the signing identity, causing Keychain to re-prompt).
/// The vault file is readable only by the current user (POSIX 0600).
enum KeychainHelper {

    private static let vaultFileName = "credentials.vault"

    /// Encryption key derived from a stable machine-specific identifier.
    /// Uses the hardware UUID so the vault is tied to this Mac.
    private static var encryptionKey: SymmetricKey {
        let seed: String
        if let uuid = getMachineUUID() {
            seed = "com.phishguard.vault.\(uuid)"
        } else {
            seed = "com.phishguard.vault.fallback"
        }
        let hash = SHA256.hash(data: Data(seed.utf8))
        return SymmetricKey(data: hash)
    }

    private static func getMachineUUID() -> String? {
        #if canImport(IOKit)
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        defer { IOObjectRelease(service) }
        guard service != 0,
              let uuidRef = IORegistryEntryCreateCFProperty(service, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0) else {
            return nil
        }
        return uuidRef.takeRetainedValue() as? String
        #elseif canImport(UIKit)
        return UIDevice.current.identifierForVendor?.uuidString
        #else
        return nil
        #endif
    }

    private static var vaultURL: URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let dir = appSupport.appendingPathComponent("PhishGuard")
        if !FileManager.default.fileExists(atPath: dir.path) {
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        return dir.appendingPathComponent(vaultFileName)
    }

    // MARK: - Vault (encrypted file holding all credentials)

    private static func loadVault() -> [String: String] {
        guard let encryptedData = try? Data(contentsOf: vaultURL),
              encryptedData.count > 0 else {
            return [:]
        }

        do {
            let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
            let decryptedData = try AES.GCM.open(sealedBox, using: encryptionKey)
            return (try? JSONDecoder().decode([String: String].self, from: decryptedData)) ?? [:]
        } catch {
            return [:]
        }
    }

    private static func saveVault(_ vault: [String: String]) {
        guard let jsonData = try? JSONEncoder().encode(vault) else { return }

        do {
            let sealedBox = try AES.GCM.seal(jsonData, using: encryptionKey)
            guard let combined = sealedBox.combined else { return }
            try combined.write(to: vaultURL, options: .atomic)
            // Set file permissions to owner-only (0600)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: vaultURL.path)
        } catch {
            // Vault save failed — credentials will be lost on next read
        }
    }

    // MARK: - Migration from Keychain (macOS only)

    /// One-time migration: reads any existing Keychain vault and moves it to the file-based vault.
    static func migrateFromKeychainIfNeeded() {
        #if os(macOS)
        // Skip if file vault already exists
        if FileManager.default.fileExists(atPath: vaultURL.path) { return }

        // Try to read from old Keychain location
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.phishguard.app",
            kSecAttrAccount as String: "credentials",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let dict = try? JSONDecoder().decode([String: String].self, from: data) else {
            return
        }

        // Save to file vault
        saveVault(dict)

        // Delete old Keychain item
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.phishguard.app",
            kSecAttrAccount as String: "credentials",
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        #endif
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
