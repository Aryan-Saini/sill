import Foundation
import Security
import StreamProtocol

/// This device's remote identity (docs/remote-access-plan.md §7.2): a P-256 key in the Keychain,
/// tag `me.saffer.sill.device-key`, readable only while the device is unlocked, never synced and
/// never in a backup (`WhenUnlockedThisDeviceOnly`), so a lost or restored device cannot use it.
/// Made at the first pairing; its certificate is rebuilt at each launch (the pin is the key).
///
/// A software key: whether Network.framework can sign the TLS handshake with a Secure Enclave key
/// is R0-a, on a real device (open question 12). DEBUG `-SillDeviceKeySE 1` makes and uses a
/// Secure Enclave key under its own tag for that check; the simulator has no Secure Enclave.
///
/// Main thread, or the network queue once made: the identity is immutable and cached.
enum DeviceIdentity {
    static let tag = Data("me.saffer.sill.device-key".utf8)
    #if DEBUG
    static let secureEnclaveTag = Data("me.saffer.sill.device-key.se".utf8)
    static var usesSecureEnclave: Bool { UserDefaults.standard.bool(forKey: "SillDeviceKeySE") }
    #endif

    private static let lock = NSLock()
    private static var cached: RemoteIdentity?

    private static var currentTag: Data {
        #if DEBUG
        if usesSecureEnclave { return secureEnclaveTag }
        #endif
        return tag
    }

    /// The identity when this device has a key; nil before the first pairing, and after a restore
    /// from a backup (the key does not travel).
    static func existing() -> RemoteIdentity? {
        lock.lock(); defer { lock.unlock() }
        if let cached { return cached }
        guard let key = readKey() else { return nil }
        cached = RemoteIdentity(privateKey: key)
        return cached
    }

    /// The identity, made now if this device has none yet (the first pairing).
    static func loadOrCreate() throws -> RemoteIdentity {
        if let id = existing() { return id }
        lock.lock(); defer { lock.unlock() }
        let key = try makeKey()
        guard let id = RemoteIdentity(privateKey: key) else { throw IdentityError("the new key couldn’t make a certificate") }
        cached = id
        return id
    }

    /// True only when the Keychain says, for every tag this build uses, that there is no key
    /// (errSecItemNotFound): a restore from a backup, where the key did not travel. Any other
    /// answer (the Keychain not readable yet, a DEBUG run with the Secure Enclave key under its
    /// own tag, which found none and made the real pairings look keyless) is not proof, and
    /// clearing the saved Macs on it would lose pairings the key still serves.
    static func knownMissing() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if cached != nil || readKey() != nil { return false }
        var tags = [tag]
        #if DEBUG
        tags.append(secureEnclaveTag)
        #endif
        return tags.allSatisfy { status(of: $0) == errSecItemNotFound }
    }

    /// Forgets the key (`-SillForgetMacs 1`).
    static func forget() {
        lock.lock(); defer { lock.unlock() }
        cached = nil
        let query: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: currentTag]
        SecItemDelete(query as CFDictionary)
        SecItemDelete(savedMacsQuery as CFDictionary)
    }

    private static let savedMacsService = "me.saffer.sill.saved-macs"

    private static var savedMacsQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: savedMacsService,
            kSecAttrAccount as String: savedMacsService,
        ]
    }

    /// Reads the `ThisDeviceOnly` Keychain mirror of `SavedMacs` (issue #140).
    static func readSavedMacs() -> String? {
        var query = savedMacsQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Writes `SavedMacs` JSON to the `ThisDeviceOnly` Keychain mirror so a force-quit (`SIGKILL`)
    /// before `cfprefsd` flushes `UserDefaults` never loses a pairing (issue #140).
    static func writeSavedMacs(_ text: String) {
        let data = Data(text.utf8)
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        if SecItemUpdate(savedMacsQuery as CFDictionary, update as CFDictionary) == errSecItemNotFound {
            var add = savedMacsQuery
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(add as CFDictionary, nil)
        }
    }

    struct IdentityError: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    private static func keyQuery(_ tag: Data) -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
    }

    private static func readKey() -> SecKey? {
        var query = keyQuery(currentTag)
        query[kSecReturnRef as String] = true
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item,
              CFGetTypeID(item) == SecKeyGetTypeID() else { return nil }
        return (item as! SecKey)      // the type was just checked
    }

    /// The Keychain's answer for a key under `tag`, without reading it.
    private static func status(of tag: Data) -> OSStatus {
        SecItemCopyMatching(keyQuery(tag) as CFDictionary, nil)
    }

    private static func makeKey() throws -> SecKey {
        var privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: currentTag,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        #if DEBUG
        if usesSecureEnclave {
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil) else {
                throw IdentityError("no Secure Enclave access control")
            }
            privateAttributes.removeValue(forKey: kSecAttrAccessible as String)
            privateAttributes[kSecAttrAccessControl as String] = access
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        #endif
        attributes[kSecPrivateKeyAttrs as String] = privateAttributes
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw IdentityError("no key could be made (\(error.map { "\($0.takeRetainedValue())" } ?? "no reason given"))")
        }
        if readKey() == nil {
            let add: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: currentTag,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                kSecValueRef as String: key,
            ]
            SecItemAdd(add as CFDictionary, nil)
        }
        return key
    }
}
