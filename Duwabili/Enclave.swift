/*
Derived from trailofbits/SecureEnclaveCrypto
Copyright (c) 2016 Håvard Fossli
Copyright (c) 2016 Trail of Bits, Inc.
*/

import Security
import LocalAuthentication

public class Enclave {
	public init(_ tag: String, _ identifier: String, _ group: String, _ prompt: String) {
		self.tag = tag
		self.identifier = identifier
		self.group = group
		self.prompt = prompt
	}
	
	public func touch() { _ = privateKey }
	
	public func encrypt(_ plainText: Data) -> Data? {
		var e: Unmanaged<CFError>?
		if let k = publicKey {
			let r = SecKeyCreateEncryptedData(k, algorithm, plainText as CFData, &e)
			return r! as Data
		} else {
			print(e.debugDescription)
			return nil
		}
	}
	
	public func decrypt(_ digest: Data) -> Data? {
		var e: Unmanaged<CFError>?
		if let k = privateKey {
			if let r = SecKeyCreateDecryptedData(k, algorithm, digest as CFData, &e) { return r as Data }
			else { return Data()}
		} else {
			print(e.debugDescription)
			return nil
		}
	}
	
	public func verify(signature: Data, plainText: Data) throws -> Bool {
		var ptc = [UInt8](repeating: 0, count: plainText.count)
		plainText.copyBytes(to: &ptc, count: plainText.count)
		var sb = [UInt8](repeating: 0, count: signature.count)
		signature.copyBytes(to: &sb, count: signature.count)
		
		if let k = publicKey {
			let s = SecKeyRawVerify(k, .PKCS1, ptc, ptc.count, sb, sb.count)
			guard s == errSecSuccess else { throw NyEnclaveError(message: "Could not create signature", osStatus: s) }
			return true
		}
		return false
	}

	public func sign(_ plainText: Data) throws -> Data {
		let blockSize = 256
		let maxChunkSize = blockSize - 11
		guard plainText.count / MemoryLayout<UInt8>.size <= maxChunkSize else { throw NyEnclaveError(message: "data length exceeds \(maxChunkSize)", osStatus: nil) }
		var ptc = [UInt8](repeating: 0, count: plainText.count / MemoryLayout<UInt8>.size)
		plainText.copyBytes(to: &ptc, count: plainText.count)
		var sb = [UInt8](repeating: 0, count: blockSize)
		var bs = blockSize
		if let k = privateKey {
			let s = SecKeyRawSign(k, .PKCS1, ptc, ptc.count, &sb, &bs)
			guard s == errSecSuccess else {
				if s == errSecParam { throw NyEnclaveError(message: "Could not create signature due to bad parameters", osStatus: s) }
				else { throw NyEnclaveError(message: "Could not create signature", osStatus: s) }
			}
		}
		return Data(bytes: UnsafePointer<UInt8>(sb), count: bs)
	}
	
	private lazy var publicKey: SecKey? = {
		if let k = privateKey { return SecKeyCopyPublicKey(k) }
		else { return nil }
	}()
	
	private lazy var privateKey: SecKey? = {
		do {
			if let k = try? existingPrivateKey() { return k }
			else { return try newPrivateKey() }
		} catch { return nil }
	}()

	private func existingPrivateKey() throws -> SecKey {
		let query: [String: Any] = [
			kSecClass as String: kSecClassKey,
			kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
			kSecAttrAccessGroup as String: qualifiedGroup as AnyObject,
			kSecAttrApplicationTag as String: tag,
			kSecReturnRef as String: true,
			kSecUseAuthenticationContext as String: context,
			kSecUseOperationPrompt as String: prompt
		]
		var result: CFTypeRef?
		let s = SecItemCopyMatching(query as CFDictionary, &result)
		guard s == errSecSuccess else { throw NyEnclaveError(message: "Could not get key for query: \(query)", osStatus: s) }
		return result as! SecKey
	}

	private func newPrivateKey() throws -> SecKey {
		var attributes: [String: Any] = [
			kSecAttrKeyType as String: attrKeyTypeEllipticCurve,
			kSecAttrKeySizeInBits as String: 256,
			kSecPrivateKeyAttrs as String: [
				kSecAttrAccessGroup as String: qualifiedGroup as AnyObject,
				kSecAttrApplicationTag as String: tag,
				kSecAttrIsPermanent as String: true,
				kSecAttrAccessControl as String: try access(with: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
			]
		]
		
		#if targetEnvironment(simulator)
			print("NOT USING SECURE ENCLAVE!")
		#else
			attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
		#endif

		var error: Unmanaged<CFError>?
		guard let pk = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else { throw error!.takeRetainedValue() as Error }
		return pk
	}
	
	private func deletePublicKey() throws {
		let query: [String: Any] = [
			kSecClass as String: kSecClassKey,
			kSecAttrKeyType as String: attrKeyTypeEllipticCurve,
			kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
			kSecAttrAccessGroup as String: qualifiedGroup as AnyObject,
			kSecAttrApplicationTag as String: tag
		]
		let s = SecItemDelete(query as CFDictionary)
		guard s == errSecSuccess else { throw NyEnclaveError(message: "Could not delete private key", osStatus: s) }
	}
	
	private func deletePrivateKey() throws {
		let query: [String: Any] = [
			kSecClass as String: kSecClassKey,
			kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
			kSecAttrAccessGroup as String: qualifiedGroup as AnyObject,
			kSecAttrApplicationTag as String: tag,
			kSecReturnRef as String: true
		]
		let s = SecItemDelete(query as CFDictionary)
		guard s == errSecSuccess else {
			throw NyEnclaveError(message: "Could not delete private key", osStatus: s)
		}
	}

	private func access(with protection: CFString = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags: SecAccessControlCreateFlags = [.userPresence, .privateKeyUsage]) throws -> SecAccessControl {
		var e: Unmanaged<CFError>?
		let a = SecAccessControlCreateWithFlags(kCFAllocatorDefault, protection, flags, &e)
		guard a != nil else { throw NyEnclaveError(message: "Could not generate access control. Error \(e!.takeRetainedValue())", osStatus: nil) }
		return a!
	}
	
	private lazy var context: LAContext = {
		let c = LAContext()
		c.touchIDAuthenticationAllowableReuseDuration = 15
		return c
	}()
	
	private let tag: String
	private let identifier: String
	private let group: String
	private let prompt: String
	private lazy var qualifiedGroup = "\(identifier).\(group)"
	private lazy var algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
	private lazy var attrKeyTypeEllipticCurve = kSecAttrKeyTypeECSECPrimeRandom as String
}


struct NyEnclaveError: Error {
	let message: String
	let osStatus: OSStatus?
	
	init(message: String, osStatus: OSStatus?) {
		self.message = message
		self.osStatus = osStatus
	}
}
