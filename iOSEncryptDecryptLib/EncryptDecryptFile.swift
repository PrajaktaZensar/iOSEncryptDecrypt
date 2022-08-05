//
//  EncryptDecryptFile.swift
//  iOSEncryptDecryptLib
//
//  Created by Prajakta Kiran Patil on 16/07/22.
//

import Foundation
import CommonCrypto
import CryptoKit


//-------- For Cryptokit-----------
@available(iOS 13.0, *)
public class CryptoKitClass {

    var passowrdString: String!
    let randomKey = SymmetricKey(size: .bits256)
    var encryptedData: String!
    public typealias KeyPair = (publicKey: SecKey, privateKey: SecKey)
    
    public init(passowrdString: String) {
            self.passowrdString = passowrdString
    }
    
/*------------------ENCRYPTING/DECRYPTING DATA---------------------------

--------------- You can encrypt the contents of super secret msg--------
--------------- AES with Galois/Counter Mode (AES-GCM) provides both authenticated encryption (confidentiality and authentication) and the ability to check the integrity and authentication of additional authenticated data (AAD) that is sent in the clear.

------------------ENCRYPTING/DECRYPTING DATA---------------------------*/
    
    
    public func AESencryptFunc(passowrdString: String) throws -> String {
        let textData = passowrdString.data(using: .utf8)!
        let encrypted = try AES.GCM.seal(textData, using: randomKey)
        encryptedData = encrypted.combined!.base64EncodedString()
        return encryptedData
    }
    
    

    public func AESdecryptFunc() -> String {
        do {
            guard let data = Data(base64Encoded: try encryptedData) else {
                return "Could not decode text: \(passowrdString ?? "")"
            }

            let sealedBox = try AES.GCM.SealedBox(combined: data)
            let decryptedData = try AES.GCM.open(sealedBox, using: randomKey)

            guard let text = String(data: decryptedData, encoding: .utf8) else {
                return "Could not decode data: \(decryptedData)"
            }

            return text
        } catch let error {
            return "Error decrypting message: \(error.localizedDescription)"
        }
    }
    
//------------------------------------------------------------------------------
/*----------------------------AUTHENTICATE--------------------------------------

--------------- Hash-based Message Authentication Code
--------------- The HMAC process mixes a secret key with the message data and hashes the result. The hash value is mixed with the secret key again, and then hashed a second time.

----------------------------AUTHENTICATE--------------------------------------*/

        // CrytoKit
        public func authenticateHmacSHA512CryptoKit() -> String? {
            // Create the hash
            let passwordData = passowrdString.data(using: .utf8)!
            let symmetricKey = SymmetricKey(data: passwordData)
            let passwordHashDigest = HMAC<SHA512>.authenticationCode(for: passwordData, using: symmetricKey)
            return formatPassword(Data(passwordHashDigest))
        }
    
    
    
    
//------------------------------------------------------------------------------
/*----------------------------HASHING--------------------------------------
 
--------------- Hashing algorithm used to convert text of any length into a fixed-size string.
--------------- Each output produces a SHA-512 length of 512 bits (64 bytes). This algorithm is commonly used for email addresses hashing, password hashing, and digital record verification.
 
----------------------------HASHING----------------------------------------*/


        // CrytoKit
        public func hashSha512CryptoKit() -> String? {
            // Create the hash
            let passwordData = passowrdString.data(using: .utf8)!
            let passwordHashDigest = SHA512.hash(data: passwordData)
            return formatPassword(Data(passwordHashDigest))
        }
    
    
    
    
    
//------------------------------------------------------------------------------
/*----------------------CREATING AND VERIFYING SIGNATURES-----------------------------
     
--------------- A signature that has been confirmed to be valid by a recipient, gives them a strong indication that the information was indeed created by the person claiming to have created it and hasn’t been tampered with
--------------- Common public-key cryptography use cases are encryption and digital signatures.
--------------- CryptoKit uses ECC algorithms exclusively. We can choose between the P256/P384/P521 ECC algorithm and the Curve25519 ECC algorithm. They both have approximately the same security level and small key sizes.
 
     
----------------------CREATING AND VERIFYING SIGNATURES-----------------------------*/
    
    
    public func senderSignatureCurve25519() -> (Data, Data, SHA512Digest) {
        let senderSigningPrivateKey = Curve25519.Signing.PrivateKey()
       
        let senderSigningPublicKeyData =
        senderSigningPrivateKey.publicKey.rawRepresentation
        //The rawRepresentation of the public key is of type Data, so you can send it over the network.

        let data = passowrdString.data(using: .utf8)!
        let digest512 = SHA512.hash(data: data)
        let signatureForDigest = try! senderSigningPrivateKey.signature(
          for: Data(digest512))
        
        
        return (senderSigningPublicKeyData, signatureForDigest, digest512)

    }
    
    
    public func receiverVerifySignatureCurve25519(publicKey : Data, signature: Data, SHA512Digest: SHA512Digest) -> Bool {
        
        let publicKeyVal = try! Curve25519.Signing.PublicKey(
          rawRepresentation: publicKey)
     
        if publicKeyVal.isValidSignature(signature,
          for: Data(SHA512Digest)) {
            return true
        } else {
            return false
        }
    }
    
//------------------------------------------------------------------------------
/*------------------------------RSA ALGO-----------------------------
--------------------------------RSA ALGO---------------------------------------*/
    
    
    
    public func generateKeyPair(publicKeyTag: String, privateKeyTag:String, keySize: Int) -> KeyPair?  {

       // A key whose value indicates the item's private tag.
        let privateAttributes = [String(kSecAttrIsPermanent): true,
                                 String(kSecAttrApplicationTag): privateKeyTag] as [String : Any]
        let publicAttributes = [String(kSecAttrIsPermanent): true,
                                String(kSecAttrApplicationTag): publicKeyTag] as [String : Any]

        let pairAttributes = [String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
                              String(kSecAttrKeySizeInBits): keySize,
                              String(kSecPublicKeyAttrs): publicAttributes,
                              String(kSecPrivateKeyAttrs): privateAttributes] as [String : Any]
        var publicKey: SecKey?
        var privateKey: SecKey?
        let result = SecKeyGeneratePair(pairAttributes as CFDictionary, &publicKey, &privateKey)

        if result != errSecSuccess {
            return nil
        }
        return KeyPair(publicKey: publicKey!, privateKey: privateKey!)
    }
    
    
   public func callEncryptionUsingRSA(publicKey : SecKey, encryptData : String) -> Data {
        
        
        var error: Unmanaged<CFError>?
        let message = Data(encryptData.utf8)
        let ciphertext = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, message as CFData, &error)! as Data
        
        return ciphertext
    }
  
  
    
   public func callDecryptionUsingRSA(encyrptedData: Data, privateKey: SecKey) -> String {
        
        var error: Unmanaged<CFError>?
        let plaintext = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, encyrptedData as CFData, &error)! as Data
        let decryptedText = String(data: plaintext, encoding: .utf8) ?? "Non UTF8"
        return decryptedText
    }

        // Common Password Format
    func formatPassword(_ password: Data) -> String {
        var passwordString : String = password.map { String(format: "%02x", $0) }.joined()
            // Add a dash after every 8 characters
        var index = passwordString.index(passwordString.startIndex, offsetBy: 8)
        repeat {
            passwordString.insert("-", at: index)
            passwordString.formIndex(&index, offsetBy: 9)
        } while index < passwordString.endIndex
        return passwordString
    }
    
    
}


public class PinningManager: NSObject {
    
    var publicKeyHash = ""
    var certificateName = ""
    
    public init(publicKeyHash : String, certificateName: String) {
        self.publicKeyHash = publicKeyHash
        self.certificateName = certificateName
    }
    
    let rsa2048Asn1Header:[UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]
    
    private var isCertificatePinning: Bool = false
    
    private func sha256(data : Data) -> String {
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        
        keyWithHeader.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(keyWithHeader.count), &hash)
        }
        
        
        return Data(hash).base64EncodedString()
    }
    
   public func callAPI(withURL url: URL, isCertificatePinning: Bool, completion: @escaping (String) -> Void) {
        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        self.isCertificatePinning = isCertificatePinning
        var responseMessage = ""
        let task = session.dataTask(with: url) { (data, response, error) in
            if error != nil {
                print("error: \(error!.localizedDescription): \(error!)")
                responseMessage = "Pinning failed"
            } else if data != nil {
                let str = String(decoding: data!, as: UTF8.self)
                print("Received data:\n\(str)")
                if isCertificatePinning {
                    responseMessage = "Certificate pinning is successfully completed"
                }else {
                    responseMessage = "Public key pinning is successfully completed"
                }
            }
            
            DispatchQueue.main.async {
                completion(responseMessage)
            }
            
        }
        task.resume()
        
    }
    
}

@available(iOS 12.0, *)
extension PinningManager: URLSessionDelegate {
    
    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil);
            return
        }
        
        if self.isCertificatePinning {
            
            
            let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0)
            // SSL Policies for domain name check
            let policy = NSMutableArray()
            policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
            
            //evaluate server certifiacte
            let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)
            
            //Local and Remote certificate Data
            let remoteCertificateData:NSData =  SecCertificateCopyData(certificate!)
            //let LocalCertificate = Bundle.main.path(forResource: "github.com", ofType: "cer")
            let pathToCertificate = Bundle.main.path(forResource: certificateName, ofType: "cer")
            let localCertificateData:NSData = NSData(contentsOfFile: pathToCertificate!)!
            
            //Compare certificates
            if(isServerTrusted && remoteCertificateData.isEqual(to: localCertificateData as Data)){
                let credential:URLCredential =  URLCredential(trust:serverTrust)
                print("Certificate pinning is successfully completed")
                completionHandler(.useCredential,credential)
            }
            else{
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        } else {
            if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                // Server public key
                let serverPublicKey = SecCertificateCopyKey(serverCertificate)
                let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil )!
                let data:Data = serverPublicKeyData as Data
                // Server Hash key
                let serverHashKey = sha256(data: data)
                // Local Hash Key
                let publickKeyLocal = self.publicKeyHash
                if (serverHashKey == publickKeyLocal) {
                    // Success! This is our server
                    print("Public key pinning is successfully completed")
                    completionHandler(.useCredential, URLCredential(trust:serverTrust))
                    return
                }
            }
        }
    }
}








