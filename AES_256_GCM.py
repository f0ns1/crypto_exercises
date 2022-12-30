from Crypto.Cipher import AES
import binascii, os

print("Init AES 256 GCM encryption")

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag= aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag
    )


def decrypt_AES_GCM(encryptedMessage, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, encryptedMessage[1])
    plaintext = aesCipher.decrypt_and_verify(encryptedMessage[0], encryptedMessage[2])
    return plaintext



#Main
secretKey = os.urandom(32)
print("Encription key ", binascii.hexlify(secretKey), "\n")
msg = "message to encrypt with AES_256_GCM symetric algorithm"

#Encrypt data
encryptedMessage = encrypt_AES_GCM(msg.encode('utf-8'), secretKey)
print("\n encrypted message ", {
'ciphertext': binascii.hexlify(encryptedMessage[0]),
'aesIV': binascii.hexlify(encryptedMessage[1]),
'authTag': binascii.hexlify(encryptedMessage[2])
},"\n")

#Decrypt data
decrypted = decrypt_AES_GCM(encryptedMessage, secretKey)
print("\nOriginal data decrypted: ", decrypted)
