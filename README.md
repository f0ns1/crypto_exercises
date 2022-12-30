# Cryptographic python repo

# Symmetric encription algorithm
## AES encryption

### CBC mode example :
source code: 

```
from Crypto.Cipher import AES

print("AES CBC Python encryption")

iv = b'aaaaaaaaaaaaaaaa'
key = b'bbbbbbbbbbbbbbbbbbbbbbbb'
text = b'Data to encrypt!'
print("Initialization vector : ", iv)
print("Symetric key: ", key)
print("Text to encrypt: ", text)

#Encrypt text
cipher = AES.new(key,AES.MODE_CBC,iv)
encrypted = cipher.encrypt(text)

print("Encrypted data ", encrypted)
print("Excrypted hexadecimal: ", encrypted.hex())

#Decryot text
cipher = AES.new(key, AES.MODE_CBC,iv)
plaintext = cipher.decrypt(encrypted)
print("Decrypted data : ", plaintext)

```
ouput:

```
>>> (executing file "AES_CBC.py")
AES CBC Python encryption
Initialization vector :  b'aaaaaaaaaaaaaaaa'
Symetric key:  b'bbbbbbbbbbbbbbbbbbbbbbbb'
Text to encrypt:  b'Data to encrypt!'
Encrypted data  b'M\xf32\xfc\x99\x04.\x81n\xcc\x0c\xad\\\xc1P\x1b'
Excrypted hexadecimal:  4df332fc99042e816ecc0cad5cc1501b
Decrypted data :  b'Data to encrypt!'
```
### AES CTR example:

source code:

```
import pyaes, binascii, secrets

print("AES CTR Python encryption")

iv = secrets.randbits(256)
key = b'bbbbbbbbbbbbbbbbbbbbbbbb'
text = b'Data to encrypt!'
print("Initialization vector : ", iv)
print("Symetric key: ", key)
print("Text to encrypt: ", text)

#Encrypt text
aes = pyaes.AESModeOfOperationCTR(key,pyaes.Counter(iv))
ciphertext = aes.encrypt(text)
print("Data encrypted ",ciphertext)
print("Data encrypted hexadecimal: ", ciphertext.hex())

#decrypt text
aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
plaintext = aes.decrypt(ciphertext)
print("Decrypted data : ", plaintext)
```

output:

```
>>> (executing file "AES_CTR.py")
AES CTR Python encryption
Initialization vector :  62423621268066450255339898732944785462161281974213394995151553010767326783193
Symetric key:  b'bbbbbbbbbbbbbbbbbbbbbbbb'
Text to encrypt:  b'Data to encrypt!'
Data encrypted  b'\x98\xbc\xecoJ\x85\xd8\xa7\xd1\xd6s\xfe\xea\xc4\xe1%'
Data encrypted hexadecimal:  98bcec6f4a85d8a7d1d673feeac4e125
Decrypted data :  b'Data to encrypt!'
```

### AES GCM example:

source code:

```
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

```

oputput:

```
>>> (executing file "AES_236_GCM.py")
Init AES 256 GCM encryption
Encription key  b'16a7c6c88b2a8bec6598e9612e2b90ae0b6b7ddffc85de7718395a29163595a7' 


 encrypted message  {'ciphertext': b'baa2b69f625b6358bfc2026888d9d991d4843d282fb3b0eb7c10bb25cac91401e5e958b5cca77c0508e2b86688cb003b573dfefc4ca7', 'aesIV': b'420587c7fdd3e2212ec5f0ad89096d8d', 'authTag': b'8c59ee722a3e1f5c901f338ebc07f2e9'} 


Original data decrypted:  b'message to encrypt with AES_256_GCM symetric algorithm'
```

# Hasing examples:

Source code:
```
import binascii,hashlib

print("Init Hashing functions")

text = 'Offensive Cryptographic'
data = text.encode("UTF-8")
print("Data : ", data)

sha256 = hashlib.sha256(data).digest()
print("sha256 ", binascii.hexlify(sha256))

sha3_256 = hashlib.sha3_256(data).digest()
print("sha3_256", binascii.hexlify(sha3_256))

blake2s = hashlib.new('blake2s', data).digest()
print("blake2s: ", binascii.hexlify(blake2s))

ripemd160 = hashlib.new('ripemd160', data).digest()
print("ripemd160: ", binascii.hexlify(ripemd160))
```
Output:
```
>>> (executing file "hashing.py")
Init Hashing functions
Data :  b'Offensive Cryptographic'
sha256  b'4fb93bc3562947f694d6dffa525f8ac66a6a7c1b8b0f6e3603ff8220912bacb6'
sha3_256 b'a2db3fd0f1e31f887e0f2c2dcb07009765d5a00692dbd891c4fd5d00ffd83e84'
blake2s:  b'317f16725dcf180051229fb4eb78d8573d8eb123eded2881ae504057ddf50226'
ripemd160:  b'd80ec4aae439459ed484dca817e6cacd9fdd63be'
```
#Derivated functions for passwords
##hmac 

### hmac_sha256

source code:
```
import hashlib, hmac, binascii

def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

key = b'Derivation password with Hmac'
msg = b'Secret message to protect with derivation password'

hmac_hashed = hmac_sha256(key, msg)
print("hmac example: ", binascii.hexlify(hmac_hashed))
```
Output
```
>>> (executing file "hmac_sha256.py")
hmac example:  b'8fd3a363da9ecdafc03e769365f3a5ac2d00010e9c43ea0c51ed21bdc5fffebb'
```

### pbkdf2
source code:
```
import os, binascii
from backports.pbkdf2 import pbkdf2_hmac

salt = os.urandom(64)
passwd= b'My password to derivate and protect'
key = pbkdf2_hmac("sha256", passwd, salt, 1000, 32)
print("pbkdf derivated keys : ", binascii.hexlify(key))
```
Output:
```
>>> (executing file "pbkdf2_hmac.py")
pbkdf derivated keys :  b'd3259f983131b146cf3bd764908dee0c01d55912c49620b8e3fda03061a09653'
```
