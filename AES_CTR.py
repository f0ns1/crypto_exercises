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
