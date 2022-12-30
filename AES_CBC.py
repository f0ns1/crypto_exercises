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
