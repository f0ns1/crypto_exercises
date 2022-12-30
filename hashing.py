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
