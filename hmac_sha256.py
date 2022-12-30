import hashlib, hmac, binascii

def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

key = b'Derivation password with Hmac'
msg = b'Secret message to protect with derivation password'

hmac_hashed = hmac_sha256(key, msg)
print("hmac example: ", binascii.hexlify(hmac_hashed))
