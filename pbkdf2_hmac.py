import os, binascii
from backports.pbkdf2 import pbkdf2_hmac

salt = os.urandom(64)
passwd= b'My password to derivate and protect'
key = pbkdf2_hmac("sha256", passwd, salt, 1000, 32)
print("pbkdf derivated keys : ", binascii.hexlify(key))
