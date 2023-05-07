from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto import Random
from Crypto.Util.Padding import pad
from base64 import b64encode
import secrets

ra = Random.new()

def oracle(key, plaintext):
    cipher = AES.new(key, mode = AES.MODE_CBC) # IV will be random
    return (cipher.iv, cipher.encrypt(pad(plaintext, AES.block_size)))
    
if __name__ == "__main__":
    key  = ra.read(32)
    salaire = secrets.randbelow(3000)
    m = b"Le salaire journalier du dirigeant USB est de " + str(salaire).encode() + b" CHF"
    (IV, ct) = oracle(key, m)
    print("IV = %s" % b64encode(IV))
    print("ct = %s" % b64encode(ct))
