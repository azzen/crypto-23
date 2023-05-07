from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto import Random
from Crypto.Util.Padding import pad
from base64 import b64encode
import secrets

ra = Random.new()
counter = ra.read(AES.block_size)

def increaseIV(ctr):
    ctr_int = int.from_bytes(ctr, "big")
    ctr_int += 1
    return int(ctr_int).to_bytes(AES.block_size, byteorder="big")
    
def oracle(key, plaintext):
    global counter
    counter = increaseIV(counter)
    cipher = AES.new(key, mode = AES.MODE_CBC, iv = counter)
    return (counter, cipher.encrypt(pad(plaintext, AES.block_size)))

    
if __name__ == "__main__":
    key  = ra.read(32)
    salaire = secrets.randbelow(3000)
    m = b"Le salaire journalier du dirigeant USB est de " + str(salaire).encode() + b" CHF"
    (IV, ct) = oracle(key, m)
    print("IV = %s" % b64encode(IV))
    print("ct = %s" % b64encode(ct))
