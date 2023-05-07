from Crypto.Cipher import AES
from Crypto.Util import Counter, strxor
from Crypto import Random
from base64 import b64encode, b64decode


def cbcmac(message: bytes, key: bytes) -> bytes: 
    if len(key) !=  16:
        raise Exception("Error. Need key of 128 bits")
    if len(message) % 16 != 0:
        raise Exception("Error. Message needs to be a multiple of 128 bits")
    cipher = AES.new(key,AES.MODE_ECB)
    temp = b"\x00"*16
    blocks = [message[i:i+16] for i in range(0,len(message),16)]
    for b in blocks:
        temp = strxor.strxor(temp,b)
        temp = cipher.encrypt(temp)
    return temp

def ccm(message: bytes, key: bytes) -> tuple:
    """Encrypts with AES128-CCM without authenticated data. """

    if len(key) != 16:
        raise Exception("Only AES-128 is supported")

    cipher = AES.new(key, mode = AES.MODE_CTR)
    tag = cbcmac(message, key)
    ciphertext = cipher.encrypt(message)
    #Encrypt tag for security
    cipher = AES.new(key, mode = AES.MODE_CTR, nonce = cipher.nonce) # Reinitialize counter
    tag = cipher.encrypt(tag)
    return (cipher.nonce, ciphertext, tag)

def ccm_dec(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypts with AES128-CCM without authenticated data."""
    if len(key) != 16:
        raise Exception("Only AES-128 is supported")
    
    cipher = AES.new(key, mode = AES.MODE_CTR, nonce = nonce)
    plaintext = cipher.decrypt(ciphertext)
    
    cipher = AES.new(key, mode = AES.MODE_CTR, nonce = nonce)       # Reinitialize counter
    computed_tag = cipher.encrypt(cbcmac(plaintext, key))

    if computed_tag != tag:
        raise Exception("Tampering detected, found: %s, expected: %s" % (b64encode(computed_tag), b64encode(tag)))
    return plaintext


def forge(m1, m2, c1, c2, tag1):
    ks_1 = strxor.strxor(m1, c1)
    mac = strxor.strxor(tag1, ks_1)

    ks2_0 = strxor.strxor(m2[:16], c2[:16]) 
    ks2_1 = strxor.strxor(m2[16:], c2[16:]) 

    m3 = m1 + strxor.strxor(mac, m1)
    m3_xored1 = strxor.strxor(m3[:16], ks2_0)
    m3_xored2 = strxor.strxor(m3[16:], ks2_1)
    c3 = m3_xored1 + m3_xored2
    tag3 = strxor.strxor(mac, ks2_0)

    return c3, tag3



if __name__ == "__main__":

    ra = Random.new()
    key  = ra.read(16)

    m1 = b"Ceci est un test"
    m2 = b"Ceci est un autre test plus long"

    # Modified CCM decryption
    (IV1, c1, tag1) = ccm(m1, key)
    print("[*] Original message:", m1, "message after decryption:", ccm_dec(c1, tag1, key, IV1))

    # Forge and test the message with a random key

    (IV1, c1, tag1) = ccm(m1, key)
    (IV2, c2, tag2) = ccm(m2, key)
    (c3, tag3) = forge(m1, m2, c1, c2, tag1)

    ccm_dec(c3, tag3, key, IV2)

    # Forge a message with given parameters 

    c1 = b'EHubBeTiWNyzbrY4Da2/Wg=='
    IV1 = b'bj/hI9gXTXo='
    tag1 = b'qrhGt/5P1KAhQXVGEC3f6w=='
    c2 = b'AOv2ASSoxGCp4D2q79kexu5MvQfYdneQR7BZ2Ar46Lk='
    IV2 = b'7j4I2dF47fg='
    tag2 = b'XK2bmxQjYPsMJRJX7Y2DsQ=='

    (c3, tag3) = forge(m1, m2, b64decode(c1), b64decode(c2), b64decode(tag1))

    print("[+] Forged ciphertext:", b64encode(c3))
    print("[+] Forged tag:", b64encode(tag3))
    print("[+] IV to be used:", IV2)



