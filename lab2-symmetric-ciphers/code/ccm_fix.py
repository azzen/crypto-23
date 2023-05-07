from Crypto.Cipher import AES
from Crypto.Util import strxor
from Crypto import Random

def ccm(message: bytes, key: bytes) -> tuple:
    """Encrypts with AES128-CCM without authenticated data. """
    cipher = AES.new(key, mode = AES.MODE_CCM, assoc_len=0)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return (cipher.nonce, ciphertext, tag)

def ccm_dec(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypts with AES128-CCM without authenticated data."""
    cipher = AES.new(key, mode = AES.MODE_CCM, nonce=nonce, assoc_len=0)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
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

    # Forge and test the message with a random key

    (IV1, c1, tag1) = ccm(m1, key)
    (IV2, c2, tag2) = ccm(m2, key)
    (c3, tag3) = forge(m1, m2, c1, c2, tag1)

    ccm_dec(c3, tag3, key, IV2) # will raise an exception

