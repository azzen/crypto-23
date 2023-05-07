from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode
import secrets
import re
import socket

"""
This function queries the server with the specific key_id to encrypt
the plaintext. It returns the IV and the ciphertext as bytes.
Example:
>>> (IV, ct) = real_oracle(44, b'Hello World!')
>>> print("IV = %s" % b64encode(IV))
IV = b'roVEA/Wt8N7Ojp1GXEdb8w=='
>>> print("ct = %s" % b64encode(ct))
ct = b'HNly5YICj5mPh1LW3SLgNw=='

You can also contact the server manually with netcat:
$ nc iict-mv330-sfa.einet.ad.eivd.ch 8000 
Welcome to USB's encryption server

Please enter the encryption key ID: 44
Please enter the message in hex to encrypt: AAAA            

Encryption successful:
Message w/ padding: aaaa0e0e0e0e0e0e0e0e0e0e0e0e0e0e
IV                : ae854403f5adf0dece8e9d465c475bf0
Ciphertext        : edfab2e3f33b97de070a6c71f3dd0e34

Bye!
"""

def real_oracle(key_id: int, plaintext: bytes, host='iict-mv330-sfa.einet.ad.eivd.ch', port=8000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        # Wait for ID prompt
        while b'ID: ' not in s.recv(1024):
            pass
        s.sendall(str(key_id).encode('ascii') + b'\n')
        s.sendall(plaintext.hex().encode('ascii') + b'\n')
        # Read until we get b'Bye!'
        output = b''
        while b'Bye!' not in output:
            output += s.recv(1024)

        # Read the plaintext, iv and ciphertext
        output = output.decode('ascii')
        pt = re.findall(r'Message.*?: ([0-9a-fA-F]+)\n', output)
        iv = re.findall(r'IV.*?: ([0-9a-fA-F]+)\n', output)
        ct = re.findall(r'Ciphertext.*?: ([0-9a-fA-F]+)\n', output)

        # Ensure that we got exactly 3 regex matches
        if len(pt) + len(iv) + len(ct) != 3:
            raise Exception("Failed to get ciphertext")

        return bytes.fromhex(iv[0]), bytes.fromhex(ct[0])

def increaseIV(ctr):
    ctr_int = int.from_bytes(ctr, "big")
    ctr_int += 1
    return int(ctr_int).to_bytes(AES.block_size, byteorder="big")

def oracle_attack(key_id: int, IV_0: bytes, C: bytes) -> tuple[int, bytes]:
    IV_1, _ = real_oracle(key_id, b"Salut hugo")
    for i in range(3000):
        print('\r', f"[*] Testing: {i}", end='')
        m = b"Le salaire journalier du dirigeant USB est de " + str(i).encode() + b" CHF"
        IV_1 = increaseIV(IV_1) # IV_1 + 1

        # IV_0 ^ ((IV_1 + 1) ^ M_1)
        m_xored = b"%s%s" % (strxor(IV_0, strxor(IV_1, m[:AES.block_size])), m[AES.block_size:])

        _, Cprime = real_oracle(MY_KEY_ID, m_xored)
        if Cprime == C:
            print("\n[+] salary found:", i)   
            return i, m

if __name__ == "__main__":
    MY_KEY_ID = 42
    value, message = oracle_attack(MY_KEY_ID, 
                  b64decode(b'7jEifQQCqQ3rZcQ/egT0AQ=='), 
                  b64decode(b'1lyePVLAttnvgt8Y0VUKz0jThiGTOW/MuYIUatU5LXUdVnwvknv7vPXAW5rhet1riB6k47RWbNWO6guC/AbjFg=='))
    print(f"[+] value = {value}, message = {message}")