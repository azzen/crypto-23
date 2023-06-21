from hashlib import sha256
from secrets import SystemRandom
from sage.all import *

def params():
    p256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a256 = p256 - 3
    b256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    E = EllipticCurve(GF(p256), [a256, b256])
    G = E(gx, gy)
    return (G, E, n)

def keyGen(G, n):
    a = ZZ.random_element(n)
    A = a*G
    return (a, A)

def fastInverse(k, n):
    return power_mod(k, n-2, n)

def H(M, n):
    return int(sha256(M).hexdigest(),16) % n


def sign(M: bytes, a: int):
    (G, E, n) = params()
    F = Integers(n)
    r = 0
    s = 0
    while r == 0 or s == 0:
        k = ZZ.random_element(n)
        Q = k * G
        x_1 = Q[0]
        r = F(x_1)
        k_inv = fastInverse(k, n)
        s = F((H(M, n) + a * r) * k_inv)
    return (r, s)
    

def verify(M, sig, A, G, n):
    (r, s) = sig
    s_inv = fastInverse(s, n)
    u1 = s_inv*H(M, n)
    u2 = s_inv*r
    return ((u1*G + u2*A)[0].lift() % n) == r

def verify_fix(M, sig, A, G, n):
    (r, s) = sig
    if not (1 <= r <= n - 1) or not (1 <= s <= n - 1):
        return False
    s_inv = fastInverse(s, n)
    u1 = s_inv*H(M, n)
    u2 = s_inv*r
    return ((u1*G + u2*A)[0].lift() % n) == r

# Test ECDSA sign
(G, e, n) = params()
(a, A) = keyGen(G, n)
(r, s) = sign(b'Hello world!', a)
print("Test ECDSA sign with fixed verify: ", verify_fix(b'Hello world!', (r,s), A, G, n))
print("Test ECDSA sign with verify: ", verify(b'Hello world!', (r,s), A, G, n))


# Attack with (0, 0)
(G, e, n) = params()
A = e(103391715223592104880946617363764734060447968625876169899508608725561253089994, 11799287218278686980098131532236831839559217772535271225734297692249395988410)
m = "Je dois 10000 CHF à Alexandre Duc".encode('utf8')
pair = (0, 0)
print("Attack with 0 and verify: ", verify(m, pair, A, G, n))
print("Attack with 0 and verify_fix: ", verify_fix(m, pair, A, G, n))


