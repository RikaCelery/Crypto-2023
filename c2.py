from Crypto.Util.number import *
import math
import random


def get_key_pair(bits):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    gcd = math.gcd(e, phi)
    while gcd != 1:
        e = random.randrange(1, phi)
        gcd = math.gcd(e, phi)
    d = inverse(e, phi)
    return (e, n), (d, n)


def encrypt(plain_text, public_key):
    e, n = public_key
    cipher_text_long:int = pow(bytes_to_long(plain_text), e, n)
    cipher_text = hex(cipher_text_long)
    return long_to_bytes(cipher_text_long)


def decrypt(cipher_text_bytes, private_key):
    d, n = private_key
    cipher_text_long = bytes_to_long(cipher_text_bytes)
    decrypted_bytes = long_to_bytes(pow(cipher_text_long, d, n))
    return decrypted_bytes
