import timeit
import random
from sympy import isprime


# Functions for RSA implementation
def generate_prime(bits):
    while True:
        number = random.getrandbits(bits)
        if isprime(number):
            return number


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def multiplicative_inverse(e, phi):
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    if old_s < 0:
        old_s += phi
    return old_s


def generate_rsa_keys(bits=2048):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common choice for e
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))


def encrypt(public_key, plaintext):
    e, n = public_key
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    return ciphertext


def decrypt(private_key, ciphertext):
    d, n = private_key
    plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return plaintext


# User inputs
key_size = int(input("Enter key size (e.g., 1024, 2048): "))
plaintext = input("Enter plaintext to encrypt: ")

# Generate RSA keys
public_key, private_key = generate_rsa_keys(key_size)

# Measure encryption time
start_time = timeit.default_timer()
encrypted_message = encrypt(public_key, plaintext)
encryption_time = timeit.default_timer() - start_time
print("Encryption time:", encryption_time)

# Measure decryption time
start_time = timeit.default_timer()
decrypted_message = decrypt(private_key, encrypted_message)
decryption_time = timeit.default_timer() - start_time
print("Decryption time:", decryption_time)

# Output encrypted and decrypted message for verification
print("Encrypted message:", encrypted_message)
print("Decrypted message:", decrypted_message)
