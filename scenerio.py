import random

# RSA functions added
def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(start, end):
    while True:
        num = random.randint(start, end)
        if is_prime(num):
            return num

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    d, x1, x2, y1 = 0, 0, 1, 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2, x1 = x1, x
        d, y1 = y1, y

    if temp_phi == 1:
        return d + phi

def generate_rsa_keys():
    p = generate_prime(100, 300)
    q = generate_prime(100, 300)
    n = p * q
    phi = (p-1) * (q-1)
    
    e = 3
    while gcd(e, phi) != 1:
        e += 2

    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def rsa_encrypt(message, pub_key):
    e, n = pub_key
    cipher = pow(int(message, 2), e, n)  # we convert the binary message to integer before encryption 
    return cipher

def rsa_decrypt(ciphertext, priv_key):
    d, n = priv_key
    plain = bin(pow(ciphertext, d, n))[2:].zfill(8)  # we convert the decrypted integer to binary before returning
    return plain

# some S-DES functions added
def generate_random_key(length=8):
    return ''.join(random.choice('01') for _ in range(length))

def generate_random_key(length=10):
    return ''.join(random.choice(['0', '1']) for _ in range(length))


def permute(bits, permutation):
    return ''.join(bits[i] for i in permutation)


def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]


def xor(bits1, bits2):
    return ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bits1, bits2))


def sbox_lookup(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return format(sbox[row][col], '02b')


def f_k(block, subkey):
    EP = [3, 0, 1, 2, 1, 2, 3, 0]  #for a 4-bit block
    S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
    S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
    P4 = [1, 3, 2, 0]

    expanded_half = permute(block[4:], EP)
    xor_result = xor(expanded_half, subkey)

    left_half = xor_result[:4]
    right_half = xor_result[4:]

    left_sbox = sbox_lookup(left_half, S0)
    right_sbox = sbox_lookup(right_half, S1)

    sbox_result = left_sbox + right_sbox
    p4_result = permute(sbox_result, P4)

    return xor(block[:4], p4_result) + block[4:]

def split_into_blocks(data, block_size=8):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def encrypt_decrypt_blocks(blocks, keys, encrypt=True):
    result_blocks = []
    for block in blocks:
        if len(block) < 8:
            block = block.ljust(8, '0')  # Padding if necessary
        result_blocks.append(s_des_encrypt_decrypt(block, keys, encrypt))
    return result_blocks

def s_des_encrypt_decrypt(plaintext, keys, encrypt=True):
    IP = [1, 5, 2, 0, 3, 7, 4, 6]
    IP_inv = [3, 0, 2, 4, 6, 1, 7, 5]
    permuted_text = permute(plaintext, IP)

    if encrypt:
        temp = f_k(permuted_text, keys[0])
        temp = temp[4:] + temp[:4]
        result = f_k(temp, keys[1])
    else:
        temp = f_k(permuted_text, keys[1])
        temp = temp[4:] + temp[:4]
        result = f_k(temp, keys[0])

    message = permute(result, IP_inv)
    return message


def key_generation(key):
    P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
    P8 = [5, 2, 6, 3, 7, 4, 9, 8]

    permuted_key = permute(key, P10)
    left, right = permuted_key[:5], permuted_key[5:]
    left_shifted = left_shift(left, 1) + left_shift(right, 1)
    key1 = permute(left_shifted, P8)
    left_shifted = left_shift(left_shift(left, 2), 1) + left_shift(left_shift(right, 2), 1)
    key2 = permute(left_shifted, P8)

    return key1, key2

random_key = generate_random_key()

# Command-based GUI Functions
def main_menu():
    print("\nRSA and S-DES Communication Simulation")
    print("1. Generate RSA Key Pairs for Alice and Bob")
    print("2. Share Public Keys and Encrypt S-DES Key with RSA")
    print("3. Encrypt Message with S-DES")
    print("4. Decrypt Message with S-DES")
    print("5. Exit")
    choice = input("Enter choice: ")
    return choice

def integrate_s_des_functions():
    # S-DES Anahtar Üretimi
    global s_des_key, keys
    s_des_key = generate_random_key(10)  # S-DES için rastgele anahtar üret
    keys = key_generation(s_des_key)  # S-DES için iki alt anahtar üretir
    print(f"\nGenerated S-DES Key: {s_des_key}")
    print(f"S-DES Subkeys: {keys}")

def generate_rsa_keys_interface():
    global alice_pub_key, alice_priv_key, bob_pub_key, bob_priv_key
    alice_pub_key, alice_priv_key = generate_rsa_keys()
    bob_pub_key, bob_priv_key = generate_rsa_keys()
    print("\nRSA Key Pairs Generated for Alice and Bob.")
    print(f"Alice's Public Key: {alice_pub_key}")
    print(f"Alice's Private Key: {alice_priv_key}")
    print(f"Bob's Public Key: {bob_pub_key}")
    print(f"Bob's Private Key: {bob_priv_key}")

def share_keys_and_encrypt_sdes_key():
    global encrypted_key, decrypted_key, s_des_key,keys
    s_des_key = generate_random_key()
    keys = key_generation(s_des_key)
    print(f"\nGenerated S-DES Key: {s_des_key}")
    print(f"S-DES Subkeys: {keys}")
    encrypted_key = rsa_encrypt(s_des_key, bob_pub_key)
    decrypted_key = rsa_decrypt(encrypted_key, bob_priv_key)
    print("S-DES Key Encrypted with Bob's Public Key and Sent to Bob.")
    print(f"Bob has decrypted the key: {decrypted_key}")
def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary):
    text = ''
    for i in range(0, len(binary), 8):
        text += chr(int(binary[i:i+8], 2))
    return text

# Modify the encrypt_message_with_sdes function to convert the message to binary first
def encrypt_message_with_sdes():
    global encrypted_message
    message = input("\nEnter message to encrypt with S-DES: ")
    message_binary = text_to_binary(message)  # Convert message to binary
    # Split the binary message into blocks and encrypt each block
    encrypted_blocks = encrypt_decrypt_blocks(split_into_blocks(message_binary), keys, encrypt=True)
    encrypted_message = ''.join(encrypted_blocks)
    print(f"Encrypted Message: {encrypted_message}")

# Modify the decrypt_message_with_sdes function to convert the decrypted binary back to text
def decrypt_message_with_sdes():
    decrypted_blocks = encrypt_decrypt_blocks(split_into_blocks(encrypted_message), keys, encrypt=False)
    decrypted_message_binary = ''.join(decrypted_blocks)
    decrypted_message = binary_to_text(decrypted_message_binary)  # Convert binary back to text
    print(f"\nDecrypted Message: {decrypted_message}")

# Main execution loop
if __name__ == "__main__":
    alice_pub_key = alice_priv_key = bob_pub_key = bob_priv_key = None
    encrypted_key = decrypted_key = s_des_key = None
    encrypted_message = ""

    while True:
        choice = main_menu()
        if choice == '1':
            generate_rsa_keys_interface()
        elif choice == '2':
            if alice_pub_key and bob_pub_key:
                share_keys_and_encrypt_sdes_key()
            else:
                print("RSA key pairs must be generated first (Option 1).")
        elif choice == '3':
            if decrypted_key:
                encrypt_message_with_sdes()
            else:
                print("S-DES key must be shared first (Option 2).")
        elif choice == '4':
            if encrypted_message:
                decrypt_message_with_sdes()
            else:
                print("There's no encrypted message to decrypt.")
        elif choice == '5':
            print("Exiting program.")
            break
        else:
            print("Invalid choice, please try again.")
