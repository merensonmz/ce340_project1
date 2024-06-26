import random
import timeit

# code for task 3 and  4c and 4d
# task 4c and 4d can be done with using this code while writing report.

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



#
def f_k(block, subkey):
    EP = [3, 0, 1, 2, 1, 2, 3, 0]  #for a 4-bit block
    S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
    S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
    P4 = [1, 3, 2, 0]

    # second half EP permute
    expanded_half = permute(block[4:], EP)
    #  0 xor 0 = 0 1 xor 0 = 1
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

    return permute(result, IP_inv)


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
print(f"Random Key: {random_key}")

key1, key2 = key_generation(random_key)

plaintext = input("Enter plaintext (in bits): ")
plaintext_blocks = split_into_blocks(plaintext)

start_encryption = timeit.default_timer()
encrypted_blocks = encrypt_decrypt_blocks(plaintext_blocks, [key1, key2], True)
encryption_time = timeit.default_timer() - start_encryption
ciphertext = ''.join(encrypted_blocks)
print(f"Encrypted: {ciphertext}")
print(f"Encryption Time: {encryption_time:.8f} seconds")

start_decryption = timeit.default_timer()
decrypted_blocks = encrypt_decrypt_blocks(encrypted_blocks, [key1, key2], False)
decryption_time = timeit.default_timer() - start_decryption
decrypted_text = ''.join(decrypted_blocks)
print(f"Decrypted: {decrypted_text}")
print(f"Decryption Time: {decryption_time:.8f} seconds")
