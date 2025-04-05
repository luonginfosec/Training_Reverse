def KSA(key):
    S = list(range(256))
    T = [key[i % len(key)] for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        S[i], S[j] = S[j], S[i]
    print(S)
    return S

def PRGA(S, data_length):
    i = 0
    j = 0
    keystream = []
    for _ in range(data_length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        key_byte = S[(S[i] + S[j]) % 256]
        keystream.append(key_byte)
    return keystream

def RC4_encrypt_decrypt(key, data):
    key = [ord(c) for c in key]
    S = KSA(key)
    keystream = PRGA(S, len(data))
    result = bytes(d ^ k for d, k in zip(data, keystream))
    return result

def input_data():
    key = input("Nhập key: ")
    plaintext = input("Nhập plaintext: ").encode()
    return key, plaintext

def output_result(ciphertext, decrypted):
    print("Ciphertext (hex):", ciphertext.hex())
    print("Decrypted text:", decrypted.decode())

if __name__ == "__main__":
    key, plaintext = input_data()
    ciphertext = RC4_encrypt_decrypt(key, plaintext)
    decrypted = RC4_encrypt_decrypt(key, ciphertext)
    output_result(ciphertext, decrypted)
