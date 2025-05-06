def rc4_ksa(key):
    key_length = len(key)
    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, n):
    i = j = 0
    keystream = []
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return keystream

def rc4_decrypt(enc, key):
    S = rc4_ksa(key)
    keystream = rc4_prga(S, len(enc))
    return bytes([c ^ k for c, k in zip(enc, keystream)])

key = [0x33, 0xbf, 0xad, 0xde]
enc = [0x7D, 0x08, 0xED, 0x47, 0xE5, 0x00, 0x88, 0x3A,0x7A, 0x36, 0x02, 0x29, 0xE4]

plaintext = rc4_decrypt(enc, key)
print("Decrypted:", plaintext)
