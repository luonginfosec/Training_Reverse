def str_to_key(s):
    """Chuyển chuỗi 16 ký tự thành 4 số nguyên 32-bit (little endian)."""
    assert len(s) == 16, "Key must be 16 characters (128 bits)"
    return [int.from_bytes(s[i:i+4].encode(), 'little') for i in range(0, 16, 4)]

def tea_decrypt_block(block, key):
    """Giải mã 1 block (8 byte) bằng thuật toán TEA với 32 vòng."""
    v0 = int.from_bytes(block[:4], 'little')
    v1 = int.from_bytes(block[4:], 'little')
    delta = 0x9E3779B9
    sum_ = (delta * 32) & 0xFFFFFFFF

    for _ in range(32):
        v1 = (v1 - ((key[3] + (v0 >> 5)) ^ (sum_ + v0) ^ (key[2] + (v0 << 4)))) & 0xFFFFFFFF
        v0 = (v0 - ((key[1] + (v1 >> 5)) ^ (sum_ + v1) ^ (key[0] + (v1 << 4)))) & 0xFFFFFFFF
        sum_ = (sum_ - delta) & 0xFFFFFFFF

    return v0.to_bytes(4, 'little') + v1.to_bytes(4, 'little')

# Dữ liệu mã hóa từ .rdata
enc_bytes = bytes([
    0x19, 0x2C, 0x30, 0x2A, 0x79, 0xF9, 0x54, 0x02,
    0xB3, 0xA9, 0x6C, 0xD6, 0x91, 0x80, 0x95, 0x04,
    0x29, 0x59, 0xE8, 0xA3, 0x0F, 0x79, 0xBD, 0x86,
    0xAF, 0x05, 0x13, 0x6C, 0xFE, 0x75, 0xDB, 0x2B,
    0xAE, 0xE0, 0xF0, 0x5D, 0x88, 0x4B, 0x86, 0x89,
    0x33, 0x66, 0xAC, 0x45, 0x9A, 0x6C, 0x78, 0xA6,
    0x00, 0x00, 0x00, 0x00  # padding hoặc NULL bytes
])

# Key dạng chuỗi
key_str = "VdlKe9upfBFkkO0L"
key = str_to_key(key_str)

# Giải mã toàn bộ
plaintext = b''
for i in range(0, len(enc_bytes), 8):
    block = enc_bytes[i:i+8]
    if len(block) < 8:
        break  # bỏ qua block cuối nếu không đủ 8 bytes
    plaintext += tea_decrypt_block(block, key)

# Hiển thị kết quả
print("Decrypted (raw bytes):", plaintext)
try:
    print("Decrypted (ASCII):", plaintext.decode())
except UnicodeDecodeError:
    print("Decrypted (partial ASCII):", plaintext.decode(errors='ignore'))
