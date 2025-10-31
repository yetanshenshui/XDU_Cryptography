def pkcs7_pad(data, block_size):
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)

# 示例
original = b"YELLOW SUBMARINE"
padded = pkcs7_pad(original, 20)
print(padded)