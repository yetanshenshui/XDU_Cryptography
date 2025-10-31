import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random

# 目标Base64字符串
target_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
target_bytes = base64.b64decode(target_b64)

# 随机密钥和前缀
key = get_random_bytes(16)
random_prefix = get_random_bytes(random.randint(1, 100))


def encrypt(data):
    plaintext = random_prefix + data + target_bytes
    cipher = AES.new(key, AES.MODE_ECB)
    pad_len = 16 - len(plaintext) % 16
    return cipher.encrypt(plaintext + bytes([pad_len]) * pad_len)


# 发现块大小
block_size = 16
for i in range(1, 33):
    if len(encrypt(b'A' * i)) != len(encrypt(b'A' * (i + 1))):
        block_size = len(encrypt(b'A' * (i + 1))) - len(encrypt(b'A' * i))
        break

# 发现前缀长度
prefix_len = 0
for pad in range(block_size):
    ct = encrypt(b'A' * (pad + block_size * 2))
    blocks = [ct[i:i + block_size] for i in range(0, len(ct), block_size)]
    for i in range(len(blocks) - 1):
        if blocks[i] == blocks[i + 1]:
            prefix_len = i * block_size - pad
            break
    if prefix_len: break

# 计算对齐填充
prefix_pad = (block_size - prefix_len % block_size) % block_size
offset = prefix_len + prefix_pad

# 逐字节解密
result = b""
for i in range(len(encrypt(b'A' * prefix_pad)) - offset):
    shift = block_size - 1 - (i % block_size)
    padding = b'A' * (prefix_pad + shift)
    target_block = encrypt(padding)[(offset + i) // block_size * block_size:]

    for byte in range(256):
        test_input = padding + result + bytes([byte])
        test_block = encrypt(test_input)[(offset + i) // block_size * block_size:]
        if test_block[:block_size] == target_block[:block_size]:
            result += bytes([byte])
            break

print(result.decode('utf-8'))