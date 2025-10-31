import os
import random
from Crypto.Cipher import AES

# 生成随机AES密钥
def generate_random_key():
    return os.urandom(16)

# 字节异或操作
def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# PKCS#7填充
def pkcs7_pad(data, block_size):
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)

# AES ECB加密
def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

# AES CBC加密
def aes_cbc_encrypt(plaintext, key, iv):
    block_size = len(key)
    plaintext = pkcs7_pad(plaintext, block_size)
    ciphertext = b''
    prev_block = iv

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        xored = xor_bytes(block, prev_block)
        encrypted_block = aes_ecb_encrypt(xored, key)
        ciphertext += encrypted_block
        prev_block = encrypted_block
    return ciphertext

# 加密预言机：随机选择ECB或CBC模式加密数据
def encryption_oracle(plaintext):
    key = generate_random_key()
    # 在明文前后添加5-10个随机字节
    prefix_len = random.randint(5, 10)
    suffix_len = random.randint(5, 10)
    prefix = os.urandom(prefix_len)
    suffix = os.urandom(suffix_len)
    modified_plaintext = prefix + plaintext + suffix
    # 随机选择加密模式
    if random.randint(0, 1) == 0:
        # ECB模式
        print("Oracle选择: ECB模式")
        return aes_ecb_encrypt(pkcs7_pad(modified_plaintext, 16), key), "ECB"
    else:
        # CBC模式
        print("Oracle选择: CBC模式")
        iv = os.urandom(16)
        return aes_cbc_encrypt(modified_plaintext, key, iv), "CBC"

# 检测加密模式ECB/CBC
def detect_ecb_cbc(ciphertext):
    block_size = 16
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    # 检查是否有重复的块
    unique_blocks = set(blocks)
    # 如果存在重复块，很可能是ECB模式
    if len(blocks) != len(unique_blocks):
        return "ECB"
    else:
        return "CBC"


def advanced_detection_oracle():
    # 创建包含重复块的输入（3个相同的块）
    test_input = b'A' * 48  # 3个完整的AES块
    ciphertext, actual_mode = encryption_oracle(test_input)
    detected_mode = detect_ecb_cbc(ciphertext)
    return actual_mode, detected_mode

# 演示
def simple_demo():
    print("ECB/CBC检测器演示")
    # 创建一个明显包含重复块的输入
    test_data = b"AAAAAAAAAAAAAAAA" * 4  # 4个相同的块

    ciphertext, actual_mode = encryption_oracle(test_data)
    detected_mode = detect_ecb_cbc(ciphertext)

    print(f"实际加密模式: {actual_mode}")
    print(f"检测到的模式: {detected_mode}")
    print(f"检测结果: {'正确' if actual_mode == detected_mode else '错误'}")

if __name__ == "__main__":
    simple_demo()
    print("\n")
