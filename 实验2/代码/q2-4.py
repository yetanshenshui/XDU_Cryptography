import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

# 全局随机密钥
global_key = get_random_bytes(16)

# 要解密的未知字符串（base64编码）
unknown_b64 = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

# 解码未知字符串
unknown_string = base64.b64decode(unknown_b64)

def encryption_oracle(plaintext):
    # 在用户输入后附加未知字符串
    full_plaintext = plaintext + unknown_string

    # 使用 PKCS7 填充
    padding_length = 16 - (len(full_plaintext) % 16)
    if padding_length == 0:
        padding_length = 16
    full_plaintext += bytes([padding_length]) * padding_length

    # ECB 模式加密
    cipher = AES.new(global_key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(full_plaintext)

    return ciphertext

def detect_block_size():
    plaintext = b""
    initial_length = len(encryption_oracle(plaintext))

    # 不断增加输入长度，直到密文长度变化
    for i in range(1, 100):
        plaintext = b"A" * i
        new_length = len(encryption_oracle(plaintext))

        if new_length != initial_length:
            block_size = new_length - initial_length
            return block_size

    return None

def detect_ecb(block_size):
    # 发送两个相同块的明文
    plaintext = b"A" * block_size * 3
    ciphertext = encryption_oracle(plaintext)

    # 检查是否有重复的块
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    # 如果有重复的块，说明是 ECB 模式
    return len(blocks) != len(set(blocks))

def byte_at_a_time_ecb_decryption():
    # 1. 检测块大小
    block_size = detect_block_size()
    # 2. 检测 ECB 模式
    is_ecb = detect_ecb(block_size)
    if not is_ecb:
        print("警告：不是 ECB 模式，攻击可能失败")
    # 3. 确定未知字符串的长度
    base_length = len(encryption_oracle(b""))
    # 4. 逐字节解密
    discovered = b""

    # 对于每个字节位置进行解密
    for byte_pos in range(base_length):
        # 计算当前字节所在的块和块内位置
        block_index = byte_pos // block_size
        byte_in_block = byte_pos % block_size

        # 构造短一个字节的输入
        padding_length = block_size - byte_in_block - 1
        short_input = b"A" * padding_length

        # 获取目标密文块（我们想要解密的块）
        target_ciphertext = encryption_oracle(short_input)
        target_block = target_ciphertext[block_index * block_size:(block_index + 1) * block_size]

        # 构建字典：最后一个字节的所有可能值
        dictionary = {}

        # 对于所有可能的最后一个字节
        for byte_val in range(256):
            # 构造测试输入：padding + 已知字节 + 测试字节
            test_input = short_input + discovered + bytes([byte_val])

            # 确保我们只取第一个块进行比较
            test_ciphertext = encryption_oracle(test_input)
            test_block = test_ciphertext[0:block_size]

            dictionary[test_block] = bytes([byte_val])

        # 在字典中查找匹配的块
        if target_block in dictionary:
            discovered_byte = dictionary[target_block]
            discovered += discovered_byte
        else:
            break

    # 移除 PKCS7 填充
    try:
        padding_length = discovered[-1]
        if padding_length <= block_size:
            # 检查填充是否有效
            if discovered[-padding_length:] == bytes([padding_length]) * padding_length:
                discovered = discovered[:-padding_length]
    except:
        pass

    return discovered

def main():
    # 执行解密攻击
    decrypted = byte_at_a_time_ecb_decryption()
    print("解密内容:")
    print(decrypted.decode('utf-8'))

if __name__ == "__main__":
    main()