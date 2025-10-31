from Crypto.Cipher import AES
import base64

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def pkcs7_pad(data, block_size):
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)

def pkcs7_unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def aes_ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

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

def aes_cbc_decrypt(ciphertext, key, iv):
    block_size = len(key)
    plaintext = b''
    prev_block = iv

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        decrypted_block = aes_ecb_decrypt(block, key)
        plaintext_block = xor_bytes(decrypted_block, prev_block)
        plaintext += plaintext_block
        prev_block = block
    return pkcs7_unpad(plaintext)

# 解密给定的文件
def decrypt_file():
    # 读取并解码base64文件
    with open('file_2.txt', 'r') as f:
        ciphertext_b64 = f.read().strip()
    ciphertext = base64.b64decode(ciphertext_b64)
    key = b"YELLOW SUBMARINE"
    iv = b'\x00' * 16

    # CBC解密
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)

    return plaintext.decode('utf-8', errors='ignore')


# 测试CBC加密解密
def test_cbc():
    test_key = b"YELLOW SUBMARINE"
    test_iv = b'\x00' * 16
    test_plaintext = b"Hello, this is a test message for CBC mode!"

    # 加密
    ciphertext = aes_cbc_encrypt(test_plaintext, test_key, test_iv)
    # 解密
    decrypted = aes_cbc_decrypt(ciphertext, test_key, test_iv)

if __name__ == "__main__":
    test_cbc()
    # 解密文件
    decrypted_text = decrypt_file()
    print("解密后的文件内容:")
    print(decrypted_text[:500] + "..." if len(decrypted_text) > 500 else decrypted_text)

    