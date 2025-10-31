import os
from Crypto.Cipher import AES

# 全局随机密钥
AES_KEY = os.urandom(16)

def parse_kv(cookie):
    return dict(pair.split('=') for pair in cookie.split('&'))

# 生成用户配置文件
def profile_for(email):
    email = email.replace('&', '').replace('=', '')
    return f"email={email}&uid=10&role=user"

# PKCS#7 填充
def pkcs7_pad(data, block_size):
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)

# PKCS#7 去除填充
def pkcs7_unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

# 加密配置文件
def encrypt_profile(profile):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_data = pkcs7_pad(profile.encode(), 16)
    return cipher.encrypt(padded_data)

# 解密密文并解析配置文件
def decrypt_profile(ciphertext):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return parse_kv(pkcs7_unpad(decrypted).decode())

# ECB 剪切粘贴攻击
def ecb_cut_and_paste_attack():
    # 创建恰好填充一个块的email
    block1_email = "foo@bar.co"
    profile1 = profile_for(block1_email)
    cipher1 = encrypt_profile(profile1)

    # 获取第一个块（包含email部分）
    block1 = cipher1[:16]
    # 创建包含"admin"的块
    block2_email = "foo@bar.admin" + "\x0b" * 11
    profile2 = profile_for(block2_email[:13])
    cipher2 = encrypt_profile(profile2)

    # 获取第二个块（包含"admin"和填充）
    block2 = cipher2[16:32]

    # 组合攻击
    block3_email = "foo@bar.xx"
    profile3 = profile_for(block3_email)
    cipher3 = encrypt_profile(profile3)

    # 构造恶意密文：email部分 + role=部分 + admin块
    malicious_cipher = cipher3[:32] + block2

    # 解密验证
    result = decrypt_profile(malicious_cipher)
    return result

# 测试
if __name__ == "__main__":
    email = "test@example.com"
    profile = profile_for(email)
    print("配置文件:", profile)

    encrypted = encrypt_profile(profile)
    decrypted = decrypt_profile(encrypted)
    print("解密结果:", decrypted)
