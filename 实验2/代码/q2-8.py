import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class CBCBitFlippingAttack:
    def __init__(self):
        # 生成随机AES密钥
        self.key = os.urandom(16)
        self.iv = os.urandom(16)  # 为了CBC模式

    def quote_special_chars(self, data):
        data = data.replace(';', '%3B')
        data = data.replace('=', '%3D')
        return data

# 第一个函数：加密用户数据
    def encrypt_userdata(self, userdata):
        # 转义特殊字符
        userdata_quoted = self.quote_special_chars(userdata)

        # 构建完整字符串
        prefix = "comment1=cooking%20MCs;userdata="
        suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
        plaintext = prefix + userdata_quoted + suffix

        # 加密
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

        return ciphertext

# 第二个函数：检查是否有admin权限
    def check_admin(self, ciphertext):
        try:
            # 解密
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            plaintext = decrypted.decode('latin-1')  # 使用latin-1避免解码错误

            # 检查是否包含";admin=true;"
            if ";admin=true;" in plaintext:
                return True, plaintext

            return False, plaintext

        except Exception as e:
            return False, f"Decryption error: {str(e)}"

# 执行CBC位翻转攻击
    def cbc_bit_flip_attack(self):
        print("=== CBC Bit Flipping Attack ===")
        # 1. 首先加密一个已知的用户数据
        user_input = "XadminXtrueX"  # 使用占位符
        ciphertext = self.encrypt_userdata(user_input)

        print(f"Original user input: {user_input}")
        print(f"Ciphertext length: {len(ciphertext)} bytes")

        # 2. 检查原始密文是否包含admin权限
        is_admin, original_plaintext = self.check_admin(ciphertext)
        print(f"Before attack - Admin access: {is_admin}")

        # 3. 分析块结构
        prefix = "comment1=cooking%20MCs;userdata="
        print(f"Prefix length: {len(prefix)} characters")
        print(f"Prefix in hex: {prefix.encode().hex()}")

        # 4. 执行位翻转攻击
        ciphertext_bytearray = bytearray(ciphertext)
        flip_0 = ord('X') ^ ord(';')
        ciphertext_bytearray[16 + 0] ^= flip_0  # 影响第三个块的第一个字符
        # 在位置6: 'X' -> '=' (0x58 -> 0x3D)
        flip_6 = ord('X') ^ ord('=')
        ciphertext_bytearray[16 + 6] ^= flip_6  # 影响第三个块的第七个字符
        # 在位置11: 'X' -> ';' (0x58 -> 0x3B)
        flip_11 = ord('X') ^ ord(';')
        ciphertext_bytearray[16 + 11] ^= flip_11  # 影响第三个块的第十二个字符

        modified_ciphertext = bytes(ciphertext_bytearray)

        print("\nAfter bit flipping attack:")
        is_admin_after, modified_plaintext = self.check_admin(modified_ciphertext)
        print(f"Admin access: {is_admin_after}")

        return is_admin_after, modified_ciphertext

if __name__ == "__main__":
    # 执行攻击
    attack = CBCBitFlippingAttack()
    success, final_ciphertext = attack.cbc_bit_flip_attack()
    if success:
        print("\n Attack successful! Admin access gained!")
    else:
        print("\n Attack failed!")
