import random
import math

# 扩展欧几里得算法
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# 计算模逆元
def invmod(a, m):
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"模逆元不存在: {a} 和 {m} 不互质")
    return x % m

# Miller-Rabin素数测试
def is_prime(n, k=5):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # 将 n-1 写成 2^r * d 的形式
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    def check_composite(a):
        x = pow(a, d, n)
        if x in (1, n - 1):
            return False
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return False
        return True

    for _ in range(k):
        a = random.randint(2, n - 2)
        if check_composite(a):
            return False
    return True

# 生成指定位数的质数
def generate_prime(bits=512):
    while True:
        # 生成奇数
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # 确保是bits位数且为奇数

        if is_prime(p):
            return p


class RSA:
    def __init__(self, p=None, q=None, bits=512):
        if p and q:
            self.p = p
            self.q = q
        else:
            print("生成RSA质数...")
            self.p = generate_prime(bits)
            self.q = generate_prime(bits)
            while self.p == self.q:
                self.q = generate_prime(bits)

        self._generate_keys()

    # 生成RSA密钥
    def _generate_keys(self):
        self.n = self.p * self.q
        self.et = (self.p - 1) * (self.q - 1)  # 欧拉函数

        # 公钥指数
        self.e = 3

        # 确保e与et互质
        while math.gcd(self.e, self.et) != 1:
            self.e += 2

        # 私钥指数
        self.d = invmod(self.e, self.et)

        print(f"p = {self.p}")
        print(f"q = {self.q}")
        print(f"n = {self.n}")
        print(f"et = {self.et}")
        print(f"e = {self.e}")
        print(f"d = {self.d}")

    def get_public_key(self):
        return (self.e, self.n)

    def get_private_key(self):
        return (self.d, self.n)

    def encrypt(self, m):
        return pow(m, self.e, self.n)

    def decrypt(self, c):
        return pow(c, self.d, self.n)

    def encrypt_string(self, text):
        # 将字符串转换为十六进制数字
        hex_str = text.encode('utf-8').hex()
        m = int(hex_str, 16)
        return self.encrypt(m)

    def decrypt_string(self, c):
        m = self.decrypt(c)
        # 将数字转换回字符串
        hex_str = hex(m)[2:]  # 去掉'0x'前缀
        # 确保十六进制字符串长度为偶数
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        return bytes.fromhex(hex_str).decode('utf-8')


def test_small_primes():
    print("=== 测试小质数 ===")
    # 使用小质数
    p = 61
    q = 53

    rsa = RSA(p, q)

    # 测试数字42
    test_num = 42
    print(f"\n测试数字: {test_num}")

    encrypted = rsa.encrypt(test_num)
    decrypted = rsa.decrypt(encrypted)

    print(f"加密: {test_num} -> {encrypted}")
    print(f"解密: {encrypted} -> {decrypted}")
    print(f"测试结果: {'成功' if test_num == decrypted else '失败'}")


def test_big_primes():
    print("\n=== 测试大质数 ===")
    rsa = RSA(bits=256)  # 使用256位质数

    test_num = 42
    print(f"\n测试数字: {test_num}")

    encrypted = rsa.encrypt(test_num)
    decrypted = rsa.decrypt(encrypted)

    print(f"加密: {test_num} -> {encrypted}")
    print(f"解密: {encrypted} -> {decrypted}")
    print(f"测试结果: {'成功' if test_num == decrypted else '失败'}")


def test_string_encryption():
    print("\n=== 测试字符串加密 ===")
    rsa = RSA(bits=256)

    test_string = "Hello, RSA!"
    print(f"测试字符串: '{test_string}'")

    encrypted = rsa.encrypt_string(test_string)
    decrypted = rsa.decrypt_string(encrypted)

    print(f"加密后的数字: {encrypted}")
    print(f"解密后的字符串: '{decrypted}'")
    print(f"测试结果: {'成功' if test_string == decrypted else '失败'}")


if __name__ == "__main__":
    # 测试扩展欧几里得算法和模逆
    print("测试模逆运算:")
    a, m = 17, 3120
    inv = invmod(a, m)
    print(f"invmod({a}, {m}) = {inv}")
    print(f"验证: {a} * {inv} % {m} = {a * inv % m}")

    # 运行测试
    test_small_primes()
    test_big_primes()
    test_string_encryption()