import math

def main():
    p = 1009
    q = 3643
    n = p * q
    phi = (p - 1) * (q - 1)

    def count_unencrypted_messages(e, p, q):
        # 计算未加密信息的数量
        return (1 + math.gcd(e - 1, p - 1)) * (1 + math.gcd(e - 1, q - 1))

    min_count = float('inf')
    valid_e = []
    # 遍历所有可能的 e
    for e in range(2, phi):
        # 检查 e 是否与 phi 互质
        if math.gcd(e, phi) == 1:
            count = count_unencrypted_messages(e, p, q)

            if count < min_count:
                min_count = count
                valid_e = [e]
            elif count == min_count:
                valid_e.append(e)

    print(f"最小未加密信息数量: {min_count}")
    print(f"满足条件的 e 的个数: {len(valid_e)}")
    print(f"所有满足条件的 e 的和: {sum(valid_e)}")

if __name__ == "__main__":
    main()