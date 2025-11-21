# 以下只有部分关键代码，并非完整的可直接运行的


# 1.提取加密帧中RSA参数
def getOptions(filepath: str):
    with open(filepath, "r", encoding='GBK') as f:
        msg = f.read()
        n = int('0x' + msg[:1024 // 4], 16)
        e = int('0x' + msg[1024 // 4:2048 // 4], 16)
        c = int('0x' + msg[2048 // 4:], 16)
    return n, e, c



# 2、共模攻击
def com_module_attack(e1, e2, n, c1, c2):
# a*e1 + b*e2 = 1
    a, b, d = extended_gcd(e1, e2)
    print('============frame0, frame4===================')
    print('p=')
    print('q=')
    print('frame0_e=' + str(e1))
    print('frame4_e=' + str(e2))
    print('msg=', end='')
    print(libnum.n2s(int((pow(c1, a, n) * pow(c2, b, n)) % n))[-8:])



# 3、因数碰撞攻击
def bad_choose_pq_com(e1, c1, n1, e2, c2, n2):
    p = math.gcd(n1, n2)
    q1 = n1 // p
    q2 = n2 // p
    print('================frame1======================')
    print('p=' + str(p))
    print('q=' + str(q1))
    print('e=' + str(e1))
    print('msg=', end='')
    decryptRSA(p, q1, e1, c1)
    print('================frame18======================')
    print('p=' + str(p))
    print('q=' + str(q2))
    print('e=' + str(e2))
    print('msg=', end='')
    decryptRSA(p, q2, e2, c2)



# 4、低加密指数广播攻击
def broadcast_attack(params: list):
    x, n = chinese_remainder_theorem(params)
    print('==========frame3, 8, 12, 16, 20==============')
    print('p=')
    print('q=')
    print('e=5')
    print('msg=', end='')
    print(libnum.n2s(int(gmpy2.iroot(x, 5)[0]))[-8:])



# 5、Pollard p-1分解攻击
def factor_n_p_1_attack(frames: list):
    i = 0
    for c, n, e in frames:
        if i == 0:
            print('================frame2======================')
        elif i == 1:
            print('================frame6======================')
        else:
            print('================frame19======================')
    p = factor_n_p_1(n)
    q = n // p
    print('p=' + str(p))
    print('q=' + str(q))
    print('e=' + str(e))
    print('msg=', end='')
    decryptRSA(p, q, e, c)
    i = i + 1



# 6、Fermat分解攻击
def factor_n_fermat_attack(frames: list):
    i = 0
    for c, n, e in frames:
        if i == 0:
            print('================frame10======================')
        else:
            print('================frame14======================')
    p, q = fermat(n)
    print('p=' + str(p))
    print('q=' + str(q))
    print('e=' + str(e))
    print('msg=', end='')
    decryptRSA(p, q, e, c)
    i = i + 1