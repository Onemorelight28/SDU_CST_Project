import time
import secrets
from typing import Tuple
from gmssl import sm3

# SM2参数 (使用推荐的256位素数域椭圆曲线)
SM2_p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
SM2_G = (SM2_Gx, SM2_Gy)


class SM2:
    def __init__(self):
        self.p = SM2_p
        self.a = SM2_a
        self.b = SM2_b
        self.n = SM2_n
        self.G = SM2_G
        self.byte_len = 256 // 8

    def _int_to_bytes(self, i: int) -> bytes:
        return i.to_bytes(self.byte_len, byteorder="big")

    def _mod_inverse(self, a: int, m: int) -> int:
        if a == 0:
            raise ValueError("模逆元不存在")

        def extended_gcd(a, b):
            if b == 0:
                return a, 1, 0
            else:
                g, x, y = extended_gcd(b, a % b)
                return g, y, x - (a // b) * y

        g, x, _ = extended_gcd(a, m)
        if g != 1:
            raise ValueError("模逆元不存在")
        else:
            return x % m

    def _point_add(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if (y1 + y2) % self.p == 0:
                return (0, 0)
            else:
                lam = (3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1, self.p) % self.p
        else:
            lam = (y2 - y1) * self._mod_inverse(x2 - x1, self.p) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def _point_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        k = k % self.n
        R = (0, 0)
        current = P
        while k > 0:
            if k & 1:
                R = self._point_add(R, current)
            current = self._point_add(current, current)
            k >>= 1
        return R

    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        d = secrets.randbelow(self.n - 1) + 1
        P = self._point_mul(d, self.G)
        return d, P

    def _get_z(self, user_id: bytes, P: Tuple[int, int]) -> bytes:
        entl = (len(user_id) * 8).to_bytes(2, "big")
        a_bytes = self._int_to_bytes(self.a)
        b_bytes = self._int_to_bytes(self.b)
        gx_bytes = self._int_to_bytes(self.G[0])
        gy_bytes = self._int_to_bytes(self.G[1])
        px_bytes = self._int_to_bytes(P[0])
        py_bytes = self._int_to_bytes(P[1])
        data_to_hash = entl + user_id + a_bytes + b_bytes + gx_bytes + gy_bytes + px_bytes + py_bytes
        hex_digest = sm3.sm3_hash(list(data_to_hash))
        return bytes.fromhex(hex_digest)

    def _get_e(self, z: bytes, msg: bytes) -> int:
        data_to_hash = z + msg
        hex_digest = sm3.sm3_hash(list(data_to_hash))
        h_digest_bytes = bytes.fromhex(hex_digest)
        e = int.from_bytes(h_digest_bytes, byteorder="big")
        return e

    def sign(self, d: int, msg: bytes, user_id: bytes) -> Tuple[int, int]:
        P = self._point_mul(d, self.G)
        z = self._get_z(user_id, P)
        e = self._get_e(z, msg)
        while True:
            k = secrets.randbelow(self.n - 1) + 1
            x1, y1 = self._point_mul(k, self.G)
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue
            s = (self._mod_inverse(1 + d, self.n) * (k - r * d)) % self.n
            if s != 0:
                return r, s

    def verify(self, P: Tuple[int, int], user_id: bytes, msg: bytes, signature: Tuple[int, int]) -> bool:
        r, s = signature
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        z = self._get_z(user_id, P)
        e = self._get_e(z, msg)
        t = (r + s) % self.n
        if t == 0:
            return False
        p1 = self._point_mul(s, self.G)
        p2 = self._point_mul(t, P)
        x1, y1 = self._point_add(p1, p2)
        if x1 == 0 and y1 == 0:
            return False
        R = (e + x1) % self.n
        return R == r

    # --- PoC 辅助方法 ---
    def sign_manual_k(self, d: int, msg: bytes, user_id: bytes, k: int) -> Tuple[int, int]:
        """使用指定的k进行SM2签名，用于攻击模拟"""
        P = self._point_mul(d, self.G)
        z = self._get_z(user_id, P)
        e = self._get_e(z, msg)

        x1, y1 = self._point_mul(k, self.G)
        r = (e + x1) % self.n
        if r == 0 or r + k == self.n:
            raise ValueError("k值导致r无效，请为攻击更换k")

        s = (self._mod_inverse(1 + d, self.n) * (k - r * d)) % self.n
        if s == 0:
            raise ValueError("k值导致s为0，请为攻击更换k")
        return r, s

    def ecdsa_sign_manual_k(self, d: int, msg: bytes, k: int) -> Tuple[int, int, int]:
        """使用指定的k进行ECDSA签名，用于攻击模拟"""
        # 1. 计算消息哈希 e
        hex_digest = sm3.sm3_hash(list(msg))
        e = int.from_bytes(bytes.fromhex(hex_digest), "big")

        # 2. 计算 kG = (x, y)
        x, y = self._point_mul(k, self.G)

        # 3. 计算 r = x mod n
        r = x % self.n
        if r == 0:
            raise ValueError("k值导致r为0，请为攻击更换k")

        # 4. 计算 s = k^-1 * (e + r*d) mod n
        k_inv = self._mod_inverse(k, self.n)
        s = (k_inv * (e + r * d)) % self.n
        if s == 0:
            raise ValueError("k值导致s为0，请为攻击更换k")

        return r, s, e


def pitfall_1_leaking_k(sm2_instance: "SM2"):
    """
    演示场景1: 泄露临时随机数k导致私钥泄露
    """
    print("--- 场景1: 泄露临时随机数 k ---")

    # 1. 用户A生成密钥对
    d_A, P_A = sm2_instance.generate_keypair()
    user_id_A = b"user_a@example.com"
    msg = b"This is a test message for leaking k attack."

    # 2. 用户A进行签名, 但临时随机数k被泄露
    k_leaked = secrets.randbelow(sm2_instance.n - 1) + 1
    r, s = sm2_instance.sign_manual_k(d_A, msg, user_id_A, k_leaked)

    print(f"原始私钥 (d): {hex(d_A)}")
    print(f"泄露的随机数 (k): {hex(k_leaked)}")
    print(f"生成的签名 (r, s): ({hex(r)}, {hex(s)})")

    # 3. 攻击者使用泄露的k和签名(r, s)恢复私钥
    # 根据公式: d = (k - s) * mod_inverse(s + r, n)
    s_plus_r_inv = sm2_instance._mod_inverse(s + r, sm2_instance.n)
    d_recovered = ((k_leaked - s) * s_plus_r_inv) % sm2_instance.n

    print(f"恢复的私钥 (d_recovered): {hex(d_recovered)}")

    # 4. 验证私钥是否恢复成功
    assert d_A == d_recovered
    print("✅ 攻击成功: 私钥已成功恢复！\n")


def pitfall_2_reusing_k(sm2_instance: "SM2"):
    """
    演示场景2: 重复使用临时随机数k导致私钥泄露
    """
    print("--- 场景2: 重复使用临时随机数 k ---")

    # 1. 用户A生成密钥对
    d_A, P_A = sm2_instance.generate_keypair()
    user_id_A = b"user_a@example.com"
    msg1 = b"This is the first message."
    msg2 = b"This is the second message, signed with the same k."

    # 2. 用户A使用同一个k对两条不同消息签名
    k_reused = secrets.randbelow(sm2_instance.n - 1) + 1
    r1, s1 = sm2_instance.sign_manual_k(d_A, msg1, user_id_A, k_reused)
    r2, s2 = sm2_instance.sign_manual_k(d_A, msg2, user_id_A, k_reused)

    # 确保签名不同 (如果r1=r2, 则s1=s2, 攻击失效)
    if r1 == r2:
        print("偶然情况：两次签名完全相同，无法演示攻击。请重试。")
        return

    print(f"原始私钥 (d): {hex(d_A)}")
    print(f"重复使用的k: {hex(k_reused)}")
    print(f"签名1 (r1, s1): ({hex(r1)}, {hex(s1)})")
    print(f"签名2 (r2, s2): ({hex(r2)}, {hex(s2)})")

    # 3. 攻击者使用两次签名恢复私钥
    # 根据公式: d = (s1 - s2) * mod_inverse(r2 - r1 - s1 + s2, n)
    # 为避免负数，计算 (s1 - s2) % n 和 (s2 - s1 + r2 - r1) % n
    numerator = (s1 - s2) % sm2_instance.n
    denominator = (r2 - r1 - s1 + s2) % sm2_instance.n
    denominator_inv = sm2_instance._mod_inverse(denominator, sm2_instance.n)

    d_recovered = (numerator * denominator_inv) % sm2_instance.n

    print(f"恢复的私钥 (d_recovered): {hex(d_recovered)}")

    # 4. 验证私钥是否恢复成功
    assert d_A == d_recovered
    print("✅ 攻击成功: 私钥已成功恢复！\n")


def pitfall_3_same_d_k_in_ecdsa_sm2(sm2_instance: "SM2"):
    """
    演示场景3: 在SM2和ECDSA中使用相同的私钥d和临时随机数k
    """
    print("--- 场景3: SM2与ECDSA共用 d 和 k ---")

    # 1. 用户生成密钥对，计划在两个算法中使用
    d, P = sm2_instance.generate_keypair()
    user_id = b"user_ reusing_keys@example.com"
    msg = b"A message signed by two different algorithms."

    # 2. 用户使用相同的d和k，分别生成ECDSA和SM2签名
    k_reused = secrets.randbelow(sm2_instance.n - 1) + 1

    # ECDSA签名
    r1, s1, e1 = sm2_instance.ecdsa_sign_manual_k(d, msg, k_reused)

    # SM2签名
    r2, s2 = sm2_instance.sign_manual_k(d, msg, user_id, k_reused)

    print(f"原始私钥 (d): {hex(d)}")
    print(f"共用的k: {hex(k_reused)}")
    print(f"ECDSA签名 (r1, s1): ({hex(r1)}, {hex(s1)})")
    print(f"SM2签名 (r2, s2): ({hex(r2)}, {hex(s2)})")

    # 3. 攻击者结合两个签名恢复私钥
    # 根据公式 d = (e1 - s1*s2) * mod_inverse(s1*s2 + s1*r2 - r1, n)
    numerator = (e1 - s1 * s2) % sm2_instance.n
    denominator = (s1 * s2 + s1 * r2 - r1) % sm2_instance.n
    denominator_inv = sm2_instance._mod_inverse(denominator, sm2_instance.n)

    d_recovered = (numerator * denominator_inv) % sm2_instance.n

    print(f"恢复的私钥 (d_recovered): {hex(d_recovered)}")

    # 4. 验证
    assert d == d_recovered
    print("✅ 攻击成功: 私钥已成功恢复！\n")


# --- Main Execution ---
if __name__ == "__main__":
    sm2 = SM2()

    # 场景1: 泄露k
    pitfall_1_leaking_k(sm2)

    # 场景2: 重用k
    pitfall_2_reusing_k(sm2)

    # 场景3: SM2和ECDSA共用d和k
    pitfall_3_same_d_k_in_ecdsa_sm2(sm2)
