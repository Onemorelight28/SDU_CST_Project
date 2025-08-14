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

    def _shamir_mul_add(self, s: int, P: Tuple[int, int], t: int, Q: Tuple[int, int]) -> Tuple[int, int]:
        """
        使用 Shamir's Trick 高效计算 [s]P + [t]Q
        """
        # 预计算 P+Q
        P_plus_Q = self._point_add(P, Q)
        R = (0, 0)

        # 从 s 和 t 的最高位开始处理
        for i in range(max(s.bit_length(), t.bit_length()) - 1, -1, -1):
            # Double
            R = self._point_add(R, R)

            # Add based on the bits of s and t
            s_bit = (s >> i) & 1
            t_bit = (t >> i) & 1

            if s_bit == 1 and t_bit == 1:
                R = self._point_add(R, P_plus_Q)
            elif s_bit == 1:
                R = self._point_add(R, P)
            elif t_bit == 1:
                R = self._point_add(R, Q)

        return R

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

    def _affine_to_jacobian(self, P: Tuple[int, int]) -> Tuple[int, int, int]:
        # (x, y) -> (x, y, 1)
        if P == (0, 0):
            return (1, 1, 0)  # 雅可比坐标系的无穷远点
        return (P[0], P[1], 1)

    def _jacobian_to_affine(self, P: Tuple[int, int, int]) -> Tuple[int, int]:
        X, Y, Z = P
        if Z == 0:
            return (0, 0)
        Z_inv = self._mod_inverse(Z, self.p)
        Z_inv_sq = (Z_inv * Z_inv) % self.p
        x = (X * Z_inv_sq) % self.p
        y = (Y * Z_inv_sq * Z_inv) % self.p
        return (x, y)

    def _point_double_jacobian(self, P: Tuple[int, int, int]) -> Tuple[int, int, int]:
        X1, Y1, Z1 = P
        if Z1 == 0:
            return (1, 1, 0)

        S = (4 * X1 * Y1 * Y1) % self.p
        M = (3 * X1 * X1 + self.a * Z1 * Z1 * Z1 * Z1) % self.p

        X3 = (M * M - 2 * S) % self.p
        Y3 = (M * (S - X3) - 8 * Y1 * Y1 * Y1 * Y1) % self.p
        Z3 = (2 * Y1 * Z1) % self.p

        return X3, Y3, Z3

    def _point_add_jacobian(self, P: Tuple[int, int, int], Q: Tuple[int, int, int]) -> Tuple[int, int, int]:
        if P[2] == 0:
            return Q
        if Q[2] == 0:
            return P

        X1, Y1, Z1 = P
        X2, Y2, Z2 = Q

        Z1_sq = (Z1 * Z1) % self.p
        Z2_sq = (Z2 * Z2) % self.p

        U1 = (X1 * Z2_sq) % self.p
        U2 = (X2 * Z1_sq) % self.p
        S1 = (Y1 * Z2_sq * Z2) % self.p
        S2 = (Y2 * Z1_sq * Z1) % self.p

        if U1 == U2:
            if S1 != S2:
                return (1, 1, 0)  # P = -Q
            else:
                return self._point_double_jacobian(P)  # P = Q

        H = (U2 - U1) % self.p
        R = (S2 - S1) % self.p
        H_sq = (H * H) % self.p
        H_cu = (H * H_sq) % self.p
        U1_H_sq = (U1 * H_sq) % self.p

        X3 = (R * R - H_cu - 2 * U1_H_sq) % self.p
        Y3 = (R * (U1_H_sq - X3) - S1 * H_cu) % self.p
        Z3 = (Z1 * Z2 * H) % self.p

        return X3, Y3, Z3

    def _point_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        if k % self.n == 0 or P == (0, 0):
            return (0, 0)

        P_jac = self._affine_to_jacobian(P)
        R_jac = (1, 1, 0)  # 初始为无穷远点

        # 使用基础的Double-and-Add，但在雅可比坐标下进行
        temp = P_jac
        while k > 0:
            if k & 1:
                R_jac = self._point_add_jacobian(R_jac, temp)
            temp = self._point_double_jacobian(temp)
            k >>= 1

        # 最终将结果转换回仿射坐标
        return self._jacobian_to_affine(R_jac)

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
        # sm3.sm3_hash返回十六进制字符串，需用bytes.fromhex转换
        hex_digest = sm3.sm3_hash(list(data_to_hash))
        return bytes.fromhex(hex_digest)

    def _get_e(self, z: bytes, msg: bytes) -> int:
        data_to_hash = z + msg
        hex_digest = sm3.sm3_hash(list(data_to_hash))
        # 将十六进制字符串转换为bytes，再转换为整数
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

        # === 使用优化后的方法 ===
        # 计算 (x1, y1) = [s]G + [t]P
        x1, y1 = self._shamir_mul_add(s, self.G, t, P)
        # ========================

        if x1 == 0 and y1 == 0:
            return False
        R = (e + x1) % self.n
        return R == r


class SM2Signer:
    def __init__(self, sm2_instance: SM2, private_key: int, user_id: bytes):
        self.sm2 = sm2_instance
        self.d = private_key
        self.user_id = user_id

        # === 预计算和缓存 ===
        print("Signer初始化：正在预计算公钥P和Z值...")
        self.P = self.sm2._point_mul(self.d, self.sm2.G)
        self.z = self.sm2._get_z(self.user_id, self.P)
        print("预计算完成。")

    def sign(self, msg: bytes) -> Tuple[int, int]:
        # 直接使用缓存的z值
        e = self.sm2._get_e(self.z, msg)

        while True:
            k = secrets.randbelow(self.sm2.n - 1) + 1
            x1, y1 = self.sm2._point_mul(k, self.sm2.G)
            r = (e + x1) % self.sm2.n
            if r == 0 or r + k == self.sm2.n:
                continue
            s = (self.sm2._mod_inverse(1 + self.d, self.sm2.n) * (k - r * self.d)) % self.sm2.n
            if s != 0:
                return r, s


def run_performance_test(sm2_instance, title: str):
    """
    一个通用的性能测试运行器，接收一个SM2实例和测试标题。
    """
    print(f"--- {title} ---")
    test_cases = [16, 64, 256, 1024, 4096]
    print(f"{'数据大小(B)':<12} {'密钥生成(ms)':<15} {'签名(ms)':<12} {'验证(ms)':<12} {'状态':<10}")
    print("-" * 64)

    # 为了结果稳定，对每个数据大小运行多次取平均值（可选，此处为简化只运行一次）
    for size in test_cases:
        data = secrets.token_bytes(size)
        user_id = b"test_user@example.com"

        # 1. 测试密钥生成
        start_keygen = time.time()
        d, P = sm2_instance.generate_keypair()
        keygen_time = (time.time() - start_keygen) * 1000

        # 2. 测试签名
        start_sign = time.time()
        signature = sm2_instance.sign(d, data, user_id)
        sign_time = (time.time() - start_sign) * 1000

        # 3. 测试验证
        start_verify = time.time()
        is_valid = sm2_instance.verify(P, user_id, data, signature)
        verify_time = (time.time() - start_verify) * 1000

        status = "成功" if is_valid else "失败!"
        print(f"{size:<12} {keygen_time:<15.3f} {sign_time:<12.3f} {verify_time:<12.3f} {status:<10}")

        if not is_valid:
            print("错误：验证失败，程序中断！")
            break


# ==================== 主程序入口 ====================
if __name__ == "__main__":
    # 实例化优化版SM2
    sm2_optimized = SM2()

    # 运行性能对比测试
    run_performance_test(sm2_optimized, "性能测试: 优化版SM2")
