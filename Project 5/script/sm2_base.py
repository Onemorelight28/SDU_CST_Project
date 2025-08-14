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
        p1 = self._point_mul(s, self.G)
        p2 = self._point_mul(t, P)
        x1, y1 = self._point_add(p1, p2)
        if x1 == 0 and y1 == 0:
            return False
        R = (e + x1) % self.n
        return R == r


def test_sm2_functionality_and_performance():
    sm2 = SM2()
    test_cases = [16, 64, 256, 1024, 4096]
    print("SM2 功能及性能测试 (已修正为合规版本):")
    print(f"{'数据大小(B)':<12} {'密钥生成(ms)':<15} {'签名(ms)':<12} {'验证(ms)':<12} {'状态':<10}")
    print("-" * 62)
    for size in test_cases:
        data = secrets.token_bytes(size)
        user_id = b"test_user@example.com"
        start_keygen = time.time()
        d, P = sm2.generate_keypair()
        keygen_time = (time.time() - start_keygen) * 1000
        start_sign = time.time()
        signature = sm2.sign(d, data, user_id)
        sign_time = (time.time() - start_sign) * 1000
        start_verify = time.time()
        is_valid = sm2.verify(P, user_id, data, signature)
        verify_time = (time.time() - start_verify) * 1000
        status = "成功" if is_valid else "失败!"
        print(f"{size:<12} {keygen_time:<15.3f} {sign_time:<12.3f} {verify_time:<12.3f} {status:<10}")
        if not is_valid:
            print("错误：验证失败，程序中断！")
            break


if __name__ == "__main__":
    test_sm2_functionality_and_performance()
