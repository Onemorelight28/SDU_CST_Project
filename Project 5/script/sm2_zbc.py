import ecdsa
import hashlib
import secrets
from ecdsa.ellipticcurve import INFINITY

# 使用比特币所用的 secp256k1 曲线
curve = ecdsa.SECP256k1
G = curve.generator
n = curve.order

# --- 步骤 1: 模拟场景 ---
# 假设我们有中本聪的公钥 P (这里我们生成一个模拟的)
# 真实的私钥 d_satoshi 是未知的，我们只在生成公钥时用一次
d_satoshi = ecdsa.SigningKey.from_secret_exponent(secrets.randbelow(n), curve=curve)
P_satoshi = d_satoshi.get_verifying_key()

print("--- 场景设定 ---")
print(f"中本聪的公钥 (P): (x={hex(P_satoshi.pubkey.point.x())}, y={hex(P_satoshi.pubkey.point.y())})")
print("-" * 20)


# --- 步骤 2: 攻击者伪造签名 ---
# 攻击者完全不知道 d_satoshi
print("\n--- 攻击者开始伪造 ---")

# 2.1. 选择任意随机数 u 和 v
u = secrets.randbelow(n)
v = secrets.randbelow(n)
print(f"1. 攻击者选择随机数 u: {hex(u)}")
print(f"2. 攻击者选择随机数 v: {hex(v)}")

# 2.2. 计算伪造的点 R = uG + vP
R = u * G + v * P_satoshi.pubkey.point
if R == INFINITY:
    raise ValueError("计算出的R点是无穷远点，请重试")
print(f"3. 计算伪造的点 R = uG + vP: (x={hex(R.x())}, y={hex(R.y())})")

# 2.3. 构造 r 和 s
r_forged = R.x() % n
v_inv = pow(v, -1, n)
s_forged = (r_forged * v_inv) % n
print(f"4. 构造伪造签名 (r,s):")
print(f"   r = R.x mod n = {hex(r_forged)}")
print(f"   s = r * v^-1 mod n = {hex(s_forged)}")

# 2.4. 构造对应的伪造哈希 e
e_forged = (u * s_forged) % n
print(f"5. 构造伪造哈希 e: {hex(e_forged)}")
print("-" * 20)


# --- 步骤 3: 在不同验证器上进行验证 ---
print("\n--- 验证阶段 ---")
# 攻击者可以提交任何他想声明的消息
fake_message = b"I am Satoshi Nakamoto and I own all bitcoins."
forged_signature_bytes = ecdsa.util.sigencode_der(r_forged, s_forged, n)


# 3.1. 存在漏洞的验证器
# 这个验证器直接使用攻击者提供的哈希值 e_forged
def verify_flawed(public_key, signature, message_hash_provided):
    try:
        # ecdsa-py 库的 verify_digest 允许直接传入哈希值
        # 这模拟了不自行计算哈希的验证逻辑
        is_valid = public_key.verify_digest(signature, digest=message_hash_provided.to_bytes(32, "big"), sigdecode=ecdsa.util.sigdecode_der)
        return is_valid
    except ecdsa.BadSignatureError:
        return False


print("1. 在【存在漏洞】的验证器上验证:")
print(f"   提交的消息: '{fake_message.decode()}'")
print(f"   提交的签名: (r={hex(r_forged)}, s={hex(s_forged)})")
print(f"   提交的哈希: {hex(e_forged)}")

result_flawed = verify_flawed(P_satoshi, forged_signature_bytes, e_forged)
print(f"   验证结果: {result_flawed}")
if result_flawed:
    print("   ✅ 攻击成功！伪造的签名通过了存在漏洞的验证器。")
else:
    print("   ❌ 攻击失败。")

print("-" * 20)


# 3.2. 正确的验证器
# 这个验证器会忽略外部哈希，自己对消息进行计算
def verify_correct(public_key, signature, message):
    try:
        # 库的 verify 方法会自己对 message 做哈希 (默认SHA-1，需指定)
        is_valid = public_key.verify(signature, message, hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der)
        return is_valid
    except ecdsa.BadSignatureError:
        return False


print("2. 在【正确】的验证器上验证:")
print(f"   提交的消息: '{fake_message.decode()}'")
print(f"   提交的签名: (r={hex(r_forged)}, s={hex(s_forged)})")
real_hash_of_fake_message = int.from_bytes(hashlib.sha256(fake_message).digest(), "big")
print(f"   验证器内部计算的哈希: {hex(real_hash_of_fake_message)}")

result_correct = verify_correct(P_satoshi, forged_signature_bytes, fake_message)
print(f"   验证结果: {result_correct}")
if not result_correct:
    print("   ✅ 伪造的签名被正确地拒绝了。")
else:
    print("   ❌ 系统存在未知问题。")
