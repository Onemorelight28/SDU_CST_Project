import random
import hashlib
from phe import paillier

# --- 1. 公共参数和辅助函数 ---

def setup_group_and_hash(key_length=1024):
    """
    生成一个大素数来模拟素数阶循环群 G。
    在实践中，会使用更复杂的密码学群。
    这里我们使用模 p 的乘法群。
    """
    # 为了简化，我们只使用一个大素数 p 作为模数。
    # 在一个真实的系统中，会使用安全素数和生成元。
    p = 100663435183797483443429381292534639899738483252199994361993313939369945300139
    # 定义一个哈希函数 H: U -> G
    # 将字符串输入哈希，然后转换为一个整数，最后模 p
    def H(identifier: str) -> int:
        hex_hash = hashlib.sha256(identifier.encode()).hexdigest()
        int_hash = int(hex_hash, 16)
        return int_hash % p
        
    print("公共参数设置完成。")
    return p, H

# --- 2. 参与方类的定义 ---

class Party1:
    def __init__(self, V: set, group_p: int, hash_function):
        """
        初始化 P1。
        :param V: P1 的标识符集合。
        :param group_p: 群的模数 p。
        :param hash_function: 哈希函数 H。
        """
        self.V = V
        self.p = group_p
        self.H = hash_function
        self.k1 = None
        self.pk = None
        print(f"P1 已初始化，持有 {len(self.V)} 个元素。")

    def setup(self):
        """P1 选择它的私钥 k1。"""
        # 从 Z_p^* 中选择一个随机私钥 k1
        self.k1 = random.randint(1, self.p - 1)
        print("P1: 已生成私钥 k1。")

    def receive_pk(self, pk: paillier.PaillierPublicKey):
        """P1 接收来自 P2 的同态加密公钥。"""
        self.pk = pk
        print("P1: 已接收到同态加密公钥 pk。")
        
    def round1(self) -> list:
        """
        执行协议的 Round 1。
        P1 对其集合中的每个元素 v 进行 H(v)^k1 计算。
        """
        print("\n--- P1: 开始 Round 1 ---")
        blinded_elements = [pow(self.H(v), self.k1, self.p) for v in self.V]
        random.shuffle(blinded_elements)
        print(f"P1: 计算了 {len(blinded_elements)} 个盲化元素，并将其随机排序后发送给 P2。")
        return blinded_elements

    def round3(self, Z: list, p2_data: list) -> paillier.EncryptedNumber:
        """
        执行协议的 Round 3。
        P1 识别交集并计算加密后的总和。
        :param Z: 从 P2 收到的 H(v_i)^(k1*k2) 集合。
        :param p2_data: 从 P2 收到的 (H(w_j)^k2, AEnc(t_j)) 对的列表。
        :return: 加密后的最终总和 S_J。
        """
        print("\n--- P1: 开始 Round 3 ---")
        
        # 1. P1 对收到的 p2_data 中的第一部分进行指数运算
        p1_reblinded_map = {
            pow(h_w_k2, self.k1, self.p): encrypted_t
            for h_w_k2, encrypted_t in p2_data
        }
        print(f"P1: 对 P2 发来的 {len(p2_data)} 个数据对的第一部分进行再盲化。")
        
        # 2. 识别交集
        # 将 Z 转换为集合以便快速查找
        Z_set = set(Z)
        intersection_ciphertexts = []
        for reblinded_h, encrypted_t in p1_reblinded_map.items():
            if reblinded_h in Z_set:
                intersection_ciphertexts.append(encrypted_t)
        
        print(f"P1: 发现 {len(intersection_ciphertexts)} 个交集元素。")

        # 3. 同态地计算总和
        if not intersection_ciphertexts:
            # 如果没有交集，返回加密的0
            encrypted_sum = self.pk.encrypt(0)
        else:
            # 使用同态加法将所有交集元素的密文相加
            encrypted_sum = intersection_ciphertexts[0]
            for i in range(1, len(intersection_ciphertexts)):
                encrypted_sum += intersection_ciphertexts[i]
        
        print("P1: 已同态计算出交集值的总和。")

        # 4. 随机化结果 (ARefresh)
        # Paillier 的同态加法已经具有随机性，但为了严格遵循协议，
        # 我们可以通过加上一个加密的 0 来显式地进行再随机化。
        refreshed_encrypted_sum = encrypted_sum + self.pk.encrypt(0)
        print("P1: 对加密总和进行随机化，并发送给 P2。")
        
        return refreshed_encrypted_sum


class Party2:
    def __init__(self, W: dict, group_p: int, hash_function, he_key_length=1024):
        """
        初始化 P2。
        :param W: P2 的 {标识符: 值} 字典。
        :param group_p: 群的模数 p。
        :param hash_function: 哈希函数 H。
        """
        self.W = W
        self.p = group_p
        self.H = hash_function
        self.k2 = None
        self.pk = None
        self.sk = None
        self.he_key_length = he_key_length
        print(f"P2 已初始化，持有 {len(self.W)} 个元素。")

    def setup(self):
        """P2 选择私钥 k2 并生成同态加密密钥对。"""
        # 选择私钥 k2
        self.k2 = random.randint(1, self.p - 1)
        # 生成同态加密密钥对
        self.pk, self.sk = paillier.generate_paillier_keypair(n_length=self.he_key_length)
        print("P2: 已生成私钥 k2 和同态加密密钥对 (pk, sk)。")
        return self.pk

    def round2(self, p1_data: list) -> (list, list):
        """
        执行协议的 Round 2。
        :param p1_data: 从 P1 处收到的 H(v_i)^k1 列表。
        :return: (Z, p2_prepared_data) 元组
        """
        print("\n--- P2: 开始 Round 2 ---")
        
        # 1. 计算 Z = {H(v_i)^(k1*k2)}
        Z = [pow(h_v_k1, self.k2, self.p) for h_v_k1 in p1_data]
        random.shuffle(Z)
        print(f"P2: 计算了集合 Z 并随机排序。")

        # 2. 处理自己的数据 W
        p2_prepared_data = []
        for w, t in self.W.items():
            # 计算 H(w_j)^k2
            h_w_k2 = pow(self.H(w), self.k2, self.p)
            # 加密 t_j
            encrypted_t = self.pk.encrypt(t)
            p2_prepared_data.append((h_w_k2, encrypted_t))
        
        random.shuffle(p2_prepared_data)
        print(f"P2: 处理了自己的 {len(self.W)} 个数据对，并将其随机排序。")
        
        print("P2: 将 Z 和处理后的数据对发送给 P1。")
        return Z, p2_prepared_data

    def decrypt_final_sum(self, final_ciphertext: paillier.EncryptedNumber) -> int:
        """
        解密从 P1 处收到的最终密文。
        """
        print("\n--- P2: 输出阶段 ---")
        decrypted_sum = self.sk.decrypt(final_ciphertext)
        print(f"P2: 已解密最终结果。")
        return decrypted_sum

# --- 3. 协议执行流程 ---

def main():
    # 定义双方的数据
    # V: P1 的集合
    # W: P2 的 {标识符: 值} 字典
    p1_items = {'apple', 'banana', 'orange', 'grape', 'mango'}
    p2_items = {'banana': 10, 'grape': 25, 'pear': 15, 'apple': 5, 'watermelon': 30}
    
    # 计算期望结果
    intersection_keys = p1_items.intersection(p2_items.keys())
    expected_sum = sum(p2_items[key] for key in intersection_keys)
    
    print("="*50)
    print("协议开始")
    print("="*50)
    print(f"P1 的集合 V: {p1_items}")
    print(f"P2 的集合 W: {p2_items}")
    print(f"理论交集: {intersection_keys}")
    print(f"期望的总和: {expected_sum}")
    print("-" * 50)

    # 1. Setup
    p, H = setup_group_and_hash()
    
    p1 = Party1(p1_items, p, H)
    p2 = Party2(p2_items, p, H)

    p1.setup()
    p2_pk = p2.setup()
    p1.receive_pk(p2_pk)
    
    # 2. Round 1
    p1_to_p2_data = p1.round1()
    
    # 3. Round 2
    Z, p2_to_p1_data = p2.round2(p1_to_p2_data)
    
    # 4. Round 3
    final_encrypted_sum = p1.round3(Z, p2_to_p1_data)
    
    # 5. Output
    final_sum = p2.decrypt_final_sum(final_encrypted_sum)
    
    print("\n" + "="*50)
    print("协议结束")
    print("="*50)
    print(f"协议计算出的交集总和: {final_sum}")
    print(f"期望的交集总和: {expected_sum}")
    
    # 验证结果
    if final_sum == expected_sum:
        print("\n[SUCCESS] 协议成功执行，结果正确！")
    else:
        print("\n[FAILURE] 协议执行失败，结果不匹配。")

if __name__ == "__main__":
    main()