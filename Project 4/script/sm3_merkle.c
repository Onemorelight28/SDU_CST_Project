#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <memory>
#include <cmath>


// 用于将字节数组转换为十六进制字符串以便打印
std::string bytesToHexString(const uint8_t* bytes, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return ss.str();
}

class SM3 {
public:
    SM3() {
        init();
    }

    void init() {
        state[0] = 0x7380166F;
        state[1] = 0x4914B2B9;
        state[2] = 0x172442D7;
        state[3] = 0xDA8A0600;
        state[4] = 0xA96F30BC;
        state[5] = 0x163138AA;
        state[6] = 0xE38DEE4D;
        state[7] = 0xB0FB0E4E;
        total_len = 0;
        buffer_len = 0;
    }

    void update(const uint8_t* data, size_t len) {
        total_len += len;
        size_t remaining_len = len;
        size_t data_offset = 0;

        while (remaining_len > 0) {
            size_t to_fill = 64 - buffer_len;
            size_t chunk_len = (remaining_len < to_fill) ? remaining_len : to_fill;

            for (size_t i = 0; i < chunk_len; ++i) {
                buffer[buffer_len + i] = data[data_offset + i];
            }

            buffer_len += chunk_len;
            data_offset += chunk_len;
            remaining_len -= chunk_len;

            if (buffer_len == 64) {
                compress(buffer);
                buffer_len = 0;
            }
        }
    }

    void final(uint8_t hash[32]) {
        // Step 1: Padding
        buffer[buffer_len++] = 0x80;

        if (buffer_len > 56) {
            while (buffer_len < 64) {
                buffer[buffer_len++] = 0x00;
            }
            compress(buffer);
            buffer_len = 0;
        }

        while (buffer_len < 56) {
            buffer[buffer_len++] = 0x00;
        }

        // Step 2: Append length
        uint64_t bit_len = total_len * 8;
        for (int i = 0; i < 8; ++i) {
            buffer[56 + i] = (bit_len >> (56 - 8 * i)) & 0xFF;
        }

        // Step 3: Final compression
        compress(buffer);

        // Step 4: Output hash
        for (int i = 0; i < 8; ++i) {
            hash[i * 4 + 0] = (state[i] >> 24) & 0xFF;
            hash[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            hash[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            hash[i * 4 + 3] = state[i] & 0xFF;
        }
    }

    uint32_t state[8];
    uint64_t total_len;
    size_t buffer_len;
    uint8_t buffer[64];

    // --- Helper Functions ---
    static inline uint32_t rotl(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline uint32_t T(int j) {
        if (j >= 0 && j <= 15) return 0x79CC4519;
        return 0x7A879D8A;
    }

    static inline uint32_t FF(int j, uint32_t x, uint32_t y, uint32_t z) {
        if (j >= 0 && j <= 15) return x ^ y ^ z;
        return (x & y) | (x & z) | (y & z);
    }

    static inline uint32_t GG(int j, uint32_t x, uint32_t y, uint32_t z) {
        if (j >= 0 && j <= 15) return x ^ y ^ z;
        return (x & y) | ((~x) & z);
    }

    static inline uint32_t P0(uint32_t x) {
        return x ^ rotl(x, 9) ^ rotl(x, 17);
    }

    static inline uint32_t P1(uint32_t x) {
        return x ^ rotl(x, 15) ^ rotl(x, 23);
    }

    // --- Core Compression Function ---
    void compress(const uint8_t block[64]) {
        uint32_t W[68];
        uint32_t W_prime[64];

        // Message Expansion
        for (int i = 0; i < 16; ++i) {
            W[i] = (uint32_t)block[i * 4] << 24 |
                (uint32_t)block[i * 4 + 1] << 16 |
                (uint32_t)block[i * 4 + 2] << 8 |
                (uint32_t)block[i * 4 + 3];
        }

        for (int j = 16; j < 68; ++j) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15)) ^ rotl(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; ++j) {
            W_prime[j] = W[j] ^ W[j + 4];
        }

        // Compression Rounds
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];
        uint32_t SS1, SS2, TT1, TT2;

        for (int j = 0; j < 64; ++j) {
            SS1 = rotl(rotl(A, 12) + E + rotl(T(j), j), 7);
            SS2 = SS1 ^ rotl(A, 12);
            TT1 = FF(j, A, B, C) + D + SS2 + W_prime[j];
            TT2 = GG(j, E, F, G) + H + SS1 + W[j];
            D = C;
            C = rotl(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotl(F, 19);
            F = E;
            E = P0(TT2);
        }

        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }
};
// Merkle树节点
struct MerkleNode {
    std::vector<uint8_t> hash;
    std::shared_ptr<MerkleNode> left;
    std::shared_ptr<MerkleNode> right;

    MerkleNode(const std::vector<uint8_t>& h) : hash(h), left(nullptr), right(nullptr) {}
};

// Merkle树类
class SM3MerkleTree {
public:
    SM3MerkleTree() : root(nullptr) {}

    // 构建Merkle树
    void buildTree(const std::vector<std::vector<uint8_t>>& leaves) {
        if (leaves.empty()) return;

        std::vector<std::shared_ptr<MerkleNode>> nodes;
        for (const auto& leaf : leaves) {
            nodes.push_back(std::make_shared<MerkleNode>(leaf));
        }

        while (nodes.size() > 1) {
            std::vector<std::shared_ptr<MerkleNode>> new_level;

            for (size_t i = 0; i < nodes.size(); i += 2) {
                auto left = nodes[i];
                auto right = (i + 1 < nodes.size()) ? nodes[i + 1] : nodes[i]; // 奇数个节点时复制最后一个

                std::vector<uint8_t> combined(left->hash);
                combined.insert(combined.end(), right->hash.begin(), right->hash.end());

                std::vector<uint8_t> parent_hash(32);
                SM3 sm3;
                sm3.update(combined.data(), combined.size());
                sm3.final(parent_hash.data());

                auto parent = std::make_shared<MerkleNode>(parent_hash);
                parent->left = left;
                parent->right = right;

                new_level.push_back(parent);
            }

            nodes = new_level;
        }

        root = nodes[0];
        leaf_hashes = leaves;
    }

    // 获取根哈希
    std::vector<uint8_t> getRootHash() const {
        return root ? root->hash : std::vector<uint8_t>(32, 0);
    }

    // 存在性证明
    struct ProofStep {
        std::vector<uint8_t> hash;
        bool is_left; // 指示兄弟节点是在左边还是右边
    };

    std::vector<ProofStep> getInclusionProof(size_t index) const {
        std::vector<ProofStep> proof;

        if (index >= leaf_hashes.size()) return proof;

        size_t tree_size = leaf_hashes.size();
        size_t idx = index;
        std::shared_ptr<MerkleNode> node = root;

        // 从根到叶子的路径
        std::vector<std::shared_ptr<MerkleNode>> path;
        buildPath(node, idx, tree_size, path);

        // 反向遍历路径构建证明
        for (size_t i = path.size() - 1; i > 0; --i) {
            auto current = path[i];
            auto parent = path[i - 1];

            if (parent->left == current) {
                // 当前节点是左子节点，需要右兄弟的哈希
                proof.push_back({ parent->right->hash, false });
            }
            else {
                // 当前节点是右子节点，需要左兄弟的哈希
                proof.push_back({ parent->left->hash, true });
            }
        }

        return proof;
    }

    // 验证存在性证明
    static bool verifyInclusionProof(
        const std::vector<uint8_t>& leaf_hash,
        const std::vector<uint8_t>& root_hash,
        const std::vector<ProofStep>& proof,
        size_t index,
        size_t tree_size) {

        std::vector<uint8_t> computed_hash = leaf_hash;

        for (const auto& step : proof) {
            std::vector<uint8_t> combined;

            if (step.is_left) {
                combined.insert(combined.end(), step.hash.begin(), step.hash.end());
                combined.insert(combined.end(), computed_hash.begin(), computed_hash.end());
            }
            else {
                combined.insert(combined.end(), computed_hash.begin(), computed_hash.end());
                combined.insert(combined.end(), step.hash.begin(), step.hash.end());
            }

            SM3 sm3;
            sm3.update(combined.data(), combined.size());
            sm3.final(computed_hash.data());
        }

        return computed_hash == root_hash;
    }

    // 不存在性证明
    struct NonInclusionProof {
        std::vector<ProofStep> proof;
        std::vector<uint8_t> left_leaf;  // 小于目标哈希的最大叶子
        std::vector<uint8_t> right_leaf; // 大于目标哈希的最小叶子
    };

    NonInclusionProof getNonInclusionProof(const std::vector<uint8_t>& target_hash) const {
        NonInclusionProof result;

        // 查找目标哈希应该插入的位置
        auto it = std::lower_bound(leaf_hashes.begin(), leaf_hashes.end(), target_hash);
        size_t pos = it - leaf_hashes.begin();

        if (pos > 0) {
            result.left_leaf = leaf_hashes[pos - 1];
            result.proof = getInclusionProof(pos - 1);
        }

        if (pos < leaf_hashes.size()) {
            result.right_leaf = leaf_hashes[pos];
            auto right_proof = getInclusionProof(pos);

            // 合并两个证明
            if (result.proof.empty()) {
                result.proof = right_proof;
            }
            else {
                // 取两个证明的共同部分
                size_t common_length = std::min(result.proof.size(), right_proof.size());
                for (size_t i = 0; i < common_length; ++i) {
                    if (result.proof[i].hash != right_proof[i].hash) {
                        result.proof.resize(i);
                        break;
                    }
                }
            }
        }

        return result;
    }

    // 验证不存在性证明
    static bool verifyNonInclusionProof(
        const std::vector<uint8_t>& target_hash,
        const std::vector<uint8_t>& root_hash,
        const NonInclusionProof& proof) {

        // 验证左叶子确实小于目标哈希
        if (!proof.left_leaf.empty() && proof.left_leaf >= target_hash) {
            return false;
        }

        // 验证右叶子确实大于目标哈希
        if (!proof.right_leaf.empty() && proof.right_leaf <= target_hash) {
            return false;
        }

        // 验证左叶子的存在性证明
        if (!proof.left_leaf.empty()) {
            if (!verifyInclusionProof(proof.left_leaf, root_hash, proof.proof, 0, 0)) {
                return false;
            }
        }

        // 验证右叶子的存在性证明
        if (!proof.right_leaf.empty()) {
            if (!verifyInclusionProof(proof.right_leaf, root_hash, proof.proof, 0, 0)) {
                return false;
            }
        }

        return true;
    }

private:
    std::shared_ptr<MerkleNode> root;
    std::vector<std::vector<uint8_t>> leaf_hashes;

    // 递归构建路径
    void buildPath(std::shared_ptr<MerkleNode> node, size_t& index, size_t tree_size,
        std::vector<std::shared_ptr<MerkleNode>>& path) const {
        path.push_back(node);

        if (!node->left && !node->right) return;

        size_t left_size = tree_size / 2;
        if (tree_size % 2 != 0) left_size++;

        if (index < left_size) {
            buildPath(node->left, index, left_size, path);
        }
        else {
            index -= left_size;
            buildPath(node->right, index, tree_size - left_size, path);
        }
    }
};

// 辅助函数：将十六进制字符串转换为字节数组
std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// 辅助函数：打印字节数组为十六进制字符串
void printHex(const std::vector<uint8_t>& bytes) {
    for (uint8_t b : bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
}

// 测试函数
void testMerkleTree() {
    // 生成10万个叶子节点
    const size_t num_leaves = 100000;
    std::vector<std::vector<uint8_t>> leaves;

    std::cout << "生成 " << num_leaves << " 个叶子节点..." << std::endl;
    for (size_t i = 0; i < num_leaves; ++i) {
        std::string data = "Leaf " + std::to_string(i);
        std::vector<uint8_t> leaf(data.begin(), data.end());

        // 计算SM3哈希作为叶子节点的值
        std::vector<uint8_t> hash(32);
        SM3 sm3;
        sm3.update(leaf.data(), leaf.size());
        sm3.final(hash.data());

        leaves.push_back(hash);
    }

    // 按哈希值排序叶子节点 (RFC6962要求排序的Merkle树)
    std::sort(leaves.begin(), leaves.end());

    // 构建Merkle树
    std::cout << "构建Merkle树..." << std::endl;
    SM3MerkleTree tree;
    tree.buildTree(leaves);

    // 获取根哈希
    auto root_hash = tree.getRootHash();
    std::cout << "根哈希: ";
    printHex(root_hash);

    // 测试存在性证明
    size_t test_index = 12345;
    std::cout << "\n测试存在性证明，索引 " << test_index << "..." << std::endl;
    auto inclusion_proof = tree.getInclusionProof(test_index);
    bool verified = SM3MerkleTree::verifyInclusionProof(
        leaves[test_index], root_hash, inclusion_proof, test_index, leaves.size());

    std::cout << "验证结果: " << (verified ? "成功" : "失败") << std::endl;

    // 测试不存在性证明
    std::vector<uint8_t> non_existing_hash(32, 0xAA); // 创建一个不存在的哈希
    std::cout << "\n测试不存在性证明..." << std::endl;
    auto non_inclusion_proof = tree.getNonInclusionProof(non_existing_hash);
    bool non_inclusion_verified = SM3MerkleTree::verifyNonInclusionProof(
        non_existing_hash, root_hash, non_inclusion_proof);

    std::cout << "验证结果: " << (non_inclusion_verified ? "成功" : "失败") << std::endl;
}

int main() {
    testMerkleTree();
    return 0;
}