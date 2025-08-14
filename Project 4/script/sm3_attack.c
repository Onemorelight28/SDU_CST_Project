#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <chrono>
#include <sstream>  // 添加缺少的头文件

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

void testLengthExtensionAttack() {
    std::cout << "=== 长度扩展攻击验证 ===" << std::endl;

    // 原始消息和哈希
    std::string original_msg = "secret_data";
    uint8_t original_hash[32];
    SM3 sm3_original;
    sm3_original.update(reinterpret_cast<const uint8_t*>(original_msg.data()), original_msg.size());
    sm3_original.final(original_hash);
    std::cout << "原始消息: \"" << original_msg << "\"" << std::endl;
    std::cout << "原始哈希: " << bytesToHexString(original_hash, 32) << std::endl;

    // 攻击者知道 original_hash 和 original_msg.length()，但不知道 original_msg
    // 尝试构造 extended_msg = original_msg || padding || extension
    std::string extension = "malicious_extension";

    // 方法1: 直接计算 extended_msg 的真实哈希
    // 构造正确的填充 (需要知道原始消息长度)
    size_t original_bit_len = original_msg.size() * 8;
    size_t padding_len = (56 - (original_msg.size() % 64 + 1)) % 64;
    if (padding_len < 0) padding_len += 64;

    std::vector<uint8_t> extended_data;
    extended_data.insert(extended_data.end(), original_msg.begin(), original_msg.end());
    extended_data.push_back(0x80);
    extended_data.insert(extended_data.end(), padding_len, 0x00);

    // 添加原始长度 (64位大端)
    uint64_t bit_len = original_bit_len;
    for (int i = 0; i < 8; ++i) {
        extended_data.push_back((bit_len >> (56 - 8 * i)) & 0xFF);
    }

    // 添加扩展数据
    extended_data.insert(extended_data.end(), extension.begin(), extension.end());

    // 计算真实哈希
    uint8_t real_extended_hash[32];
    SM3 sm3_real;
    sm3_real.update(extended_data.data(), extended_data.size());
    sm3_real.final(real_extended_hash);
    std::cout << "真实扩展哈希: " << bytesToHexString(real_extended_hash, 32) << std::endl;

    // 方法2: 尝试长度扩展攻击 (修正版)
    SM3 sm3_extended;

    // 1. 手动设置初始状态 (从原始哈希恢复)
    for (int i = 0; i < 8; ++i) {
        sm3_extended.state[i] =
            (uint32_t)(original_hash[i * 4]) << 24 |
            (uint32_t)(original_hash[i * 4 + 1]) << 16 |
            (uint32_t)(original_hash[i * 4 + 2]) << 8 |
            (uint32_t)(original_hash[i * 4 + 3]);
    }

    // 2. 计算原始消息+填充的总长度
    // 这个长度是哈希函数为了生成 original_hash 所处理过的总字节数。
    // original_msg(11) + 0x80(1) + padding_zeros(44) + length(8) = 64 bytes
    size_t original_len_with_padding = (original_msg.size() < 56) ? 64 : 128;
    // 更通用的计算
    size_t padding_len_calc = (56 - (original_msg.size() % 64 + 1) + 64) % 64;
    size_t forged_message_len = original_msg.size() + 1 + padding_len_calc + 8;


    // 3. 设置哈希对象的初始长度为“已处理”的数据长度
    sm3_extended.total_len = forged_message_len;
    sm3_extended.buffer_len = 0; // 我们从一个完整的块边界开始

    // 4. 只处理扩展部分, update函数会正确地将 extension.size() 加到 total_len 上
    sm3_extended.update(reinterpret_cast<const uint8_t*>(extension.data()), extension.size());

    uint8_t extended_hash[32];
    sm3_extended.final(extended_hash); // final()现在会使用正确的总长度 (forged_message_len + extension.size())

    std::cout << "修正后扩展攻击哈希: " << bytesToHexString(extended_hash, 32) << std::endl;

    // 比较结果
    bool is_vulnerable = true;
    for (int i = 0; i < 32; ++i) {
        if (real_extended_hash[i] != extended_hash[i]) {
            is_vulnerable = false;
            break;
        }
    }

    if (is_vulnerable) {
        std::cout << "结果: SM3 长度扩展攻击成功!" << std::endl;
    }
    else {
        std::cout << "结果: SM3 长度扩展攻击失败!" << std::endl;
    }

    std::cout << "=== 验证结束 ===\n" << std::endl;
}

int main() {

    // 长度扩展攻击验证
    testLengthExtensionAttack();

    return 0;
}