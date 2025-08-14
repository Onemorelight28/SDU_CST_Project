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

private:
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

void testAndBenchmark(const std::string& input_str, int iterations) {
    SM3 sm3;
    uint8_t hash[32];
    const std::vector<uint8_t> input_data(input_str.begin(), input_str.end());

    std::cout << "--- 测试开始 ---" << std::endl;
    std::cout << "输入长度: " << input_data.size() << " 字节" << std::endl;
    std::cout << "迭代次数: " << iterations << std::endl;

    // correctness check
    sm3.init();
    sm3.update(input_data.data(), input_data.size());
    sm3.final(hash);
    std::cout << "哈希结果: " << bytesToHexString(hash, 32) << std::endl;

    // benchmark
    auto start_time = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        sm3.init();
        sm3.update(input_data.data(), input_data.size());
        sm3.final(hash);
    }
    auto end_time = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> elapsed_ms = end_time - start_time;
    double time_per_op = elapsed_ms.count() / iterations;

    std::cout << std::fixed << std::setprecision(9);
    std::cout << "平均每次哈希耗时: " << time_per_op << " ms (" << time_per_op * 1000000 << " ns)" << std::endl;
    std::cout << "--- 测试结束 ---\n" << std::endl;
}

int main() {
    // 官方标准样例
    std::string test_case_1 = "abc";
    testAndBenchmark(test_case_1, 1000);

    // 较长输入样例 (1KB)
    std::string test_case_3(1024, 'x');
    testAndBenchmark(test_case_3, 1000);

    // 更长输入样例 (1MB)
    std::string test_case_4(1024 * 1024, 'y');
    testAndBenchmark(test_case_4, 50);
    return 0;
}