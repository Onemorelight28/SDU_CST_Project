#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <chrono>
#include <sstream>
#include <immintrin.h>
#include <omp.h>
#include <cstring>

// 用于将字节数组转换为十六进制字符串以便打印
std::string bytesToHexString(const uint8_t* bytes, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return ss.str();
}

class OptimizedSM3 {
public:
    OptimizedSM3() {
        init();
    }

    void init() {
        _mm256_zeroall();  // 清除AVX寄存器
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

        // 处理缓冲区中已有的数据
        if (buffer_len > 0) {
            size_t to_fill = std::min(64 - buffer_len, len);
            memcpy(buffer + buffer_len, data, to_fill);
            buffer_len += to_fill;
            data += to_fill;
            len -= to_fill;

            if (buffer_len == 64) {
                compress_fast(buffer);
                buffer_len = 0;
            }
        }

        // 处理完整的64字节块
        size_t blocks = len / 64;
        if (blocks > 0) {
#ifdef _OPENMP
            if (blocks > 1024) {  // 大数据量使用并行
                parallel_compress(data, blocks * 64);
            }
            else {
                for (size_t i = 0; i < blocks; ++i) {
                    compress_fast(data + i * 64);
                }
            }
#else
            for (size_t i = 0; i < blocks; ++i) {
                compress_fast(data + i * 64);
            }
#endif
            data += blocks * 64;
            len -= blocks * 64;
        }

        // 存储剩余数据
        if (len > 0) {
            memcpy(buffer, data, len);
            buffer_len = len;
        }
    }

    void final(uint8_t hash[32]) {
        // Step 1: Padding
        buffer[buffer_len++] = 0x80;

        if (buffer_len > 56) {
            while (buffer_len < 64) {
                buffer[buffer_len++] = 0x00;
            }
            compress_fast(buffer);
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
        compress_fast(buffer);

        // Step 4: Output hash
        for (int i = 0; i < 8; ++i) {
            hash[i * 4 + 0] = (state[i] >> 24) & 0xFF;
            hash[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            hash[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            hash[i * 4 + 3] = state[i] & 0xFF;
        }
    }

private:
    alignas(64) uint32_t state[8];
    uint64_t total_len;
    size_t buffer_len;
    alignas(64) uint8_t buffer[64];

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

    // SIMD优化的P1函数
    static inline __m256i simd_p1(__m256i x) {
        __m256i rot15 = _mm256_or_si256(_mm256_slli_epi32(x, 15), _mm256_srli_epi32(x, 17));
        __m256i rot23 = _mm256_or_si256(_mm256_slli_epi32(x, 23), _mm256_srli_epi32(x, 9));
        return _mm256_xor_si256(_mm256_xor_si256(x, rot15), rot23);
    }

    // 修改后的 expand_message_avx2 函数
    void expand_message_avx2(const uint8_t block[64], uint32_t W[68]) {
        // big-endian 载入 W[0..15]
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<uint32_t>(block[4 * i + 0]) << 24) |
                (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
                (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
                (static_cast<uint32_t>(block[4 * i + 3]) << 0);
        }

        // W[16..67]
        for (int j = 16; j < 68; ++j) {
            uint32_t x = W[j - 16] ^ W[j - 9] ^ ((W[j - 3] << 15) | (W[j - 3] >> (32 - 15)));
            uint32_t p1 = x ^ ((x << 15) | (x >> (32 - 15))) ^ ((x << 23) | (x >> (32 - 23))); // P1(x)
            W[j] = p1 ^ ((W[j - 13] << 7) | (W[j - 13] >> (32 - 7))) ^ W[j - 6];
        }
    }

    // 使用SIMD优化的压缩函数
    void compress_fast(const uint8_t block[64]) {
        alignas(64) uint32_t W[68];
        alignas(64) uint32_t W_prime[64];

        // SIMD优化的消息扩展
        expand_message_avx2(block, W);

        // 计算W_prime
        for (int j = 0; j < 64; j += 8) {
            __m256i wj = _mm256_load_si256((__m256i*) & W[j]);
            __m256i wj4 = _mm256_load_si256((__m256i*) & W[j + 4]);
            __m256i w_prime = _mm256_xor_si256(wj, wj4);
            _mm256_store_si256((__m256i*) & W_prime[j], w_prime);
        }

        // 展开的压缩循环
        uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
        uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

        // 处理4轮迭代为一组，减少循环开销
        for (int j = 0; j < 64; j += 4) {
            // 预计算公共部分
            uint32_t T_j = T(j);
            uint32_t T_j1 = T(j + 1);
            uint32_t T_j2 = T(j + 2);
            uint32_t T_j3 = T(j + 3);

            // 第一轮 (j)
            uint32_t A_rot12 = rotl(A, 12);
            uint32_t SS1 = rotl(A_rot12 + E + rotl(T_j, j), 7);
            uint32_t SS2 = SS1 ^ A_rot12;
            uint32_t TT1 = FF(j, A, B, C) + D + SS2 + W_prime[j];
            uint32_t TT2 = GG(j, E, F, G) + H + SS1 + W[j];

            // 第二轮 (j+1)
            uint32_t A1_rot12 = rotl(TT1, 12);
            uint32_t SS1_1 = rotl(A1_rot12 + P0(TT2) + rotl(T_j1, j + 1), 7);
            uint32_t SS2_1 = SS1_1 ^ A1_rot12;
            uint32_t TT1_1 = FF(j + 1, TT1, A, B) + rotl(C, 9) + SS2_1 + W_prime[j + 1];
            uint32_t TT2_1 = GG(j + 1, P0(TT2), E, F) + rotl(G, 19) + SS1_1 + W[j + 1];

            // 第三轮 (j+2)
            uint32_t A2_rot12 = rotl(TT1_1, 12);
            uint32_t SS1_2 = rotl(A2_rot12 + P0(TT2_1) + rotl(T_j2, j + 2), 7);
            uint32_t SS2_2 = SS1_2 ^ A2_rot12;
            uint32_t TT1_2 = FF(j + 2, TT1_1, TT1, A) + rotl(rotl(B, 9), 9) + SS2_2 + W_prime[j + 2];
            uint32_t TT2_2 = GG(j + 2, P0(TT2_1), P0(TT2), E) + rotl(rotl(F, 19), 19) + SS1_2 + W[j + 2];

            // 第四轮 (j+3)
            uint32_t A3_rot12 = rotl(TT1_2, 12);
            uint32_t SS1_3 = rotl(A3_rot12 + P0(TT2_2) + rotl(T_j3, j + 3), 7);
            uint32_t SS2_3 = SS1_3 ^ A3_rot12;
            uint32_t TT1_3 = FF(j + 3, TT1_2, TT1_1, TT1) + rotl(rotl(A, 9), 9) + SS2_3 + W_prime[j + 3];
            uint32_t TT2_3 = GG(j + 3, P0(TT2_2), P0(TT2_1), P0(TT2)) + rotl(rotl(E, 19), 19) + SS1_3 + W[j + 3];

            // 更新状态变量
            D = rotl(rotl(B, 9), 9);
            C = rotl(rotl(A, 9), 9);
            B = TT1_2;
            A = TT1_3;

            H = rotl(rotl(F, 19), 19);
            G = rotl(rotl(E, 19), 19);
            F = P0(TT2_2);
            E = P0(TT2_3);
        }

        // 更新状态
        state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
        state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
    }

    // 并行压缩函数
    void parallel_compress(const uint8_t* data, size_t len) {
        const size_t block_size = 64;
        const size_t num_blocks = len / block_size;

        // 每个线程维护自己的局部状态
        std::vector<uint32_t[8]> thread_states(omp_get_max_threads());

#pragma omp parallel
        {
            int tid = omp_get_thread_num();
            memcpy(thread_states[tid], state, sizeof(state));

#pragma omp for schedule(static)
            for (size_t i = 0; i < num_blocks; ++i) {
                alignas(64) uint32_t local_state[8];
                memcpy(local_state, thread_states[tid], sizeof(local_state));

                // 使用局部状态进行压缩
                compress_block_with_state(data + i * block_size, local_state);

                memcpy(thread_states[tid], local_state, sizeof(local_state));
            }
        }

        // 合并所有线程的结果
        for (size_t i = 0; i < thread_states.size(); ++i) {
            for (int j = 0; j < 8; ++j) {
                state[j] ^= thread_states[i][j];
            }
        }
    }

    // 使用指定状态压缩单个块
    void compress_block_with_state(const uint8_t block[64], uint32_t local_state[8]) {
        alignas(64) uint32_t W[68];
        alignas(64) uint32_t W_prime[64];

        expand_message_avx2(block, W);

        for (int j = 0; j < 64; j += 8) {
            __m256i wj = _mm256_load_si256((__m256i*) & W[j]);
            __m256i wj4 = _mm256_load_si256((__m256i*) & W[j + 4]);
            __m256i w_prime = _mm256_xor_si256(wj, wj4);
            _mm256_store_si256((__m256i*) & W_prime[j], w_prime);
        }

        uint32_t A = local_state[0], B = local_state[1], C = local_state[2], D = local_state[3];
        uint32_t E = local_state[4], F = local_state[5], G = local_state[6], H = local_state[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = rotl(rotl(A, 12) + E + rotl(T(j), j), 7);
            uint32_t SS2 = SS1 ^ rotl(A, 12);
            uint32_t TT1 = FF(j, A, B, C) + D + SS2 + W_prime[j];
            uint32_t TT2 = GG(j, E, F, G) + H + SS1 + W[j];

            D = C;
            C = rotl(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotl(F, 19);
            F = E;
            E = P0(TT2);
        }

        local_state[0] ^= A; local_state[1] ^= B; local_state[2] ^= C; local_state[3] ^= D;
        local_state[4] ^= E; local_state[5] ^= F; local_state[6] ^= G; local_state[7] ^= H;
    }
};

void testAndBenchmark(const std::string& input_str, int iterations) {
    OptimizedSM3 sm3;
    uint8_t hash[32];
    const std::vector<uint8_t> input_data(input_str.begin(), input_str.end());

    std::cout << "--- 测试开始 ---" << std::endl;
    std::cout << "输入长度: " << input_data.size() << " 字节" << std::endl;
    std::cout << "迭代次数: " << iterations << std::endl;

    // 正确性检查
    sm3.init();
    sm3.update(input_data.data(), input_data.size());
    sm3.final(hash);
    std::cout << "哈希结果: " << bytesToHexString(hash, 32) << std::endl;

    // 性能测试
    auto start_time = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        sm3.init();
        sm3.update(input_data.data(), input_data.size());
        sm3.final(hash);
    }
    auto end_time = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> elapsed_ms = end_time - start_time;
    double time_per_op = elapsed_ms.count() / iterations;
    double speed = (input_data.size() * iterations) / (elapsed_ms.count() / 1000.0) / (1024 * 1024); // MB/s

    std::cout << std::fixed << std::setprecision(9);
    std::cout << "平均每次哈希耗时: " << time_per_op << " ms (" << time_per_op * 1000000 << " ns)" << std::endl;
    std::cout << "吞吐量: " << speed << " MB/s" << std::endl;
    std::cout << "--- 测试结束 ---\n" << std::endl;
}

int main() {
    // 设置OpenMP线程数
    omp_set_num_threads(omp_get_max_threads());

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