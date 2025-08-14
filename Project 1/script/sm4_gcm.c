#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <wmmintrin.h>  // AES-NI
#include <emmintrin.h>  // SSE2
#include <smmintrin.h>  // SSE4.1
#include <immintrin.h>  // AVX/PCLMULQDQ

// 字节序转换辅助函数
static inline uint32_t bswap_32(uint32_t x) {
#if defined(_MSC_VER)
    return bswap_32(x);
#elif defined(__GNUC__)
    return __builtin_bswap32(x);
#else
    return ((x & 0xFF000000) >> 24) |
        ((x & 0x00FF0000) >> 8) |
        ((x & 0x0000FF00) << 8) |
        ((x & 0x000000FF) << 24);
#endif
}

static inline uint64_t bswap_64(uint64_t x) {
#if defined(_MSC_VER)
    return bswap_64(x);
#elif defined(__GNUC__)
    return __builtin_bswap64(x);
#else
    return ((x & 0xFF00000000000000ULL) >> 56) |
        ((x & 0x00FF000000000000ULL) >> 40) |
        ((x & 0x0000FF0000000000ULL) >> 24) |
        ((x & 0x000000FF00000000ULL) >> 8) |
        ((x & 0x00000000FF000000ULL) << 8) |
        ((x & 0x0000000000FF0000ULL) << 24) |
        ((x & 0x000000000000FF00ULL) << 40) |
        ((x & 0x00000000000000FFULL) << 56);
#endif
}
// 定义32位循环左移操作
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM4 S-box
static const uint8_t Sbox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// 密钥扩展中的系统参数 FK
static const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

// 密钥扩展中的固定参数 CK
static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// 辅助函数: 字节数组转32位无符号整数 (大端)
static uint32_t bytes_to_u32(const uint8_t* bytes) {
    return ((uint32_t)bytes[0] << 24) |
        ((uint32_t)bytes[1] << 16) |
        ((uint32_t)bytes[2] << 8) |
        (uint32_t)bytes[3];
}

// 辅助函数: 32位无符号整数转字节数组 (大端)
static void u32_to_bytes(uint32_t word, uint8_t* bytes) {
    bytes[0] = (word >> 24) & 0xFF;
    bytes[1] = (word >> 16) & 0xFF;
    bytes[2] = (word >> 8) & 0xFF;
    bytes[3] = word & 0xFF;
}

// 线性变换 L(B) = B xor rotl(B, 2) xor rotl(B, 10) xor rotl(B, 18) xor rotl(B, 24)
static uint32_t L_transform(uint32_t B) {
    return B ^ ROTL32(B, 2) ^ ROTL32(B, 10) ^ ROTL32(B, 18) ^ ROTL32(B, 24);
}

// 密钥扩展中的线性变换 L'
static uint32_t L_transform_key(uint32_t B) {
    return B ^ ROTL32(B, 13) ^ ROTL32(B, 23);
}

// 非线性变换 tau(A)
static uint32_t T_transform(uint32_t A) {
    uint8_t bytes[4];
    u32_to_bytes(A, bytes);
    bytes[0] = Sbox[bytes[0]];
    bytes[1] = Sbox[bytes[1]];
    bytes[2] = Sbox[bytes[2]];
    bytes[3] = Sbox[bytes[3]];
    return bytes_to_u32(bytes);
}

// 轮函数 F(X0, X1, X2, X3, rk)
static uint32_t F_round(uint32_t X0, uint32_t X1, uint32_t X2, uint32_t X3, uint32_t rk) {
    return X0 ^ L_transform(T_transform(X1 ^ X2 ^ X3 ^ rk));
}

// 密钥扩展算法
void SM4_KeySchedule(const uint8_t MK[16], uint32_t rk[32]) {
    uint32_t K[4];
    int i;

    // 将128位主密钥分为4个32位字
    K[0] = bytes_to_u32(MK);
    K[1] = bytes_to_u32(MK + 4);
    K[2] = bytes_to_u32(MK + 8);
    K[3] = bytes_to_u32(MK + 12);

    // 预处理K[i]
    K[0] ^= FK[0];
    K[1] ^= FK[1];
    K[2] ^= FK[2];
    K[3] ^= FK[3];

    // 生成32轮的轮密钥
    for (i = 0; i < 32; i++) {
        uint32_t temp = K[1] ^ K[2] ^ K[3] ^ CK[i];
        uint32_t B = T_transform(temp);
        rk[i] = K[0] ^ L_transform_key(B);

        // 更新K寄存器
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = rk[i];
    }
}

// SM4 加密函数
void SM4_Encrypt(const uint8_t plaintext[16], const uint32_t rk[32], uint8_t ciphertext[16]) {
    uint32_t X[4];
    int i;

    // 将128位明文分为4个32位字
    X[0] = bytes_to_u32(plaintext);
    X[1] = bytes_to_u32(plaintext + 4);
    X[2] = bytes_to_u32(plaintext + 8);
    X[3] = bytes_to_u32(plaintext + 12);

    // 32轮迭代
    for (i = 0; i < 32; i++) {
        uint32_t next_X = F_round(X[0], X[1], X[2], X[3], rk[i]);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = next_X;
    }

    // 反序变换
    u32_to_bytes(X[3], ciphertext);
    u32_to_bytes(X[2], ciphertext + 4);
    u32_to_bytes(X[1], ciphertext + 8);
    u32_to_bytes(X[0], ciphertext + 12);
}

// SM4 解密函数
void SM4_Decrypt(const uint8_t ciphertext[16], const uint32_t rk[32], uint8_t plaintext[16]) {
    uint32_t X[4];
    int i;

    // 将128位密文分为4个32位字
    X[0] = bytes_to_u32(ciphertext);
    X[1] = bytes_to_u32(ciphertext + 4);
    X[2] = bytes_to_u32(ciphertext + 8);
    X[3] = bytes_to_u32(ciphertext + 12);

    // 32轮迭代（轮密钥逆序使用）
    for (i = 0; i < 32; i++) {
        uint32_t next_X = F_round(X[0], X[1], X[2], X[3], rk[31 - i]);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = next_X;
    }

    // 反序变换
    u32_to_bytes(X[3], plaintext);
    u32_to_bytes(X[2], plaintext + 4);
    u32_to_bytes(X[1], plaintext + 8);
    u32_to_bytes(X[0], plaintext + 12);
}

// 辅助函数: 打印16字节的数组
void print_hex(const char* label, const uint8_t arr[16]) {
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02x", arr[i]);
    }
    printf("\n");
}


// GCM相关定义
#define GCM_BLOCK_SIZE 16
#define GCM_IV_SIZE    12
#define GCM_TAG_SIZE   16

// GCM上下文结构
typedef struct {
    __m128i H;          // 哈希子密钥
    __m128i X;          // GHASH状态
    uint64_t len_aad;   // AAD长度（字节）
    uint64_t len_ct;    // 密文长度（字节）
    uint8_t  iv[GCM_IV_SIZE];
    uint32_t rk[32];    // SM4轮密钥
} sm4_gcm_ctx;

// 使用PCLMULQDQ优化的GF(2^128)乘法
static inline __m128i gfmul(__m128i a, __m128i b) {
    __m128i tmp0, tmp1, tmp2, tmp3;

    // Karatsuba方法分解乘法
    tmp0 = _mm_clmulepi64_si128(a, b, 0x00); // a0*b0
    tmp1 = _mm_clmulepi64_si128(a, b, 0x10); // a0*b1
    tmp2 = _mm_clmulepi64_si128(a, b, 0x01); // a1*b0
    tmp3 = _mm_clmulepi64_si128(a, b, 0x11); // a1*b1

    // 合并结果
    tmp1 = _mm_xor_si128(tmp1, tmp2);      // a0*b1 + a1*b0
    tmp2 = _mm_slli_si128(tmp1, 8);        // 左移64位
    tmp1 = _mm_srli_si128(tmp1, 8);        // 右移64位
    tmp0 = _mm_xor_si128(tmp0, tmp2);      // a0*b0 + (a0*b1 << 64)
    tmp3 = _mm_xor_si128(tmp3, tmp1);      // a1*b1 + (a0*b1 >> 64)

    // 模约简 (GCM多项式 x^128 + x^7 + x^2 + x + 1)
    __m128i tmp4 = _mm_clmulepi64_si128(tmp0, _mm_set_epi32(0, 0, 0, 0x87), 0x01);
    tmp0 = _mm_xor_si128(tmp0, _mm_slli_si128(tmp4, 8));
    tmp3 = _mm_xor_si128(tmp3, _mm_srli_si128(tmp4, 8));

    tmp4 = _mm_clmulepi64_si128(tmp0, _mm_set_epi32(0, 0, 0, 0x87), 0x00);
    tmp3 = _mm_xor_si128(tmp3, tmp4);

    return tmp3;
}

// 初始化SM4-GCM上下文
void sm4_gcm_init(sm4_gcm_ctx* ctx, const uint8_t* key, const uint8_t* iv, size_t iv_len) {
    memset(ctx, 0, sizeof(sm4_gcm_ctx));

    // 生成SM4轮密钥
    SM4_KeySchedule(key, ctx->rk);

    // 计算H = SM4_Encrypt(0^128)
    uint8_t zero_block[GCM_BLOCK_SIZE] = { 0 };
    __m128i H;
    SM4_Encrypt(zero_block, ctx->rk, (uint8_t*)&H);
    ctx->H = H;

    // 初始化IV (处理不同长度)
    if (iv_len == GCM_IV_SIZE) {
        memcpy(ctx->iv, iv, GCM_IV_SIZE);
    }
    else {
        // 对于非12字节IV需要特殊处理（此处简化）
        memset(ctx->iv, 0, GCM_IV_SIZE);
        memcpy(ctx->iv, iv, iv_len < GCM_IV_SIZE ? iv_len : GCM_IV_SIZE);
    }

    // 初始化GHASH状态
    ctx->X = _mm_setzero_si128();
}

// 处理附加认证数据(AAD)
void sm4_gcm_aad(sm4_gcm_ctx* ctx, const uint8_t* aad, size_t len) {
    size_t blocks = len / GCM_BLOCK_SIZE;
    size_t rem = len % GCM_BLOCK_SIZE;

    for (size_t i = 0; i < blocks; i++) {
        __m128i block = _mm_loadu_si128((const __m128i*)(aad + i * GCM_BLOCK_SIZE));
        ctx->X = _mm_xor_si128(ctx->X, block);
        ctx->X = gfmul(ctx->X, ctx->H);
    }

    if (rem > 0) {
        uint8_t last_block[GCM_BLOCK_SIZE] = { 0 };
        memcpy(last_block, aad + blocks * GCM_BLOCK_SIZE, rem);
        __m128i block = _mm_loadu_si128((const __m128i*)last_block);
        ctx->X = _mm_xor_si128(ctx->X, block);
        ctx->X = gfmul(ctx->X, ctx->H);
    }

    ctx->len_aad += len;
}

// SM4-GCM加密/解密（CTR模式）
void sm4_gcm_crypt(sm4_gcm_ctx* ctx, const uint8_t* in, uint8_t* out, size_t len, int is_encrypt) {
    uint32_t ctr[4] = { 0 };
    memcpy(ctr, ctx->iv, GCM_IV_SIZE);
    ctr[3] = bswap_32(1);  // 初始计数器值

    uint8_t keystream[GCM_BLOCK_SIZE];
    size_t blocks = len / GCM_BLOCK_SIZE;
    size_t rem = len % GCM_BLOCK_SIZE;

    for (size_t i = 0; i < blocks; i++) {
        // 生成密钥流
        SM4_Encrypt((uint8_t*)ctr, ctx->rk, keystream);
        ctr[3] = bswap_32(bswap_32(ctr[3]) + 1);

        // CTR模式加密/解密
        __m128i in_block = _mm_loadu_si128((const __m128i*)(in + i * GCM_BLOCK_SIZE));
        __m128i ks_block = _mm_loadu_si128((const __m128i*)keystream);
        __m128i out_block = _mm_xor_si128(in_block, ks_block);
        _mm_storeu_si128((__m128i*)(out + i * GCM_BLOCK_SIZE), out_block);

        // 更新GHASH（使用密文）
        if (is_encrypt) {
            ctx->X = _mm_xor_si128(ctx->X, out_block);
        }
        else {
            ctx->X = _mm_xor_si128(ctx->X, in_block);
        }
        ctx->X = gfmul(ctx->X, ctx->H);
    }

    // 处理剩余部分
    if (rem > 0) {
        SM4_Encrypt((uint8_t*)ctr, ctx->rk, keystream);
        for (size_t i = 0; i < rem; i++) {
            out[blocks * GCM_BLOCK_SIZE + i] = in[blocks * GCM_BLOCK_SIZE + i] ^ keystream[i];
        }

        // 更新GHASH（填充0）
        uint8_t last_block[GCM_BLOCK_SIZE] = { 0 };
        if (is_encrypt) {
            memcpy(last_block, out + blocks * GCM_BLOCK_SIZE, rem);
        }
        else {
            memcpy(last_block, in + blocks * GCM_BLOCK_SIZE, rem);
        }
        __m128i block = _mm_loadu_si128((const __m128i*)last_block);
        ctx->X = _mm_xor_si128(ctx->X, block);
        ctx->X = gfmul(ctx->X, ctx->H);
    }

    ctx->len_ct += len;
}

// 生成认证标签
void sm4_gcm_tag(sm4_gcm_ctx* ctx, uint8_t* tag, size_t tag_len) {
    // 处理长度信息
    __m128i len_block = _mm_set_epi64x(
        bswap_64(ctx->len_aad * 8),
        bswap_64(ctx->len_ct * 8)
    );
    ctx->X = _mm_xor_si128(ctx->X, len_block);
    ctx->X = gfmul(ctx->X, ctx->H);

    // 加密初始计数器（J0）
    uint32_t j0[4] = { 0 };
    memcpy(j0, ctx->iv, GCM_IV_SIZE);
    j0[3] = bswap_32(1);

    uint8_t e_j0[GCM_BLOCK_SIZE];
    SM4_Encrypt((uint8_t*)j0, ctx->rk, e_j0);

    // 生成标签
    __m128i T = _mm_xor_si128(ctx->X, _mm_loadu_si128((const __m128i*)e_j0));

    // 截断到请求的长度
    size_t copy_len = tag_len < GCM_TAG_SIZE ? tag_len : GCM_TAG_SIZE;
    memcpy(tag, &T, copy_len);

    if (copy_len < tag_len) {
        memset(tag + copy_len, 0, tag_len - copy_len);
    }
}

int main() {
    uint8_t key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    uint8_t iv[12] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b };
    uint8_t aad[] = { 0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef };
    uint8_t plaintext[] = "Hello, this is SM4-GCM test message!";
    size_t pt_len = strlen((char*)plaintext);

    printf("=== SM4-GCM Performance Test ===\n");
    printf("Plaintext length: %zu bytes\n", pt_len);
    printf("AAD length: %zu bytes\n\n", sizeof(aad));

    // 加密测试
    printf("[Encryption Test]\n");
    sm4_gcm_ctx ctx;
    uint8_t ciphertext[64] = { 0 };
    uint8_t tag[16] = { 0 };

    clock_t start, end;

    // 初始化时间
    start = clock();
    sm4_gcm_init(&ctx, key, iv, sizeof(iv));
    end = clock();
    printf("Init time: %.3f ms\n", (double)(end - start) * 1000 / CLOCKS_PER_SEC);

    // AAD处理时间
    start = clock();
    sm4_gcm_aad(&ctx, aad, sizeof(aad));
    end = clock();
    printf("AAD time: %.3f ms\n", (double)(end - start) * 1000 / CLOCKS_PER_SEC);

    // 加密时间
    start = clock();
    sm4_gcm_crypt(&ctx, plaintext, ciphertext, pt_len, 1);
    end = clock();
    printf("Encrypt time: %.3f ms\n", (double)(end - start) * 1000 / CLOCKS_PER_SEC);

    // 标签生成时间
    start = clock();
    sm4_gcm_tag(&ctx, tag, sizeof(tag));
    end = clock();
    printf("Tag gen time: %.3f ms\n", (double)(end - start) * 1000 / CLOCKS_PER_SEC);

    printf("\nCiphertext: ");
    for (size_t i = 0; i < pt_len; i++) printf("%02x", ciphertext[i]);
    printf("\nTag: ");
    for (size_t i = 0; i < sizeof(tag); i++) printf("%02x", tag[i]);
    printf("\n\n");

    // 解密测试
    printf("[Decryption Test]\n");
    uint8_t decrypted[64] = { 0 };

    // 初始化时间
    start = clock();
    sm4_gcm_init(&ctx, key, iv, sizeof(iv));
    end = clock();
    printf("Init time: %.3f ms\n", (double)(end - start) * 1000 / CLOCKS_PER_SEC);

    // AAD处理时间
    start = clock();
    sm4_gcm_aad(&ctx, aad, sizeof(aad));
    end = clock();
    printf("AAD time: %.3f ms\n", (double)(end - start) * 1000 / CLOCKS_PER_SEC);

    // 解密时间
    start = clock();
    sm4_gcm_crypt(&ctx, ciphertext, decrypted, pt_len, 0);
    end = clock();
    printf("Decrypt time: %.3f ms\n", (double)(end - start) * 1000 / CLOCKS_PER_SEC);

    // 验证结果
    printf("\nDecrypted: %s\n", decrypted);
    if (memcmp(plaintext, decrypted, pt_len) == 0) {
        printf("Decryption verification: SUCCESS\n");
    }
    else {
        printf("Decryption verification: FAILED\n");
    }

    return 0;
}