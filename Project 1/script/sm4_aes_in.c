#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <wmmintrin.h> // AES-NI 指令集头文件

// AES-NI 宏定义
#define SM4_AESNI_ROUND(block, rkey) \
    block = _mm_aesenc_si128(block, rkey)

// 替代mm_rotl_epi32的自定义实现
static inline __m128i mm_rotl_epi32(__m128i a, int shift) {
	return _mm_or_si128(
		_mm_slli_epi32(a, shift),
		_mm_srli_epi32(a, 32 - shift)
	);
}
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

// 使用AES-NI指令实现的SM4 S盒变换
static inline __m128i sm4_aesni_sbox(__m128i x) {
	// SM4 S盒可以通过AES S盒的两次应用来近似实现
	x = _mm_aesenc_si128(x, _mm_setzero_si128());
	return _mm_aesenc_si128(x, _mm_setzero_si128());
}

// AES-NI 优化的轮函数
static inline __m128i sm4_aesni_round(__m128i block, __m128i rkey) {
	__m128i temp = _mm_xor_si128(block, rkey);
	temp = sm4_aesni_sbox(temp);
	// 线性变换L
	temp = _mm_xor_si128(temp, mm_rotl_epi32(temp, 2));
	temp = _mm_xor_si128(temp, mm_rotl_epi32(temp, 10));
	temp = _mm_xor_si128(temp, mm_rotl_epi32(temp, 18));
	temp = _mm_xor_si128(temp, mm_rotl_epi32(temp, 24));
	return temp;
}

void SM4_KeySchedule_AESNI(const uint8_t MK[16], uint32_t rk[32]) {
	__m128i K[4];

	// 加载主密钥
	K[0] = _mm_loadu_si128((const __m128i*)MK);

	// 预处理（与标准实现相同）
	K[0] = _mm_xor_si128(K[0], _mm_set_epi32(FK[0], FK[1], FK[2], FK[3]));

	// 生成轮密钥
	for (int i = 0; i < 32; i++) {
		__m128i temp = _mm_xor_si128(K[1], _mm_xor_si128(K[2], K[3]));
		temp = _mm_xor_si128(temp, _mm_set1_epi32(CK[i]));

		// 使用AES-NI加速T'变换
		temp = sm4_aesni_sbox(temp);
		temp = _mm_xor_si128(temp, mm_rotl_epi32(temp, 13));
		temp = _mm_xor_si128(temp, mm_rotl_epi32(temp, 23));

		rk[i] = _mm_extract_epi32(_mm_xor_si128(K[0], temp), 0);

		// 更新K寄存器
		K[0] = K[1];
		K[1] = K[2];
		K[2] = K[3];
		K[3] = _mm_set1_epi32(rk[i]);
	}
}

void SM4_Encrypt_AESNI(const uint8_t plaintext[16], const uint32_t rk[32], uint8_t ciphertext[16]) {
	__m128i block = _mm_loadu_si128((const __m128i*)plaintext);

	// 转换为AES-NI可用的轮密钥格式
	__m128i round_keys[32];
	for (int i = 0; i < 32; i++) {
		round_keys[i] = _mm_set1_epi32(rk[i]);
	}

	// 32轮迭代
	for (int i = 0; i < 32; i++) {
		block = sm4_aesni_round(block, round_keys[i]);
	}

	// 反序存储
	block = _mm_shuffle_epi32(block, _MM_SHUFFLE(0, 1, 2, 3));
	_mm_storeu_si128((__m128i*)ciphertext, block);
}


// AES-NI优化的SM4解密函数
void SM4_Decrypt_AESNI(const uint8_t ciphertext[16],
	const uint32_t rk[32],
	uint8_t plaintext[16]) {
	// 加载密文
	__m128i block = _mm_loadu_si128((const __m128i*)ciphertext);

	// 转换为AES-NI可用的轮密钥格式（逆序）
	__m128i round_keys[32];
	for (int i = 0; i < 32; i++) {
		round_keys[i] = _mm_set1_epi32(rk[31 - i]); // 注意这里是31-i
	}

	// 32轮迭代
	for (int i = 0; i < 32; i++) {
		__m128i temp = _mm_xor_si128(block, round_keys[i]);

		// 双AES-NI实现S盒近似
		temp = _mm_aesenc_si128(temp, _mm_setzero_si128());
		temp = _mm_aesenc_si128(temp, _mm_setzero_si128());

		// 线性变换L
		temp = _mm_xor_si128(temp, mm_rotl_epi32(temp, 2));
		temp = _mm_xor_si128(temp, mm_rotl_epi32(temp, 10));
		temp = _mm_xor_si128(temp, mm_rotl_epi32(temp, 18));
		temp = _mm_xor_si128(temp, mm_rotl_epi32(temp, 24));

		// 更新状态
		block = temp;
	}

	// 反序存储结果
	block = _mm_shuffle_epi32(block, _MM_SHUFFLE(0, 1, 2, 3));
	_mm_storeu_si128((__m128i*)plaintext, block);
}

// 辅助函数: 打印16字节的数组
void print_hex(const char* label, const uint8_t arr[16]) {
	printf("%s: ", label);
	for (int i = 0; i < 16; i++) {
		printf("%02x", arr[i]);
	}
	printf("\n");
}

// --- 正确性测试 ---
void correctness_test() {
	// 使用国标示例1作为测试样例
	const uint8_t sample_key[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
	};
	const uint8_t sample_plaintext[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
	};
	const uint8_t expected_ciphertext[16] = {
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
	};

	uint32_t round_keys[32];
	uint8_t output[16];

	// --- 正确性验证 ---
	printf("--- Correctness Verification ---\n");
	print_hex("Plaintext ", sample_plaintext);
	print_hex("Key       ", sample_key);

	SM4_KeySchedule_AESNI(sample_key, round_keys);
	SM4_Encrypt_AESNI(sample_plaintext, round_keys, output);

	print_hex("Ciphertext", output);
	print_hex("Expected  ", expected_ciphertext);

	if (memcmp(output, expected_ciphertext, 16) == 0) {
		printf("Verification PASSED!\n\n");
	}
	else {
		printf("Verification FAILED!\n\n");
	}
}

// --- 性能测试 ---
void performance_test() {
	printf("\n--- Performance Test ---\n");
	const int NUM_TESTS = 1000000; // 执行一百万次测试
	uint8_t plaintext[16], ciphertext[16], decrypted[16];
	uint8_t key[16];
	uint32_t round_keys[32];

	// 初始化随机数生成器
	srand(time(NULL));

	// 1. 密钥扩展性能测试
	printf("\n[Key Schedule Performance]\n");
	clock_t key_start = clock();

	for (int i = 0; i < NUM_TESTS; i++) {
		// 生成随机密钥
		for (int j = 0; j < 16; j++) {
			key[j] = rand() % 256;
		}
		SM4_KeySchedule_AESNI(key, round_keys);
	}

	clock_t key_end = clock();
	double key_time = (double)(key_end - key_start) / CLOCKS_PER_SEC;
	printf("Total key schedules : %d\n", NUM_TESTS);
	printf("Total time spent   : %.3f seconds\n", key_time);
	printf("Time per operation : %.3f microseconds\n\n", key_time / NUM_TESTS * 1e6);

	// 2. 加密性能测试 (使用固定密钥)
	printf("[Encryption Performance]\n");
	SM4_KeySchedule_AESNI(key, round_keys); // 使用最后一次生成的密钥

	clock_t enc_start = clock();

	for (int i = 0; i < NUM_TESTS; i++) {
		// 生成随机明文
		for (int j = 0; j < 16; j++) {
			plaintext[j] = rand() % 256;
		}
		SM4_Encrypt_AESNI(plaintext, round_keys, ciphertext);
	}

	clock_t enc_end = clock();
	double enc_time = (double)(enc_end - enc_start) / CLOCKS_PER_SEC;
	printf("Total encryptions  : %d\n", NUM_TESTS);
	printf("Total time spent   : %.3f seconds\n", enc_time);
	printf("Time per encryption: %.3f microseconds\n\n", enc_time / NUM_TESTS * 1e6);

	// 3. 解密性能测试 (需要先实现SM4_Decrypt函数)
	printf("[Decryption Performance]\n");
	// 生成一轮测试数据
	for (int j = 0; j < 16; j++) {
		plaintext[j] = rand() % 256;
	}
	SM4_Encrypt_AESNI(plaintext, round_keys, ciphertext);

	clock_t dec_start = clock();

	for (int i = 0; i < NUM_TESTS; i++) {
		SM4_Decrypt_AESNI(ciphertext, round_keys, decrypted);
	}

	clock_t dec_end = clock();
	double dec_time = (double)(dec_end - dec_start) / CLOCKS_PER_SEC;
	printf("Total decryptions  : %d\n", NUM_TESTS);
	printf("Total time spent   : %.3f seconds\n", dec_time);
	printf("Time per decryption: %.3f microseconds\n", dec_time / NUM_TESTS * 1e6);

	// 验证解密正确性
	if (memcmp(plaintext, decrypted, 16) == 0) {
		printf("Decryption verification: PASSED\n");
	}
	else {
		printf("Decryption verification: FAILED\n");
	}
}

int main() {

	// --- 正确性测试 ---
	correctness_test();

	// --- 性能测试 ---
	performance_test();

	return 0;
}