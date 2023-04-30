#include <AES.hpp>

#include <vector>
#include <functional>
#include <cassert>

uint8_t rc(size_t i) {
	constexpr std::array<uint8_t, 10> constants = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

	return constants[i - 1];
}

std::array<uint8_t, 4> rcon(size_t i) {
	return std::array<uint8_t, 4>{ rc(i), 0, 0, 0 };
}

std::array<uint8_t, 4> rotate(const std::array<uint8_t, 4>& word) {
	return std::array<uint8_t, 4>{ word[1], word[2], word[3], word[0] };
}

template<size_t N>
std::array<uint8_t, N> sbox(const std::array<uint8_t, N>& state) {
	constexpr std::array<uint8_t, 256> sbox_values = {
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
	};

	std::array<uint8_t, N> res;
	for (size_t i = 0; i < N; ++i) {
		res[i] = sbox_values[state[i]];
	}

	return res;
}

template<size_t N>
std::array<uint8_t, N> inv_sbox(const std::array<uint8_t, N>& state) {
	constexpr std::array<uint8_t, 256> sbox_inv_values = {
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
	};

	std::array<uint8_t, N> res;
	for (size_t i = 0; i < N; ++i) {
		res[i] = sbox_inv_values[state[i]];
	}

	return res;
}

std::array<uint8_t, 16> shift_row(const std::array<uint8_t, 16>& state) {
	// 0 4 8  12 => 0  4  8  12
	// 1 5 9  13    5  9  13 1
	// 2 6 10 14    10 14 2  6
	// 3 7 11 15    15 3  7  11

	std::array<uint8_t, 16> res;
	// Row 1
	res[0] = state[0];
	res[4] = state[4];
	res[8] = state[8];
	res[12] = state[12];

	// Row 2
	res[1] = state[5];
	res[5] = state[9];
	res[9] = state[13];
	res[13] = state[1];

	// Row 3
	res[2] = state[10];
	res[6] = state[14];
	res[10] = state[2];
	res[14] = state[6];

	// Row 4
	res[3] = state[15];
	res[7] = state[3];
	res[11] = state[7];
	res[15] = state[11];

	return res;
}

std::array<uint8_t, 16> inv_shift_row(const std::array<uint8_t, 16>& state) {
	// 0 4 8  12 <= 0  4  8  12
	// 1 5 9  13    5  9  13 1
	// 2 6 10 14    10 14 2  6
	// 3 7 11 15    15 3  7  11

	std::array<uint8_t, 16> res;
	// Row 1
	res[0] = state[0];
	res[4] = state[4];
	res[8] = state[8];
	res[12] = state[12];

	// Row 2
	res[5] = state[1];
	res[9] = state[5];
	res[13] = state[9];
	res[1] = state[13];

	// Row 3
	res[10] = state[2];
	res[14] = state[6];
	res[2] = state[10];
	res[6] = state[14];

	// Row 4
	res[15] = state[3];
	res[3] = state[7];
	res[7] = state[11];
	res[11] = state[15];

	return res;
}

// Product in Galois Field of 2^8
uint8_t gf2prod(uint8_t x, uint8_t y) {
	uint8_t ret = 0;
	for (size_t i = 0; i < 8; ++i) {
		if ((y & 1) != 0) {
			ret = ret ^ x;
		}
			
		uint8_t b = (x & 0x80);
		x = (x << 1) & 0xFF;
		if (b) {
			x = x ^ 0x1B;
		}		
		y = (y >> 1) & 0xFF;
	}

	return ret;
}

std::array<uint8_t, 16> mix_column(const std::array<uint8_t, 16>& state) {
	constexpr std::array<std::array<uint8_t, 4>, 4> coeffs = {
		std::array<uint8_t, 4>{ 0x02, 0x03, 0x01, 0x01 },
		std::array<uint8_t, 4>{ 0x01, 0x02, 0x03, 0x01 },
		std::array<uint8_t, 4>{ 0x01, 0x01, 0x02, 0x03 },
		std::array<uint8_t, 4>{ 0x03, 0x01, 0x01, 0x02 }
	};

	std::array<uint8_t, 16> res;
	for (size_t i = 0; i < 4; ++i) {
		for (size_t j = 0; j < 4; ++j) {
			res[i * 4 + j] = 
				gf2prod(state[i * 4 + 0], coeffs[j][0]) ^ 
				gf2prod(state[i * 4 + 1], coeffs[j][1]) ^
				gf2prod(state[i * 4 + 2], coeffs[j][2]) ^ 
				gf2prod(state[i * 4 + 3], coeffs[j][3]);
		}
	}

	return res;
}

std::array<uint8_t, 16> inv_mix_column(const std::array<uint8_t, 16>& state) {
	constexpr std::array<std::array<uint8_t, 4>, 4> coeffs = {
		std::array<uint8_t, 4>{ 0x0E, 0x0B, 0x0D, 0x09 },
		std::array<uint8_t, 4>{ 0x09, 0x0E, 0x0B, 0x0D },
		std::array<uint8_t, 4>{ 0x0D, 0x09, 0x0E, 0x0B },
		std::array<uint8_t, 4>{ 0x0B, 0x0D, 0x09, 0x0E }
	};

	std::array<uint8_t, 16> res;
	for (size_t i = 0; i < 4; ++i) {
		for (size_t j = 0; j < 4; ++j) {
			res[i * 4 + j] =
				gf2prod(state[i * 4 + 0], coeffs[j][0]) ^
				gf2prod(state[i * 4 + 1], coeffs[j][1]) ^
				gf2prod(state[i * 4 + 2], coeffs[j][2]) ^
				gf2prod(state[i * 4 + 3], coeffs[j][3]);
		}
	}

	return res;
}

template<size_t N>
std::array<uint8_t, N> arr_xor(const std::array<uint8_t, N>& lhs, const std::array<uint8_t, N>& rhs) {
	std::array<uint8_t, N> res;
	for (size_t i = 0; i < N; ++i) {
		res[i] = static_cast<unsigned char>(lhs[i] ^ rhs[i]);
	}

	return res;
}

std::array<uint8_t, 16> to_round_key(const std::vector<std::array<uint8_t, 4>>::const_iterator& it) {
	std::array<uint8_t, 16> round_key;
	for (size_t i = 0; i < 4; ++i) {
		round_key[i * 4 + 0] = (*(it + i))[0];
		round_key[i * 4 + 1] = (*(it + i))[1];
		round_key[i * 4 + 2] = (*(it + i))[2];
		round_key[i * 4 + 3] = (*(it + i))[3];
	}

	return round_key;
}

std::array<std::array<uint8_t, 16>, 15> key_expansion(const std::array<uint8_t, 32>& key) {
	constexpr size_t N = 8;
	constexpr size_t R = 15;

	std::vector<std::array<uint8_t, 4>> K = std::vector<std::array<uint8_t, 4>>(N);
	for (size_t i = 0; i < K.size(); ++i) {
		std::copy(key.begin() + 4 * i, key.begin() + 4 * (i + 1), K[i].begin());
	}

	std::vector<std::array<uint8_t, 4>> W = std::vector<std::array<uint8_t, 4>>(4 * R);
	for (size_t i = 0; i < W.size(); ++i) {
		if (i < N) {
			W[i] = K[i];
		}
		else if ((i >= N) && ((i % N) == 0)) {
			W[i] = arr_xor(W[i - N], arr_xor(sbox(rotate(W[i - 1])), rcon(i / N)));
		}
		else if ((i >= N) && (N > 6) && ((i % N) == 4)) {
			W[i] = arr_xor(W[i - N], sbox(W[i - 1]));
		}
		else {
			W[i] = arr_xor(W[i - N], W[i - 1]);
		}
	}

	std::array<std::array<uint8_t, 16>, 15> round_keys;
	for (size_t i = 0; i < round_keys.size(); ++i) {
		round_keys[i] = to_round_key(W.begin() + i * 4);
	}

	return round_keys;
}

std::array<uint8_t, 16> AES_block_encryption(const std::array<uint8_t, 16>& plaintext, const std::array<uint8_t, 32>& key) {
	constexpr size_t R = 15;

	std::array<std::array<uint8_t, 16>, 15> round_keys = key_expansion(key);

	std::array<uint8_t, 16> state = arr_xor(round_keys[0], plaintext);

	for (size_t i = 1; i < R; ++i) {
		state = sbox(state);

		state = shift_row(state);

		if (i != (R - 1)) {
			state = mix_column(state);
		}

		state = arr_xor(state, round_keys[i]);
	}

	return state;
}

std::array<uint8_t, 16> AES_block_decryption(const std::array<uint8_t, 16>& cyphertext, const std::array<uint8_t, 32>& key) {
	constexpr size_t R = 15;

	std::array<std::array<uint8_t, 16>, 15> round_keys = key_expansion(key);

	std::array<uint8_t, 16> state = cyphertext;

	for (size_t i = (R - 1); i != 0; --i) {
		state = arr_xor(state, round_keys[i]);

		if (i != (R - 1)) {
			state = inv_mix_column(state);
		}

		state = inv_shift_row(state);

		state = inv_sbox(state);
	}

	state = arr_xor(state, round_keys[0]);

	return state;
}

static std::vector<uint8_t> pad(std::vector<uint8_t> msg) {
	uint8_t pad_value = 16 - (msg.size() % 16);
	std::vector<uint8_t> padding = std::vector<uint8_t>(pad_value, pad_value);
	msg.insert(msg.end(), padding.begin(), padding.end());

	return msg;
}

static std::vector<uint8_t> unpad(const std::vector<uint8_t>& msg) {
	assert(!msg.empty());
	uint8_t pad_value = msg.back();

	return std::vector<uint8_t>(msg.begin(), msg.end() - pad_value);
}

std::vector<uint8_t> CBC_AES_encryption(const std::vector<uint8_t>& msg, const std::array<uint8_t, 32>& key, std::array<uint8_t, 16> IV) {
	std::vector<uint8_t> padded_msg = pad(msg);
	assert(padded_msg.size() % 16 == 0);
	
	std::vector<uint8_t> cypher_blocks;
	cypher_blocks.insert(cypher_blocks.begin(), IV.begin(), IV.end());

	for (size_t i = 0; i < padded_msg.size(); i += 16) {
		std::array<uint8_t, 16> block;
		std::copy(padded_msg.begin() + i, padded_msg.begin() + i + 16, block.begin());

		block = arr_xor(block, IV);

		std::array<uint8_t, 16> cypher_block = AES_block_encryption(block, key);

		IV = cypher_block;
		cypher_blocks.insert(cypher_blocks.end(), cypher_block.begin(), cypher_block.end());
	}

	return cypher_blocks;
}

std::vector<uint8_t> CBC_AES_decryption(const std::vector<uint8_t>& cyphertext, const std::array<uint8_t, 32>& key) {
	assert(!cyphertext.empty() && cyphertext.size() % 16 == 0);

	std::array<uint8_t, 16> IV;
	std::copy(cyphertext.begin(), cyphertext.begin() + 16, IV.begin());

	std::vector<uint8_t> plain_blocks;
	for (size_t i = 16; i < cyphertext.size(); i += 16) {
		std::array<uint8_t, 16> block;
		std::copy(cyphertext.begin() + i, cyphertext.begin() + i + 16, block.begin());

		std::array<uint8_t, 16> plain_block = AES_block_decryption(block, key);

		plain_block = arr_xor(plain_block, IV);

		IV = plain_block;
		plain_blocks.insert(plain_blocks.end(), plain_block.begin(), plain_block.end());
	}

	return unpad(plain_blocks);
}