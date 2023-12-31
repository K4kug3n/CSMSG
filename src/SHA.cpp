#include <SHA.hpp>

#include <boost/multiprecision/cpp_int.hpp>

namespace mp = boost::multiprecision;

static std::vector<uint8_t> pad(std::vector<uint8_t> message) {
	size_t l = message.size() * 8;
	size_t r = (l + 1) % 1024;
	size_t k = (1024 - r) + 896;
	if (r <= 896) {
		k = 896 - r;
	}

	message.push_back(0x80);
	for (size_t i = 1; i < ((k + 1) / 8); ++i) {
		message.push_back(0x00);
	}

	// Compute and add bytes of size
	for (size_t i = 0; i < 8; i++) { // size_t is 64 bits max, so first 64 bits are 0
		message.push_back(0);
	}
	for (size_t i = 0; i < 8; i++) { // work for 64-bits system only
		message.push_back((l >> ((15 - i) * 8)) & 0xFF);
	}

	return message;
}

std::vector<std::array<uint64_t, 16>> parse(const std::vector<unsigned char>& message) {
	assert((message.size() * 8) % 1024 == 0);

	std::vector<std::array<uint64_t, 16>> blocks;
	for (size_t i = 0; i < message.size(); i += 128) {

		std::array<uint64_t, 16> block;
		for (size_t j = 0; j < block.size(); ++j) {

			uint64_t block_part = 0;
			for (size_t k = 0; k < 8; ++k) {
				block_part += uint64_t(message[i + j * 8 + k]) << (8 * (7 - k));
			}
			block[j] = block_part;
		}
		blocks.push_back(block);
	}

	return blocks;
}

uint64_t ROTR(uint64_t x, uint16_t n) {
	return (x >> n) | (x << (64 - n));
}

uint64_t SHR(uint64_t x, uint16_t n) {
	return x >> n;
}

uint64_t Sigma_0(uint64_t x) {
	return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
}

uint64_t Sigma_1(uint64_t x) {
	return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
}

uint64_t sigma_0(uint64_t x) {
	return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7);
}

uint64_t sigma_1(uint64_t x) {
	return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6);
}

uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
	return (x & y) ^ (~x & z);
}

uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
	return (x & y) ^ (x & z) ^ (y & z);
}

std::array<uint64_t, 8> SHA_512(const std::vector<unsigned char>& message) {
	const std::array<uint64_t, 80> K = {
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	};

	std::array<uint64_t, 8> hash_values = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };

	std::vector<unsigned char> padded_message = pad(message);

	std::vector<std::array<uint64_t, 16>> blocks = parse(padded_message);

	for (size_t i = 0; i < blocks.size(); ++i) {

		std::array<uint64_t, 80> W;
		for (size_t t = 0; t < 80; ++t) {
			if (t <= 15) {
				W[t] = blocks[i][t];
			}
			else {
				W[t] = sigma_1(W[t - 2]) + W[t - 7] + sigma_0(W[t - 15]) + W[t - 16];
			}
		}

		uint64_t a, b, c, d, e, f, g, h;
		a = hash_values[0];
		b = hash_values[1];
		c = hash_values[2];
		d = hash_values[3];
		e = hash_values[4];
		f = hash_values[5];
		g = hash_values[6];
		h = hash_values[7];

		for (size_t t = 0; t < 80; ++t) {
			uint64_t t_1 = h + Sigma_1(e) + Ch(e, f, g) + K[t] + W[t];
			uint64_t t_2 = Sigma_0(a) + Maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + t_1;
			d = c;
			c = b;
			b = a;
			a = t_1 + t_2;
		}

		hash_values[0] += a;
		hash_values[1] += b;
		hash_values[2] += c;
		hash_values[3] += d;
		hash_values[4] += e;
		hash_values[5] += f;
		hash_values[6] += g;
		hash_values[7] += h;
	}

	return hash_values;
}