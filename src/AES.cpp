#include <AES.hpp>

#include <vector>

template <size_t N>
uint32_t uint8_to_uint32(const std::array<uint8_t, N>::const_iterator& it) {
	return uint32_t{ *it }
		| (uint32_t{ *(it + 1) } << 8)
		| (uint32_t{ *(it + 2) } << 16)
		| (uint32_t{ *(it + 3) } << 24);
}

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

std::array<std::array<uint8_t, 32>, 15> key_expansion(const std::array<uint8_t, 32>& key) {
	constexpr size_t N = 8;
	constexpr size_t R = 15;

	std::vector<std::array<uint8_t, 4>> K = std::vector<std::array<uint8_t, 4>>(N);
	for (size_t i = 0; i < K.size(); ++i) {
		std::copy(key.begin() + 4 * i, key.begin() + 4 * (i + 1), K[i].begin());
	}

	std::vector<uint32_t> W = std::vector<uint32_t>(4 * R);
}

std::array<uint8_t, 16> AES_block_encryption(const std::array<uint8_t, 16>& plaintext, const std::array<uint8_t, 32>& key) {

}