#include <Utility.hpp>

namespace mp = boost::multiprecision;

mp::uint256_t inv(const mp::uint256_t& a, const mp::uint256_t& p) {
	return mp::powm(a, p - 2, p);
}

std::array<uint8_t, 32> to_bytes(const mp::uint256_t& x) {
	std::array<uint8_t, 32> bytes;
	for (size_t i = 0; i < bytes.size(); ++i) {
		bytes[i] = static_cast<uint8_t>((x >> (i * 8)) & 0xFF);
	}

	return bytes;
}

std::array<uint8_t, 64> to_bytes(const std::array<uint64_t, 8>& arr) {
	std::array<uint8_t, 64> bytes;
	for (size_t i = 0; i < 8; ++i) {
		for (size_t j = 0; j < 8; ++j) {
			bytes[(i * 8) + j] = (arr[i] >> (56 - (j * 8))) & 0xFF;
		}
	}

	return bytes;
}

mp::uint512_t to_integer(const std::array<uint8_t, 64>& arr) {
	mp::uint512_t x = 0;
	for (size_t i = 0; i < arr.size(); ++i) {
		x += static_cast<mp::uint512_t>(arr[i]) << (i * 8);
	}

	return x;
}

mp::uint256_t to_integer(const std::array<uint8_t, 32>& arr) {
	mp::uint256_t x = 0;
	for (size_t i = 0; i < arr.size(); ++i) {
		x += static_cast<mp::uint256_t>(arr[i]) << (i * 8);
	}

	return x;
}

mp::uint256_t f_prod(const mp::uint256_t& a, const mp::uint256_t& b, const mp::uint256_t& p) {
	return static_cast<mp::uint256_t>((mp::uint512_t{ a } * mp::uint512_t{ b }) % p);
}

mp::uint256_t f_add(const mp::uint256_t& a, const mp::uint256_t& b, const mp::uint256_t& p) {
	return static_cast<mp::uint256_t>((mp::uint512_t{ a } + mp::uint512_t{ b }) % p);
}
