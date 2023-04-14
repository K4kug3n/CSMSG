#include <CurveX25519.hpp>

namespace mp = boost::multiprecision;

mp::uint256_t decode_little_endian(const std::array<uint8_t, 32>& b) {
	mp::uint256_t sum = 0;

	mp::uint256_t temp;
	for (size_t i = 0; i < b.size(); ++i) {
		temp = b[i];
		sum += (temp << (8 * i));
	}

	return sum;
}

mp::uint256_t decode_u_coordinate(std::array<uint8_t, 32> u) {
	u[31] &= (1 << (255 % 8)) - 1;

	return decode_little_endian(u);
}

mp::uint256_t decode_scalar(std::array<uint8_t, 32> k) {
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;

	return decode_little_endian(k);
}

std::array<uint8_t, 32> encode_u_coordinate(mp::uint256_t u) {
	mp::uint256_t p = mp::pow(mp::uint256_t(2), 255) - 19;
	u = u % p;

	std::array<uint8_t, 32> coord;
	for (size_t i = 0; i < coord.size(); ++i) {
		coord[i] = static_cast<uint8_t>((u >> (8 * i)) & 0xFF);
	}

	return coord;
}

std::pair<mp::uint256_t, mp::uint256_t> cswap(uint8_t swap, mp::uint256_t x_2, mp::uint256_t x_3) {
	mp::uint256_t dummy = (0 - swap) & (x_2 ^ x_3);
	x_2 = x_2 ^ dummy;
	x_3 = x_3 ^ dummy;

	return std::pair{ x_2, x_3 };
}

mp::uint256_t scalar_multiplication(const mp::uint256_t& u, const mp::uint256_t& k) {
	mp::uint256_t x_1 = u;
	mp::uint256_t x_2 = 1;
	mp::uint256_t z_2 = 0;

	mp::uint256_t x_3 = u;
	mp::uint256_t z_3 = 1;
	uint8_t swap = 0;

	mp::uint256_t p = mp::pow(mp::uint256_t(2), 255) - 19;

	for (size_t i = 0; i < 255; ++i) {
		size_t t = 255 - 1 - i;
		uint8_t k_t = static_cast<uint8_t>((k >> t) & 1);
		swap ^= k_t;

		std::pair<mp::uint256_t&, mp::uint256_t&>(x_2, x_3) = cswap(swap, x_2, x_3);
		std::pair<mp::uint256_t&, mp::uint256_t&>(z_2, z_3) = cswap(swap, z_2, z_3);
		swap = k_t;

		mp::uint256_t A = (x_2 + z_2) % p;
		mp::uint512_t AA = (mp::uint512_t(A) * A) % p;
		mp::uint512_t B = mp::uint512_t((((mp::int512_t(x_2) - mp::int512_t(z_2)) % p) + p) % p);
		mp::uint512_t BB = (B * B) % p;
		mp::uint512_t E = mp::uint512_t((((mp::int512_t(AA) - mp::int512_t(BB)) % p) + p) % p);
		mp::uint512_t C = (x_3 + z_3) % p;
		mp::uint512_t D = mp::uint512_t((((mp::int512_t(x_3) - mp::int512_t(z_3)) % p) + p) % p);
		mp::uint512_t DA = (D * A) % p;
		mp::uint512_t CB = (C * B) % p;

		x_3 = mp::uint256_t(mp::pow((DA + CB), 2) % p);
		z_3 = mp::uint256_t((x_1 * (mp::pow(DA - CB, 2) % p)) % p);
		x_2 = mp::uint256_t((AA * BB) % p);
		z_2 = mp::uint256_t((E * (AA + ((mp::uint512_t(121665) * E)) % p)) % p);
	}

	std::pair<mp::uint256_t&, mp::uint256_t&>(x_2, x_3) = cswap(swap, x_2, x_3);
	std::pair<mp::uint256_t&, mp::uint256_t&>(z_2, z_3) = cswap(swap, z_2, z_3);

	return mp::uint256_t((mp::uint512_t(x_2) * mp::powm(z_2, p - 2, p)) % p);
}

std::array<uint8_t, 32> base_point_X25519() {
	return std::array<uint8_t, 32>{ { 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } };
}

std::array<uint8_t, 32> X25519(const std::array<uint8_t, 32>& u, const std::array<uint8_t, 32>& k) {
	mp::uint256_t res = scalar_multiplication(decode_u_coordinate(u), decode_scalar(k));

	return encode_u_coordinate(res);
}
