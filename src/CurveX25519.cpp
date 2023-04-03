#include <CurveX25519.hpp>

#include <random>

namespace mp = boost::multiprecision;

std::array<unsigned char, 32> generate_random_key() {
	std::random_device dev;
	std::mt19937 rng{ dev() };
	std::uniform_int_distribution<std::mt19937::result_type> dist{ 0, UCHAR_MAX };

	std::array<unsigned char, 32> key = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	for (size_t i = 0; i < key.size(); ++i) {
		key[i] = dist(rng);
	}

	return key;
}

mp::uint256_t decode_little_endian(const std::array<unsigned char, 32>& b) {
	mp::uint256_t sum = 0;

	mp::uint256_t temp;
	for (size_t i = 0; i < b.size(); ++i) {
		temp = b[i];
		sum += (temp << (8 * i));
	}

	return sum;
}

mp::uint256_t decode_u_coordinate(std::array<unsigned char, 32> u) {
	u[31] &= (1 << (255 % 8)) - 1;

	return decode_little_endian(u);
}

mp::uint256_t decode_scalar(std::array<unsigned char, 32> k) {
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;

	return decode_little_endian(k);
}

std::array<unsigned char, 32> encode_u_coordinate(mp::uint512_t u) {
	mp::uint256_t p = mp::pow(mp::uint256_t(2), 255) - 19;
	u = u % p;

	std::array<unsigned char, 32> coord;
	for (size_t i = 0; i < coord.size(); ++i) {
		coord[i] = static_cast<unsigned char>((u >> (8 * i)) & 0xFF);
	}

	return coord;
}

std::pair<mp::uint256_t, mp::uint256_t> cswap(unsigned char swap, mp::uint256_t x_2, mp::uint256_t x_3) {
	mp::uint256_t dummy = (0 - swap) & (x_2 ^ x_3);
	x_2 = x_2 ^ dummy;
	x_3 = x_3 ^ dummy;

	return std::pair{ x_2, x_3 };
}

mp::uint512_t scalar_multiplication(const mp::uint256_t& u, const mp::uint256_t& k) {
	mp::uint256_t x_1 = u;
	mp::uint256_t x_2 = 1;
	mp::uint256_t z_2 = 0;

	mp::uint256_t x_3 = u;
	mp::uint256_t z_3 = 1;
	unsigned char swap = 0;

	mp::uint256_t p = mp::pow(mp::uint256_t(2), 255) - 19;

	for (size_t i = 0; i < 255; ++i) {
		size_t t = 255 - 1 - i;
		unsigned char k_t = static_cast<unsigned char>((k >> t) & 1);
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

	return mp::uint512_t(x_2) * mp::powm(z_2, p - 2, p);
}

std::array<unsigned char, 32> X25519(const std::array<unsigned char, 32>& u, const std::array<unsigned char, 32>& k) {
	mp::uint512_t res = scalar_multiplication(decode_u_coordinate(u), decode_scalar(k));

	return encode_u_coordinate(res);
}

KeyPair generate_key_pair_X25519() {
	std::array<unsigned char, 32> base = { 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	std::array<unsigned char, 32> private_key = generate_random_key();
	std::array<unsigned char, 32> public_key = X25519(base, private_key);

	return KeyPair{ public_key, private_key };
}
