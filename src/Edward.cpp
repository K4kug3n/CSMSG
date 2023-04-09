#include <Edward.hpp>

#include <SHA512.hpp>
#include <Utility.hpp>
#include <exception>

namespace mp = boost::multiprecision;

EdwardPoint::EdwardPoint(const mp::uint256_t& new_x, const mp::uint256_t& new_y, const mp::uint256_t& new_z, const mp::uint256_t& new_t) :
	x(new_x), y(new_y), z(new_z), t(new_t) { }

mp::uint256_t EdwardPoint::compress() const {
	mp::uint256_t z_inv = inv(z, EdwardPoint::p);
	mp::uint256_t comp_x = f_prod(x, z_inv, EdwardPoint::p);
	mp::uint256_t comp_y = f_prod(y, z_inv, EdwardPoint::p);;

	return comp_y | ((comp_x & 1) << 255);
}

EdwardPoint operator+(const EdwardPoint& P, const EdwardPoint& Q) {	
	mp::uint256_t A = f_prod(
		static_cast<mp::uint256_t>(pos_mod(mp::int512_t{ P.y } - mp::int512_t{ P.x }, EdwardPoint::p)),
		static_cast<mp::uint256_t>(pos_mod(mp::int512_t{ Q.y } - mp::int512_t{ Q.x }, EdwardPoint::p)),
		EdwardPoint::p
	);
	mp::uint256_t B = f_prod(f_add(P.y, P.x, EdwardPoint::p), f_add(Q.y, Q.x, EdwardPoint::p), EdwardPoint::p);

	mp::uint512_t C = (mp::uint512_t{ 2 } * f_prod(P.t, f_prod(Q.t, EdwardPoint::d, EdwardPoint::p), EdwardPoint::p)) % EdwardPoint::p;
	mp::uint512_t D = (mp::uint512_t{ 2 } * f_prod(P.z, Q.z, EdwardPoint::p)) % EdwardPoint::p;
	
	mp::uint512_t E = static_cast<mp::uint512_t>(pos_mod(mp::int1024_t{ B } - mp::int1024_t{ A }, EdwardPoint::p));
	mp::uint512_t F = static_cast<mp::uint512_t>(pos_mod(mp::int1024_t{ D } - mp::int1024_t{ C }, EdwardPoint::p));
	mp::uint512_t G = (D + C) % EdwardPoint::p;
	mp::uint512_t H = (B + A) % EdwardPoint::p;

	return EdwardPoint(
		mp::uint256_t{ (E * F) % EdwardPoint::p },
		mp::uint256_t{ (G * H) % EdwardPoint::p },
		mp::uint256_t{ (F * G) % EdwardPoint::p },
		mp::uint256_t{ (E * H) % EdwardPoint::p }
	);
}

EdwardPoint operator*(mp::uint256_t s, EdwardPoint P) {
	EdwardPoint Q{ 0, 1, 1, 0 }; // Neutral element

	while (s > 0) {
		if (s & 1) {
			Q = Q + P;
		}
		P = P + P;
		s >>= 1;
	}

	return Q;
}

bool operator==(const EdwardPoint& P, const EdwardPoint& Q) {
	if ((static_cast<mp::int512_t>(f_prod(P.x, Q.z, EdwardPoint::p)) - static_cast<mp::int512_t>(f_prod(Q.x, P.z, EdwardPoint::p))) % EdwardPoint::p != 0) {
		return false;
	}
	if ((static_cast<mp::int512_t>(f_prod(P.y, Q.z, EdwardPoint::p)) - static_cast<mp::int512_t>(f_prod(Q.y, P.z, EdwardPoint::p))) % EdwardPoint::p != 0) {
		return false;
	}

	return true;
}

EdwardPoint G() {
	mp::uint256_t g_y = f_prod(4, inv(5, EdwardPoint::p), EdwardPoint::p);
	mp::uint256_t g_x = recover_x(g_y, 0);

	return EdwardPoint(g_x, g_y, 1, f_prod(g_x, g_y, EdwardPoint::p));
}

mp::uint256_t recover_x(mp::uint256_t y, uint8_t sign) {
	if (y >= EdwardPoint::p) {
		throw std::runtime_error("y >= EdwardPoint::p");
	}

	mp::uint256_t dyy = (f_prod(EdwardPoint::d, f_prod(y, y, EdwardPoint::p), EdwardPoint::p) + 1) % EdwardPoint::p;
	mp::uint256_t x_2 = f_prod(f_prod(y, y, EdwardPoint::p) - 1, inv(dyy, EdwardPoint::p), EdwardPoint::p);
	if (x_2 == 0) {
		if (sign) {
			throw std::runtime_error("x_2 == 0 && sign");
		}
		
		return 0;
	}

	// Compute square root of x_2
	mp::uint256_t x = mp::powm(x_2, (EdwardPoint::p + 3) / 8, EdwardPoint::p);
	if ((static_cast<mp::int512_t>(f_prod(x, x, EdwardPoint::p)) - x_2) % EdwardPoint::p != 0) {
		x = f_prod(x, mp::powm(mp::uint256_t{ 2 }, (EdwardPoint::p - 1) / 4, EdwardPoint::p), EdwardPoint::p);
	}

	if ((static_cast<mp::int512_t>( f_prod(x, x, EdwardPoint::p) ) - x_2) % EdwardPoint::p != 0) {
		throw std::runtime_error("(x * x - x_2) % p != 0");
	}

	if ((x & 1) != sign) {
		x = EdwardPoint::p - x;
	}

	return x;
}

EdwardPoint decompress(mp::uint256_t y) {
	uint8_t sign = static_cast<uint8_t>(y >> 255);
	y &= (mp::uint256_t{ 1 } << 255) - 1;

	mp::uint256_t x = recover_x(y, sign);

	return EdwardPoint(x, y, 1, f_prod(x, y, EdwardPoint::p));
}

std::pair<boost::multiprecision::uint256_t, std::array<unsigned char, 32>> secret_expand(const std::array<unsigned char, 32>& k) {
	std::array<uint64_t, 8> h = SHA_512(std::vector<unsigned char>{ k.begin(), k.end() });
	std::array<unsigned char, 64> h_conv = to_bytes(h);

	mp::uint256_t a = 0;
	for (size_t i = 0; i < 32; ++i) {
		a += mp::uint256_t{ h_conv[i] } << (8 * i);
	}
	std::array<unsigned char, 32> h_half;
	for (size_t i = 0; i < 32; ++i) {
		h_half[i] = h_conv[i + 32];
	}

	a &= (mp::uint256_t{ 1 } << 254) - 8;
	a |= (mp::uint256_t{ 1 } << 254);

	return std::pair<mp::uint256_t, std::array<unsigned char, 32>>{ a, h_half };
}

mp::uint256_t secret_to_public(const std::array<unsigned char, 32>& k) {
	mp::uint256_t a;
	std::array<unsigned char, 32> dummy;
	std::pair<mp::uint256_t&, std::array<unsigned char, 32>&>{ a, dummy } = secret_expand(k);

	return (a * G()).compress();
}

std::array<unsigned char, 64> Ed25519_sign(const std::array<unsigned char, 32>& k, const std::vector<unsigned char>& message) {
	mp::uint256_t a;
	std::array<unsigned char, 32> prefix;
	std::pair<mp::uint256_t&, std::array<unsigned char, 32>&>{ a, prefix } = secret_expand(k);

	std::array<unsigned char, 32> A = to_bytes((a * G()).compress());
	std::vector<unsigned char> r_hash_message = message;
	r_hash_message.insert(r_hash_message.begin(), prefix.begin(), prefix.end());

	std::array<unsigned char, 64> r_hash = to_bytes(SHA_512(r_hash_message));
	mp::uint256_t r = static_cast<mp::uint256_t>(to_integer(r_hash) % EdwardPoint::q);
	EdwardPoint R = r * G();
	mp::uint256_t Rs = R.compress();

	std::array<unsigned char, 32> Rs_bytes = to_bytes(Rs);
	std::vector<unsigned char> h_hash_message = message;
	h_hash_message.insert(h_hash_message.begin(), A.begin(), A.end());
	h_hash_message.insert(h_hash_message.begin(), Rs_bytes.begin(), Rs_bytes.end());
	std::array<unsigned char, 64> h_hash = to_bytes(SHA_512(h_hash_message));
	mp::uint256_t h = static_cast<mp::uint256_t>(to_integer(h_hash) % EdwardPoint::q);

	mp::uint256_t s = f_add(r, f_prod(h, a, EdwardPoint::q), EdwardPoint::q);
	std::array<unsigned char, 32> s_bytes = to_bytes(s);

	std::array<unsigned char, 64> res;
	for (size_t i = 0; i < 32; ++i) {
		res[i] = Rs_bytes[i];
		res[i + 32] = s_bytes[i];
	}

	return res;
}

bool Ed25519_verify(const std::array<unsigned char, 32>& pub, const std::vector<unsigned char>& message, const std::array<unsigned char, 64>& signature) {
	mp::uint256_t pub_value = to_integer(pub);
	EdwardPoint A = decompress(pub_value);

	std::array<unsigned char, 32> Rs_bytes;
	std::array<unsigned char, 32> s_bytes;
	for (size_t i = 0; i < s_bytes.size(); ++i) {
		Rs_bytes[i] = signature[i];
		s_bytes[i] = signature[32 + i];
	}

	EdwardPoint R = decompress(to_integer(Rs_bytes));
	mp::uint256_t s = to_integer(s_bytes);
	if (s >= EdwardPoint::q) {
		return false;
	}

	std::vector<unsigned char> h_hash_message = message;
	h_hash_message.insert(h_hash_message.begin(), pub.begin(), pub.end());
	h_hash_message.insert(h_hash_message.begin(), Rs_bytes.begin(), Rs_bytes.end());
	std::array<unsigned char, 64> h_hash = to_bytes(SHA_512(h_hash_message));
	mp::uint256_t h = static_cast<mp::uint256_t>(to_integer(h_hash) % EdwardPoint::q);

	EdwardPoint sB = s * G();
	EdwardPoint hA = h * A;

	return sB == (R + hA);
}