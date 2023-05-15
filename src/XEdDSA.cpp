#include <XEdDSA.hpp>

#include <SHA.hpp>
#include <Utility.hpp>
#include <CurveX25519.hpp>
#include <Edward.hpp>

#include <boost/multiprecision/cpp_int.hpp>

#include <iostream>

namespace mp = boost::multiprecision;

//mp::uint256_t u_to_y(const mp::uint256_t& u) {
//	mp::uint256_t p = mp::pow(mp::uint256_t(2), 255) - 19;
//
//	return f_prod((u - 1), inv(u + 1, p), p);
//}
//
//mp::uint256_t convert_mont(const mp::uint256_t& u) {
//	mp::uint256_t u_masked = u % mp::pow(mp::uint256_t(2), 255);
//
//	return u_to_y(u_masked);
//}

//std::pair<EdwardPoint, mp::uint256_t> calculate_key_pair(const mp::uint256_t& k) {
//	const mp::uint256_t q = mp::pow(mp::uint256_t(2), 252) + mp::uint256_t{ "27742317777372353535851937790883648493" };
//
//	const EdwardPoint E = k * G();
//
//	return std::pair{ E, k % q};
//}

std::array<uint8_t, 64> XEdDSA_sign(const std::array<uint8_t, 32>& priv, const std::vector<uint8_t>& msg, const std::array<uint8_t, 64>& nonce) {
	EdwardPoint ed_public_key_point = to_integer(priv) * G();
	mp::uint256_t ed_public_key = ed_public_key_point.compress();
	uint8_t sign_bit = to_bytes(ed_public_key)[31] & 0b10000000;

	std::vector<uint8_t> r_hash_message = std::vector<uint8_t>(32, 0xFF);
	r_hash_message[0] = 0xFE;
	r_hash_message.insert(r_hash_message.end(), priv.begin(), priv.end());
	r_hash_message.insert(r_hash_message.end(), msg.begin(), msg.end());
	r_hash_message.insert(r_hash_message.end(), nonce.begin(), nonce.end());
	
	const std::array<uint8_t, 64> r_bytes = to_bytes(SHA_512(r_hash_message));
	const mp::uint256_t r = static_cast<mp::uint256_t>(to_integer(r_bytes) % EdwardPoint::q);

	const mp::uint256_t cap_r = (r * G()).compress();

	const std::array<uint8_t, 32> cap_r_bytes = to_bytes(cap_r);
	const std::array<uint8_t, 32> ed_public_key_bytes = to_bytes(ed_public_key);

	std::vector<uint8_t> h_hash_message = std::vector<uint8_t>(cap_r_bytes.begin(), cap_r_bytes.end());
	h_hash_message.insert(h_hash_message.end(), ed_public_key_bytes.begin(), ed_public_key_bytes.end());
	h_hash_message.insert(h_hash_message.end(), msg.begin(), msg.end());

	const std::array<uint8_t, 64> h_bytes = to_bytes(SHA_512(h_hash_message));
	const mp::uint256_t h = static_cast<mp::uint256_t>(to_integer(h_bytes) % EdwardPoint::q);

	const mp::uint256_t s = f_add(r, f_prod(h, to_integer(priv), EdwardPoint::q), EdwardPoint::q);
	const std::array<uint8_t, 32> s_bytes = to_bytes(s);

	std::array<uint8_t, 64> signature;
	std::copy(cap_r_bytes.begin(), cap_r_bytes.end(), signature.begin());
	std::copy(s_bytes.begin(), s_bytes.end(), signature.begin() + 32);
	
	signature[63] &= 0b01111111;
	signature[63] |= sign_bit;

	return signature;
}

bool XEdDSA_verify(const std::array<uint8_t, 32>& pub, const std::vector<uint8_t>& M, const std::array<uint8_t, 64>& signature) {
	const std::optional<EdwardPoint> ed_pub_key_opt = EdwardPoint::FromMontgomery(pub, (signature[63] & 0b10000000) >> 7);
	if (!ed_pub_key_opt) {
		return false;
	}
	const EdwardPoint ed_pub_key_point = ed_pub_key_opt.value();

	const mp::uint256_t cap_a = ed_pub_key_point.compress();
	std::array<uint8_t, 32> cap_r;
	std::copy(signature.begin(), signature.begin() + 32, cap_r.begin());

	std::array<uint8_t, 32> s;
	std::copy(signature.begin() + 32, signature.end(), s.begin());
	s[31] &= 0b01111111;
	if ((s[31] & 0b11100000) != 0) {
		return false;
	}

	const EdwardPoint minus_cap_a = -ed_pub_key_point;
	const std::array<uint8_t, 32> cap_a_bytes = to_bytes(cap_a);

	std::vector<uint8_t> hash_message = std::vector<uint8_t>(cap_r.begin(), cap_r.end());
	hash_message.insert(hash_message.end(), cap_a_bytes.begin(), cap_a_bytes.end());
	hash_message.insert(hash_message.end(), M.begin(), M.end());

	const std::array<uint8_t, 64> h_bytes = to_bytes(SHA_512(hash_message));
	const mp::uint256_t h = static_cast<mp::uint256_t>(to_integer(h_bytes) % EdwardPoint::q);

	const EdwardPoint cap_r_check_point = h * minus_cap_a + to_integer(s) * G();
	const mp::uint256_t cap_r_check = cap_r_check_point.compress();

	return to_bytes(cap_r_check) == cap_r;
}