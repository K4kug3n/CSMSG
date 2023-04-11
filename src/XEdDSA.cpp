#include <XEdDSA.hpp>

#include <SHA512.hpp>
#include <Utility.hpp>
#include <CurveX25519.hpp>
#include <Edward.hpp>

#include <iostream>

namespace mp = boost::multiprecision;

mp::uint256_t u_to_y(const mp::uint256_t& u) {
	mp::uint256_t p = mp::pow(mp::uint256_t(2), 255) - 19;

	return f_prod((u - 1), inv(u + 1, p), p);
}

mp::uint256_t convert_mont(const mp::uint256_t& u) {
	mp::uint256_t u_masked = u % mp::pow(mp::uint256_t(2), 255);

	return u_to_y(u_masked);
}

std::pair<EdwardPoint, mp::uint256_t> calculate_key_pair(const mp::uint256_t& k) {
	const std::array<uint8_t, 32> B = { 0x9, 0x0, 0x0, 0x0, 0x0 , 0x0 , 0x0, 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 };

	const mp::uint256_t q = mp::pow(mp::uint256_t(2), 252) + mp::uint256_t{ "27742317777372353535851937790883648493" };

	const EdwardPoint E = k * decompress(convert_mont(to_integer(B)));

	return std::pair{ E, k % q};
}

std::array<uint64_t, 8> hash(std::vector<uint8_t> message, uint8_t i) {
	message.insert(message.begin(), 32, 0xFF);

	message[0] -= i;

	return SHA_512(message);
}

std::array<uint8_t, 64> XEdDSA_sign(const mp::uint256_t& k, const std::vector<uint8_t>& M, const std::array<uint8_t, 64>& Z) {
	const std::array<uint8_t, 32> B = { 0x9, 0x0, 0x0, 0x0, 0x0 , 0x0 , 0x0, 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 };
	const mp::uint256_t q = mp::pow(mp::uint256_t(2), 252) + mp::uint256_t{ "27742317777372353535851937790883648493" };

	EdwardPoint A{ 0, 0, 0, 0 };
	mp::uint256_t a;
	std::pair<EdwardPoint&, mp::uint256_t&>{ A, a } = calculate_key_pair(k);

	std::vector<uint8_t> r_hash_message = M;
	const std::array<uint8_t, 32> a_bytes = to_bytes(a);
	r_hash_message.insert(r_hash_message.begin(), a_bytes.begin(), a_bytes.end());
	r_hash_message.insert(r_hash_message.end(), Z.begin(), Z.end());
	
	const std::array<uint8_t, 64> r_bytes = to_bytes(hash(r_hash_message, 1));
	const mp::uint256_t r = static_cast<mp::uint256_t>(to_integer(r_bytes) % q);

	const EdwardPoint R = r * decompress(convert_mont(to_integer(B)));
	const std::array<uint8_t, 32> R_bytes = to_bytes(R.compress());
	const std::array<uint8_t, 32> A_bytes = to_bytes(A.compress());

	std::vector<uint8_t> hash_message = M;
	hash_message.insert(hash_message.begin(), A_bytes.begin(), A_bytes.end());
	hash_message.insert(hash_message.end(), R_bytes.begin(), R_bytes.end());
	const std::array<uint8_t, 64> h_bytes = to_bytes(SHA_512(hash_message));
	const mp::uint256_t h = static_cast<mp::uint256_t>(to_integer(h_bytes) % q);

	const mp::uint256_t s = f_add(r, f_prod(h, a, q), q);
	const std::array<uint8_t, 32> s_bytes = to_bytes(s);

	std::array<uint8_t, 64> signature;
	for (size_t i = 0; i < 32; ++i) {
		signature[i] = R_bytes[i];
		signature[i + 32] = s_bytes[i];
	}

	return signature;
}

bool XEdDSA_verify(const mp::uint256_t& u, const std::vector<uint8_t>& M, const std::array<uint8_t, 64>& signature) {
	const std::array<uint8_t, 32> B = { 0x9, 0x0, 0x0, 0x0, 0x0 , 0x0 , 0x0, 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 , 0x0, 0x0, 0x0 , 0x0 , 0x0 };
	const mp::uint256_t q = mp::pow(mp::uint256_t(2), 252) + mp::uint256_t{ "27742317777372353535851937790883648493" };

	std::array<uint8_t, 32> R_bytes;
	std::array<uint8_t, 32> s_bytes;
	for (size_t i = 0; i < 32; ++i) {
		R_bytes[i] = signature[i];
		s_bytes[i] = signature[32 + i];
	}

	const EdwardPoint A = decompress(convert_mont(u));
	const std::array<uint8_t, 32> A_bytes = to_bytes(A.compress());

	std::vector<uint8_t> hash_message = M;
	hash_message.insert(hash_message.begin(), A_bytes.begin(), A_bytes.end());
	hash_message.insert(hash_message.begin(), R_bytes.begin(), R_bytes.end());

	const std::array<uint8_t, 64> h_bytes = to_bytes(SHA_512(hash_message));
	const mp::uint256_t h = static_cast<mp::uint256_t>(to_integer(h_bytes) % q);

	const mp::uint256_t s = to_integer(s_bytes);
	const EdwardPoint sB = s * decompress(convert_mont(decode_u_coordinate(B)));
	const EdwardPoint hA = h * A;

	const EdwardPoint R = decompress(to_integer(R_bytes));

	return (R + hA) == sB;
}