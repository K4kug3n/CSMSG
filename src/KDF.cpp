#include <KDF.hpp>

#include <SHA512.hpp>
#include <Utility.hpp>

#include <cassert>
#include <cmath>

std::vector<uint8_t> XOR(std::vector<uint8_t> A, const std::vector<uint8_t>& B) {
	assert(A.size() == B.size());

	for (size_t i = 0; i < A.size(); ++i) {
		A[i] ^= B[i];
	}

	return A;
}

std::array<uint8_t, 64> HMAC_512(std::vector<uint8_t> key, const std::vector<uint8_t>& msg) {
	// Following RFC 2104
	std::vector<uint8_t> ipad = std::vector < uint8_t>(64, 0x36);
	std::vector<uint8_t> opad = std::vector < uint8_t>(64, 0x5C);
	
	if (key.size() < ipad.size()) {
		key.insert(key.end(), ipad.size() - key.size(), 0); // Step 1
	}
	
	std::vector<uint8_t> step_2 = XOR(key, ipad);
	step_2.insert(step_2.end(), msg.begin(), msg.end()); // Step 3

	std::array<uint8_t, 64> step_4 = to_bytes(SHA_512(step_2)); // Step 4
	std::vector<uint8_t> step_5 = XOR({ step_4.begin(), step_4.end() }, opad);

	step_5.insert(step_5.end(), step_4.begin(), step_4.end()); // Step 6
	std::array<uint8_t, 64> step_7 = to_bytes(SHA_512(step_5));

	return step_7;
}

std::vector<uint8_t> HKDF_expand(const std::array<uint8_t, 64>& PRK, const std::vector<uint8_t>& info, size_t L) {
	assert(L <= 255 * 64);

	size_t N = std::ceil(float(L) / 64);
	
	std::vector<uint8_t> T;
	std::vector<uint8_t> T_prev;
	for (size_t i = 1; i <= N; ++i) {
		T_prev.insert(T_prev.end(), info.begin(), info.end());
		T_prev.push_back(i);

		std::array<uint8_t, 64> T_i = HMAC_512({ PRK.begin(), PRK.end() }, T_prev);
		T.insert(T.end(), T_i.begin(), T_i.end());

		T_prev = std::vector<uint8_t>{ T_i.begin(), T_i.end() };
	}

	return std::vector<uint8_t>{ T.begin(), T.begin() + L };
}

std::array<uint8_t, 64> HKDF_extract(const std::array<uint8_t, 64>& salt, const std::vector<uint8_t>& IKM) {
	return HMAC_512({ salt.begin(), salt.end() }, IKM);
}

std::vector<uint8_t> HKDF(const std::array<uint8_t, 64>& salt, const std::vector<uint8_t>& IKM, const std::vector<uint8_t>& info, size_t L) {
	return HKDF_expand(HKDF_extract(salt, IKM), info, L);
}

std::array<uint8_t, 32> KDF(std::vector<uint8_t> KM) {
	KM.insert(KM.begin(), 32, 0xFF);

	std::array<uint8_t, 64> salt;
	salt.fill(0x0);

	std::vector<uint8_t> hkdf = HKDF(salt, KM, { 67, 83, 77, 83, 71 }, 32); // "CSMSG" as info
	assert(hkdf.size() == 32);

	std::array<uint8_t, 32> res;
	std::copy(hkdf.begin(), hkdf.end(), res.begin());

	return res; 
}