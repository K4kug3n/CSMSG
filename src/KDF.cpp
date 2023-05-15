#include <KDF.hpp>

#include <SHA.hpp>
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

	size_t N = static_cast<size_t>(std::ceil(float(L) / 64));
	
	std::vector<uint8_t> T;
	std::vector<uint8_t> T_prev;
	for (size_t i = 1; i <= N; ++i) {
		T_prev.insert(T_prev.end(), info.begin(), info.end());
		T_prev.push_back(static_cast<uint8_t>(i));

		std::array<uint8_t, 64> T_i = HMAC_512({ PRK.begin(), PRK.end() }, T_prev);
		T.insert(T.end(), T_i.begin(), T_i.end());

		T_prev = std::vector<uint8_t>{ T_i.begin(), T_i.end() };
	}

	return std::vector<uint8_t>{ T.begin(), T.begin() + L };
}

std::array<uint8_t, 64> HKDF_extract(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& IKM) {
	return HMAC_512(salt, IKM);
}

std::vector<uint8_t> HKDF(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& IKM, const std::vector<uint8_t>& info, size_t L) {
	return HKDF_expand(HKDF_extract(salt, IKM), info, L);
}

std::array<uint8_t, 32> KDF(std::vector<uint8_t> KM) {
	KM.insert(KM.begin(), 32, 0xFF);

	std::vector<uint8_t> salt = std::vector<uint8_t>(64, 0x0);

	std::vector<uint8_t> hkdf = HKDF(salt, KM, { 'C', 'S', 'M', 'S', 'G' }, 32); // "CSMSG" as info
	assert(hkdf.size() == 32);

	std::array<uint8_t, 32> res;
	std::copy(hkdf.begin(), hkdf.end(), res.begin());

	return res; 
}

KdfRkResult KDF_RK(const std::array<uint8_t, 32>& rk, std::array<uint8_t, 32> dh_out) {
	std::vector<uint8_t> output = HKDF({ rk.begin(), rk.end() }, { dh_out.begin(), dh_out.end() }, { 'G', 'S', 'M', 'S', 'C' }, 64);
	assert(output.size() == 64);

	KdfRkResult result;
	std::copy(output.begin(), output.begin() + 32, result.root_key.begin());
	std::copy(output.begin() + 32, output.end(), result.chain_key.begin());

	return result;
}

KdfCkResult KDF_CK(const std::array<uint8_t, 32>& ck) {
	std::array<uint8_t, 64> long_message_key = HMAC_512({ ck.begin(), ck.end() }, { 0x1 });
	std::array<uint8_t, 64> long_next_chain_key = HMAC_512({ ck.begin(), ck.end() }, { 0x2 });

	KdfCkResult result;
	std::copy(long_message_key.begin(), long_message_key.begin() + 32, result.message_key.begin());
	std::copy(long_next_chain_key.begin(), long_next_chain_key.begin() + 32, result.chain_key.begin());

	return result;
}
