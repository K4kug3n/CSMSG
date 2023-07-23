#ifndef CSMSG_HKDF_HPP
#define CSMSG_HKDF_HPP

#include <array>
#include <vector>
#include <cstdint>
#include <cstddef>

std::array<uint8_t, 32> KDF(std::vector<uint8_t> KM);

std::vector<uint8_t> HKDF(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& IKM, const std::vector<uint8_t>& info, size_t L);

std::array<uint8_t, 64> HMAC_512(std::vector<uint8_t> key, const std::vector<uint8_t>& msg);

struct KdfRkResult {
	std::array<uint8_t, 32> root_key;
	std::array<uint8_t, 32> chain_key;
};

KdfRkResult KDF_RK(const std::array<uint8_t, 32>& rk, std::array<uint8_t, 32> dh_out);

struct KdfCkResult {
	std::array<uint8_t, 32> message_key;
	std::array<uint8_t, 32> chain_key;
};

KdfCkResult KDF_CK(const std::array<uint8_t, 32>& ck);

#endif