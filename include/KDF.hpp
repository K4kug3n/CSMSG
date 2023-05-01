#ifndef CSMSG_HKDF_HPP
#define CSMSG_HKDF_HPP

#include <array>
#include <vector>

std::array<uint8_t, 32> KDF(std::vector<uint8_t> KM);

std::array<uint8_t, 64> HMAC_512(std::vector<uint8_t> key, const std::vector<uint8_t>& msg);

#endif