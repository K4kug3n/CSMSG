#ifndef CSMSG_HKDF_HPP
#define CSMSG_HKDF_HPP

#include <array>
#include <vector>

std::array<uint8_t, 32> KDF(std::vector<uint8_t> KM);

#endif