#ifndef CSMSG_XEDDSA_HPP
#define CSMSG_XEDDSA_HPP

#include <array>
#include <vector>

std::array<uint8_t, 64> XEdDSA_sign(const std::array<uint8_t, 32>& priv, const std::vector<uint8_t>& msg, const std::array<uint8_t, 64>& nonce);

bool XEdDSA_verify(const std::array<uint8_t, 32>& pub, const std::vector<uint8_t>& M, const std::array<uint8_t, 64>& signature);

#endif