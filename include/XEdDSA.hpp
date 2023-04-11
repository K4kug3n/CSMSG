#ifndef CSMSG_XEDDSA_HPP
#define CSMSG_XEDDSA_HPP

#include <array>
#include <boost/multiprecision/cpp_int.hpp>

std::array<unsigned char, 64> XEdDSA_sign(const boost::multiprecision::uint256_t& k, const std::vector<uint8_t>& M, const std::array<uint8_t, 64>& Z);

bool XEdDSA_verify(const boost::multiprecision::uint256_t& u, const std::vector<uint8_t>& M, const std::array<uint8_t, 64>& signature);

#endif