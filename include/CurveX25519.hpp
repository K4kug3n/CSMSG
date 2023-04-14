#ifndef CSMSG_CURVEX25519_HPP
#define CSMSG_CURVEX25519_HPP

#include <array>
#include <utility>

#include <boost/multiprecision/cpp_int.hpp>

std::array<uint8_t, 32> base_point_X25519();

std::array<uint8_t, 32> X25519(const std::array<uint8_t, 32>& u, const std::array<uint8_t, 32>& k);

#endif