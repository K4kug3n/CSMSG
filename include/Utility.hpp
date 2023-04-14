#ifndef CSMSG_UTILITY_HPP
#define CSMSG_UTILITY_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <array>

boost::multiprecision::uint256_t inv(const boost::multiprecision::uint256_t& a, const boost::multiprecision::uint256_t& p);

std::array<uint8_t, 32> to_bytes(const boost::multiprecision::uint256_t& x);

std::array<uint8_t, 64> to_bytes(const std::array<uint64_t, 8>& arr);

boost::multiprecision::uint512_t to_integer(const std::array<uint8_t, 64>& arr);

boost::multiprecision::uint256_t to_integer(const std::array<uint8_t, 32>& arr);

template<std::size_t N>
std::array<uint8_t, N> random_bytes_array();

boost::multiprecision::uint256_t f_prod(const boost::multiprecision::uint256_t& a, const boost::multiprecision::uint256_t& b, const boost::multiprecision::uint256_t& p);

boost::multiprecision::uint256_t f_add(const boost::multiprecision::uint256_t& a, const boost::multiprecision::uint256_t& b, const boost::multiprecision::uint256_t& p);

template<typename T1, typename T2>
T1 pos_mod(const T1& x, const T2& p);

#include <Utility.inl>

#endif