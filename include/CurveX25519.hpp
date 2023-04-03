#ifndef CSMSG_CURVEX25519_HPP
#define CSMSG_CURVEX25519_HPP

#include <array>
#include <utility>

#include <boost/multiprecision/cpp_int.hpp>

struct KeyPair {
	std::array<unsigned char, 32> public_key;
	std::array<unsigned char, 32> private_key;
};

std::array<unsigned char, 32> generate_random_key();

boost::multiprecision::uint256_t decode_little_endian(const std::array<unsigned char, 32>& b);

boost::multiprecision::uint256_t decode_u_coordinate(std::array<unsigned char, 32> u);

boost::multiprecision::uint256_t decode_scalar(std::array<unsigned char, 32> k);

std::array<unsigned char, 32> encode_u_coordinate(boost::multiprecision::uint512_t u);

std::pair<boost::multiprecision::uint256_t, boost::multiprecision::uint256_t> cswap(unsigned char swap, boost::multiprecision::uint256_t x_2, boost::multiprecision::uint256_t x_3);

boost::multiprecision::uint512_t scalar_multiplication(const boost::multiprecision::uint256_t& u, const boost::multiprecision::uint256_t& k);

std::array<unsigned char, 32> X25519(const std::array<unsigned char, 32>& u, const std::array<unsigned char, 32>& k);

KeyPair generate_key_pair_X25519();

#endif