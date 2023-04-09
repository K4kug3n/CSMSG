#ifndef CSMSG_EDWARD_HPP
#define CSMSG_EDWARD_HPP

#include <boost/multiprecision/cpp_int.hpp> 
#include <utility>

struct EdwardPoint {
	EdwardPoint(const boost::multiprecision::uint256_t& new_x, const boost::multiprecision::uint256_t& new_y,
	            const boost::multiprecision::uint256_t& new_z, const boost::multiprecision::uint256_t& new_t);

	boost::multiprecision::uint256_t compress() const;

	boost::multiprecision::uint256_t x;
	boost::multiprecision::uint256_t y;
	boost::multiprecision::uint256_t z;
	boost::multiprecision::uint256_t t;

	inline const static boost::multiprecision::uint256_t p = boost::multiprecision::pow(boost::multiprecision::uint256_t(2), 255) - 19;
	inline const static boost::multiprecision::uint256_t q = boost::multiprecision::pow(boost::multiprecision::uint256_t(2), 252) + boost::multiprecision::uint256_t{ "27742317777372353535851937790883648493" };
	inline const static boost::multiprecision::uint256_t d = boost::multiprecision::uint256_t{ "37095705934669439343138083508754565189542113879843219016388785533085940283555" };
};

EdwardPoint operator+(const EdwardPoint& P, const EdwardPoint& Q);

EdwardPoint operator*(boost::multiprecision::uint256_t s, EdwardPoint P);

bool operator==(const EdwardPoint& P, const EdwardPoint& Q);

EdwardPoint G();

boost::multiprecision::uint256_t recover_x(boost::multiprecision::uint256_t y, uint8_t sign);

EdwardPoint decompress(boost::multiprecision::uint256_t y);

std::pair<boost::multiprecision::uint256_t, std::array<uint8_t, 32>> secret_expand(const std::array<uint8_t, 32>& k);

boost::multiprecision::uint256_t secret_to_public(const std::array<uint8_t, 32>& k);

std::array<uint8_t, 64> Ed25519_sign(const std::array<uint8_t, 32>& k, const std::vector<uint8_t>& message);

bool Ed25519_verify(const std::array<uint8_t, 32>& pub, const std::vector<uint8_t>& message, const std::array<uint8_t, 64>& signature);

#endif