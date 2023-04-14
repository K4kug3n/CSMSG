#include <Utility.hpp>

#include <random>

template<std::size_t N>
inline std::array<uint8_t, N> random_bytes_array() {
	std::random_device dev;
	std::mt19937 rng{ dev() };
	std::uniform_int_distribution<std::mt19937::result_type> dist{ 0, UCHAR_MAX };

	std::array<uint8_t, N> bytes;
	for (size_t i = 0; i < bytes.size(); ++i) {
		bytes[i] = dist(rng);
	}

	return bytes;
}

template<typename T1, typename T2>
inline T1 pos_mod(const T1& x, const T2& p) {
	return ((x % p) + p) % p;
}
