#include <iostream>

#include <boost/multiprecision/cpp_int.hpp>

//#include <array>
//#include <random>
//#include <climits>

//unsigned char random_byte() {
//	std::random_device dev;
//	std::mt19937 rng{ dev() };
//	std::uniform_int_distribution<std::mt19937::result_type> dist(0, UCHAR_MAX);
//
//	return dist(rng);
//}
//
//void X25519(const std::array<unsigned char, 32>& scalar, unsigned int u) {
//
//}

struct Point {
	uint64_t x;
	uint64_t y;
};

template<typename T>
bool get_bit(T n, uint8_t k) {
	return (n & (1 << k)) >> k;
}

uint64_t point_compression(const Point& P) {
	return P.x;
}

Point point_decompression(uint64_t x) {
	return Point{ x, x * x * x + 486662 * x * x + x };
}

Point point_negation(const Point& P) {
	return Point{ P.x, -P.y };
}

Point point_add(const Point& P, const Point& Q) {
	uint64_t lambda = (Q.y - P.y) / (Q.x - P.x);

	Point R;
	R.x = lambda * lambda + P.x + Q.x;
	R.y = lambda * (P.x - R.x) - P.y;

	return R;
}

Point montgomery_ladder(uint64_t scalar, const Point& P) {
	Point R_0 = {0, 0}; // Change for ID point curve
	Point R_1 = P;

	for (size_t i = 0; i < 64; ++i) {
		if(get_bit(scalar, i)) {
			R_1 = point_add(R_0, R_1);
			R_0 = point_add(R_0, R_0);
		}
		else {
			R_0 = point_add(R_0, R_1);
			R_1 = point_add(R_1, R_1);
		}
	}

	return R_0;
}

void main() {
	/*std::array<unsigned char, 32> a;
	for (size_t i = 0; i < a.size(); ++i) {
		a[i] = random_byte();
	}*/

	std::cout << "Hello World" << std::endl;

	std::cout << get_bit<uint8_t>(0b11111110, 0) << std::endl;

	boost::multiprecision::int128_t my_128_bit_int;
}