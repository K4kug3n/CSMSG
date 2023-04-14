#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <array>

#include <Field.hpp>

TEST_CASE("Field Element", "[FieldElement]") {
	SECTION("Test Vector 1") {
		FieldElement x{ std::array<uint8_t, 32>{ 0xbb, 0x20, 0x68, 0x1, 0x4e, 0x1a, 0xf, 0x9c, 0xcc, 0xd0, 0x9a, 0x6, 0x88, 0xb8, 0x16, 0x43, 0x2e, 0xef, 0xa8, 0x1b, 0x89, 0xe3, 0x81, 0x60, 0x8e, 0x33, 0x44, 0x8d, 0xc5, 0x9f, 0x8, 0x5d } };
		FieldElement y{ std::array<uint8_t, 32>{ 0x49, 0x7d, 0x84, 0x8e, 0x5c, 0x32, 0x34, 0x36, 0x3c, 0x74, 0xdd, 0x20, 0xc0, 0xff, 0x22, 0x2, 0xad, 0x88, 0x24, 0x5b, 0x31, 0x22, 0xf5, 0x7a, 0xd6, 0xef, 0x9c, 0x90, 0x70, 0x35, 0xae, 0x36 } };
	
		std::array<uint8_t, 32> add = (x + y).to_bytes();
		std::array<uint8_t, 32> sub = (x - y).to_bytes();
		std::array<uint8_t, 32> prod = (x * y).to_bytes();
		std::array<uint8_t, 32> x_neg = (-x).to_bytes();
		std::array<uint8_t, 32> y_neg = (-y).to_bytes();

		REQUIRE(add == std::array<uint8_t, 32>{ 0x17, 0x9e, 0xec, 0x8f, 0xaa, 0x4c, 0x43, 0xd2, 0x8, 0x45, 0x78, 0x27, 0x48, 0xb8, 0x39, 0x45, 0xdb, 0x77, 0xcd, 0x76, 0xba, 0x5, 0x77, 0xdb, 0x64, 0x23, 0xe1, 0x1d, 0x36, 0xd5, 0xb6, 0x13 });
		REQUIRE(sub == std::array<uint8_t, 32>{ 0x72, 0xa3, 0xe3, 0x72, 0xf1, 0xe7, 0xda, 0x65, 0x90, 0x5c, 0xbd, 0xe5, 0xc7, 0xb8, 0xf3, 0x40, 0x81, 0x66, 0x84, 0xc0, 0x57, 0xc1, 0x8c, 0xe5, 0xb7, 0x43, 0xa7, 0xfc, 0x54, 0x6a, 0x5a, 0x26 });
		REQUIRE(prod == std::array<uint8_t, 32>{ 0x64, 0x5, 0xfb, 0x4, 0x1b, 0xa4, 0x2f, 0x17, 0xb8, 0x54, 0x2e, 0x77, 0xad, 0xd8, 0xf7, 0x83, 0xbe, 0x86, 0x4e, 0x7e, 0x4d, 0x3, 0x50, 0xe, 0xc0, 0x4e, 0xd0, 0x22, 0xc2, 0xd3, 0x2, 0x22 });
		REQUIRE(x_neg == std::array<uint8_t, 32>{ 0x32, 0xdf, 0x97, 0xfe, 0xb1, 0xe5, 0xf0, 0x63, 0x33, 0x2f, 0x65, 0xf9, 0x77, 0x47, 0xe9, 0xbc, 0xd1, 0x10, 0x57, 0xe4, 0x76, 0x1c, 0x7e, 0x9f, 0x71, 0xcc, 0xbb, 0x72, 0x3a, 0x60, 0xf7, 0x22 });
		REQUIRE(y_neg == std::array<uint8_t, 32>{ 0xa4, 0x82, 0x7b, 0x71, 0xa3, 0xcd, 0xcb, 0xc9, 0xc3, 0x8b, 0x22, 0xdf, 0x3f, 0x0, 0xdd, 0xfd, 0x52, 0x77, 0xdb, 0xa4, 0xce, 0xdd, 0xa, 0x85, 0x29, 0x10, 0x63, 0x6f, 0x8f, 0xca, 0x51, 0x49 });
	}

	
}

