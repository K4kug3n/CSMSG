#include <catch2/catch_test_macros.hpp>

#include <CurveX25519.hpp>

TEST_CASE("CurveX25519", "[X25519]") {
	SECTION("Test Vector 1") {
		std::array<uint8_t, 32> k = { 0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4 };
		std::array<uint8_t, 32> u = { 0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c };

		std::array<uint8_t, 32> res = X25519(u, k);

		REQUIRE(res == std::array<uint8_t, 32>{ { 0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x8, 0x4f, 0x32, 0xec, 0xcf, 0x3, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x7, 0x55, 0x77, 0xa2, 0x85, 0x52 } });
	}

	SECTION("Test Vector 2") {
		std::array<uint8_t, 32> k = { 0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d, 0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d };
		std::array<uint8_t, 32> u = { 0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38, 0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93 };

		std::array<uint8_t, 32> res = X25519(u, k);

		REQUIRE(res == std::array<uint8_t, 32>{ { 0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8, 0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57 } });
	}

	SECTION("Shared") {
		std::array<uint8_t, 32> base = { 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
		
		std::array<uint8_t, 32> A_private = { 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a };
		std::array<uint8_t, 32> A_public = X25519(base, A_private);
		REQUIRE(A_public == std::array<uint8_t, 32>{ { 0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a } });
	
		std::array<uint8_t, 32> B_private = { 0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb };
		std::array<uint8_t, 32> B_public = X25519(base, B_private);
		REQUIRE(B_public == std::array<uint8_t, 32>{ { 0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f } });
	
		std::array<uint8_t, 32> A_K = X25519(B_public, A_private);
		std::array<uint8_t, 32> B_K = X25519(A_public, B_private);
		std::array<uint8_t, 32> K = { 0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42 };
		REQUIRE(A_K == K);
		REQUIRE(B_K == K);
	}
}