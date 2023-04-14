#include <catch2/catch_test_macros.hpp>

#include <array>

#include <Keys.hpp>

TEST_CASE("Keys", "[Keys]") {
	SECTION("Public Key generation") {
		PrivateKey priv{ { 0, 142, 4, 173, 25, 26, 94, 45, 22, 142, 163, 230, 237, 29, 22, 200, 71, 53, 196, 75, 14, 213, 230, 178, 155, 129, 144, 109, 35, 49, 106, 108 } };
		PublicKey pub = priv.compute_public_key();

		REQUIRE(pub.to_bytes() == std::array<uint8_t, 32>{ { 72, 125, 132, 142, 92, 50, 52, 54, 60, 116, 221, 32, 192, 255, 34, 2, 173, 136, 36, 91, 49, 34, 245, 122, 214, 239, 156, 144, 112, 53, 174, 54 } });
	}
}

