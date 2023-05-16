#include <catch2/catch_test_macros.hpp>

#include <SHA.hpp>

TEST_CASE("SHA512", "[SHA512]") {
	SECTION("Test Vector 1") {
		std::array<uint64_t, 8> res = SHA_512({ 'a', 'b', 'c' });

		REQUIRE(res == std::array<uint64_t, 8>{ { 0xDDAF35A193617ABA, 0xCC417349AE204131, 0x12E6FA4E89A97EA2, 0x0A9EEEE64B55D39A, 0x2192992A274FC1A8, 0x36BA3C23A3FEEBBD, 0x454D4423643CE80E, 0x2A9AC94FA54CA49F } });
	}

	SECTION("Test Vector 2") {
		std::array<uint64_t, 8> res = SHA_512({ 
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
			'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
			'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
			'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
			'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
			'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
			'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
			'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
			'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
			'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
			'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
			'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u'
		});

		REQUIRE(res == std::array<uint64_t, 8>{ { 0x8E959B75DAE313DA, 0x8CF4F72814FC143F, 0x8F7779C6EB9F7FA1, 0x7299AEADB6889018, 0x501D289E4900F7E4, 0x331B99DEC4B5433A, 0xC7D329EEB6DD2654, 0x5E96E55B874BE909 } });
	}
}

