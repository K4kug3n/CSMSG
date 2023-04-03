#include <iostream>

#include <CurveX25519.hpp>

void main() {
	KeyPair key_pair = generate_key_pair_X25519();

	for (size_t i = 0; i < key_pair.public_key.size(); ++i) {
		std::cout << std::hex << int(key_pair.public_key[i]) << " ";
	}

	std::cout << std::endl;

	for (size_t i = 0; i < key_pair.private_key.size(); ++i) {
		std::cout << std::hex << int(key_pair.private_key[i]) << " ";
	}
}