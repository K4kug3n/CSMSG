#include <iostream>

#include <Keys.hpp>

void main() {
	std::vector<uint8_t> msg = { 0x72 };
	
	KeyPair pair = KeyPair::Generate();
	std::array<uint8_t, 64> signature = pair.private_key.compute_signature(msg);

	std::cout << pair.public_key.verify_signature(msg, signature) << " " << true << std::endl;
}