#ifndef CSMSG_RATCHET_X3DH_HPP
#define CSMSG_RATCHET_X3DH_HPP

#include <array>
#include <Keys.hpp>

struct X3DHResult {
	std::array<uint8_t, 32> shared_key;
	std::array<uint8_t, 64> additional_data;
	PublicKey ephemeral_key;
};

#endif CSMSG_RATCHET_X3DH_HPP