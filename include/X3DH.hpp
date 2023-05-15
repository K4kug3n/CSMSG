#ifndef CSMSG_RATCHET_X3DH_HPP
#define CSMSG_RATCHET_X3DH_HPP

#include <array>
#include <Keys.hpp>
#include <Ratchet.hpp>

struct SenderX3DHResult {
	std::array<uint8_t, 32> shared_key;
	std::array<uint8_t, 64> additional_data;
	PublicKey ephemeral_key;
};

struct ReceiverX3DHResult {
	std::array<uint8_t, 32> shared_key;
	std::array<uint8_t, 64> additional_data;
};


class InitialMessage {
public:
	InitialMessage(PublicKey identity_key, PublicKey ephemeral_key, const PreKeyBundle& prekey_bundle, Ratchet::EncryptedMessage message);

	PublicKey identity_key;
	PublicKey ephemeral_key;
	std::optional<PublicKey> used_onetime_prekey;

	Ratchet::EncryptedMessage message;
};

#endif CSMSG_RATCHET_X3DH_HPP