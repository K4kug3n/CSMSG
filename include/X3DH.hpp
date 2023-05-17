#ifndef CSMSG_X3DH_HPP
#define CSMSG_X3DH_HPP

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
	InitialMessage() = delete;
	InitialMessage(PublicKey identity_key, PublicKey ephemeral_key, const PreKeyBundle& prekey_bundle, Ratchet::EncryptedMessage message);
	InitialMessage(const InitialMessage&) = default;
	InitialMessage(InitialMessage&&) = default;

	PublicKey identity_key;
	PublicKey ephemeral_key;
	std::optional<PublicKey> used_onetime_prekey;

	Ratchet::EncryptedMessage message;

	InitialMessage& operator=(const InitialMessage&) = default;
	InitialMessage& operator=(InitialMessage&&) = default;
};

std::array<uint8_t, 64> compute_additional_data(const PublicKey& pub_key_A, const PublicKey& pub_key_B);

#endif