#include <X3DH.hpp>

InitialMessage::InitialMessage(PublicKey identity_key, PublicKey ephemeral_key, const PreKeyBundle& prekey_bundle, Ratchet::EncryptedMessage message) :
	identity_key(std::move(identity_key)),
	ephemeral_key(std::move(ephemeral_key)),
	used_onetime_prekey(prekey_bundle.onetime_prekey),
	message(std::move(message)) { }

std::array<uint8_t, 64> compute_additional_data(const PublicKey& pub_key_A, const PublicKey& pub_key_B) {
	const std::array<uint8_t, 32>& bytes_A = pub_key_A.to_bytes();
	const std::array<uint8_t, 32>& bytes_B = pub_key_B.to_bytes();
	
	std::array<uint8_t, 64> AD;
	std::copy(bytes_A.begin(), bytes_A.end(), AD.begin());
	std::copy(bytes_B.begin(), bytes_B.end(), AD.begin() + 32);

	return AD;
}
