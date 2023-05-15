#include <X3DH.hpp>

InitialMessage::InitialMessage(PublicKey identity_key, PublicKey ephemeral_key, const PreKeyBundle& prekey_bundle, Ratchet::EncryptedMessage message) :
	identity_key(std::move(identity_key)),
	ephemeral_key(std::move(ephemeral_key)),
	used_onetime_prekey(prekey_bundle.onetime_prekey),
	message(std::move(message)) { }
