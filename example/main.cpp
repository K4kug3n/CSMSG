#include <iostream>

#include <Keys.hpp>
#include <X3DH.hpp>
#include <Ratchet.hpp>
#include <Message.hpp>

int main() {
	KeyBundle key_bundle_A = KeyBundle::Generate();
	
	KeyBundle key_bundle_B = KeyBundle::Generate();
	PreKeyBundle prekey_bundle_B = key_bundle_B.get_prekey_bundle();

	// Alice side
	SenderX3DHResult secret_A = key_bundle_A.compute_shared_secret(prekey_bundle_B);

	Ratchet::State A_state = Ratchet::State::Init_sender(secret_A.shared_key, prekey_bundle_B.identity_key);

	Message plaintext{ "Hello" };
	Ratchet::EncryptedMessage encrypted_msg = A_state.encrypt(plaintext, secret_A.additional_data);

	InitialMessage intial_message{ key_bundle_A.identity_key.public_key, secret_A.ephemeral_key, prekey_bundle_B, encrypted_msg };

	// Bob Side 
	ReceiverX3DHResult secret_B = key_bundle_B.compute_shared_secret(intial_message);

	Ratchet::State B_state = Ratchet::State::Init_receiver(secret_B.shared_key, key_bundle_B.identity_key);

	Message received = B_state.decrypt(encrypted_msg, secret_B.additional_data);
	std::cout << received << std::endl;

	Message plaintext_2{ "World" };
	Ratchet::EncryptedMessage encrypted_msg_2 = B_state.encrypt(plaintext_2, secret_B.additional_data);

	Message received_2 = A_state.decrypt(encrypted_msg_2, secret_A.additional_data);
	std::cout << received_2 << std::endl;

	return 0;
}