#include <iostream>

#include <Keys.hpp>
#include <KDF.hpp>
#include <X3DH.hpp>
#include <State.hpp>

void main() {
	KeyBundle key_bundle_A = KeyBundle::Generate();
	
	KeyBundle key_bundle_B = KeyBundle::Generate();
	PreKeyBundle prekey_bundle_B = key_bundle_B.get_prekey_bundle();

	// Alice side
	X3DHResult secret_A = key_bundle_A.compute_shared_secret(prekey_bundle_B);

	// Bob Side 
	//std::array<uint8_t, 32> DH1_B = prekey_bundle_B.prekey.compute_key_agreement(identity_key_A);
	//std::array<uint8_t, 32> DH2_B = identity_key_B.compute_key_agreement(ephemeral_key_A);
	//std::array<uint8_t, 32> DH3_B = prekey_bundle_B.prekey.compute_key_agreement(ephemeral_key_A);
	//std::array<uint8_t, 32> DH4_B = prekey_bundle_B.one_time_prekey.compute_key_agreement(ephemeral_key_A);

	/*std::vector<uint8_t> DH_B = std::vector<uint8_t>(128, 0);
	std::copy(DH1_B.begin(), DH1_B.end(), DH_B.begin());
	std::copy(DH2_B.begin(), DH2_B.end(), DH_B.begin() + 32);
	std::copy(DH3_B.begin(), DH3_B.end(), DH_B.begin() + 64);
	std::copy(DH4_B.begin(), DH4_B.end(), DH_B.begin() + 96);

	std::array<uint8_t, 32> SK_B = KDF(DH_B);*/

	std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

	Ratchet::State A_state = Ratchet::State::Init_alice(secret_A.shared_key, key_bundle_B.identity_key.public_key);
	Ratchet::State B_state = Ratchet::State::Init_bob(secret_A.shared_key /*SK_B*/, key_bundle_B.identity_key);

	Ratchet::EncryptedMessage encrypted_msg = A_state.encrypt(plaintext, secret_A.additional_data);

	std::vector<uint8_t> received = B_state.decrypt(encrypted_msg, secret_A.additional_data);

	for(size_t i = 0; i < received.size(); ++i) {
		std::cout << received[i] << std::endl;
	}
}