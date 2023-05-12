#include <iostream>

#include <Keys.hpp>
#include <KDF.hpp>
#include <State.hpp>

void main() {
	KeyBundle key_bundle_A = KeyBundle::Generate();
	
	KeyBundle key_bundle_B = KeyBundle::Generate();
	PreKeyBundle prekey_bundle_B = key_bundle_B.get_prekey_bundle();

	// Alice side
	std::array<uint8_t, 32> SK_A = key_bundle_A.compute_shared_secret(prekey_bundle_B);

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

	std::array<uint8_t, 64> AD;
	std::copy(key_bundle_A.identity_key.public_key.to_bytes().begin(), key_bundle_A.identity_key.public_key.to_bytes().end(), AD.begin());
	std::copy(key_bundle_B.identity_key.public_key.to_bytes().begin(), key_bundle_B.identity_key.public_key.to_bytes().end(), AD.begin() + 32);

	std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

	Ratchet::State A_state = Ratchet::State::Init_alice(SK_A, key_bundle_B.identity_key.public_key);
	Ratchet::State B_state = Ratchet::State::Init_bob(SK_A /*SK_B*/, key_bundle_B.identity_key);

	std::pair<Ratchet::Header, std::vector<uint8_t>> encryption_result = A_state.encrypt(plaintext, AD);

	std::vector<uint8_t> received = B_state.decrypt(encryption_result.first, encryption_result.second, AD);

	for(size_t i = 0; i < received.size(); ++i) {
		std::cout << received[i] << std::endl;
	}
}