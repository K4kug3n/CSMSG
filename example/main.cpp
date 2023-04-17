#include <iostream>

#include <Keys.hpp>
#include <KDF.hpp>

void main() {
	KeyPair identity_key_A = KeyPair::Generate();
	KeyPair ephemeral_key_A = KeyPair::Generate();
	PreKeyBundle prekey_bundle_A{ identity_key_A };

	KeyPair identity_key_B = KeyPair::Generate();
	KeyPair ephemeral_key_B = KeyPair::Generate();
	PreKeyBundle prekey_bundle_B{ identity_key_B };

	// Alice side
	std::array<uint8_t, 32> DH1_A = identity_key_A.compute_key_agreement(prekey_bundle_B.prekey);
	std::array<uint8_t, 32> DH2_A = ephemeral_key_A.compute_key_agreement(identity_key_B);
	std::array<uint8_t, 32> DH3_A = ephemeral_key_A.compute_key_agreement(prekey_bundle_B.prekey);
	std::array<uint8_t, 32> DH4_A = ephemeral_key_A.compute_key_agreement(prekey_bundle_B.one_time_prekey);

	std::vector<uint8_t> DH_A = std::vector<uint8_t>(128, 0);
	std::copy(DH1_A.begin(), DH1_A.end(), DH_A.begin());
	std::copy(DH2_A.begin(), DH2_A.end(), DH_A.begin() + 32);
	std::copy(DH3_A.begin(), DH3_A.end(), DH_A.begin() + 64);
	std::copy(DH4_A.begin(), DH4_A.end(), DH_A.begin() + 96);

	std::array<uint8_t, 32> SK_A = KDF(DH_A);

	// Bob Side 
	std::array<uint8_t, 32> DH1_B = prekey_bundle_B.prekey.compute_key_agreement(identity_key_A);
	std::array<uint8_t, 32> DH2_B = identity_key_B.compute_key_agreement(ephemeral_key_A);
	std::array<uint8_t, 32> DH3_B = prekey_bundle_B.prekey.compute_key_agreement(ephemeral_key_A);
	std::array<uint8_t, 32> DH4_B = prekey_bundle_B.one_time_prekey.compute_key_agreement(ephemeral_key_A);

	std::vector<uint8_t> DH_B = std::vector<uint8_t>(128, 0);
	std::copy(DH1_B.begin(), DH1_B.end(), DH_B.begin());
	std::copy(DH2_B.begin(), DH2_B.end(), DH_B.begin() + 32);
	std::copy(DH3_B.begin(), DH3_B.end(), DH_B.begin() + 64);
	std::copy(DH4_B.begin(), DH4_B.end(), DH_B.begin() + 96);

	std::array<uint8_t, 32> SK_B = KDF(DH_B);

	std::cout << (SK_A == SK_B) << " " << true << std::endl;
}