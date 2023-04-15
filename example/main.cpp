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

	// Alice to Bob
	std::array<uint8_t, 32> DH1 = identity_key_A.compute_key_agreement(prekey_bundle_B.prekey);
	std::array<uint8_t, 32> DH2 = ephemeral_key_A.compute_key_agreement(identity_key_B);
	std::array<uint8_t, 32> DH3 = ephemeral_key_A.compute_key_agreement(prekey_bundle_B.prekey);
	std::array<uint8_t, 32> DH4 = ephemeral_key_A.compute_key_agreement(prekey_bundle_B.one_time_prekey);

	std::vector<uint8_t> DH = std::vector<uint8_t>(128, 0);
	std::copy(DH1.begin(), DH1.end(), DH.begin());
	std::copy(DH2.begin(), DH2.end(), DH.begin() + 32);
	std::copy(DH3.begin(), DH3.end(), DH.begin() + 64);
	std::copy(DH4.begin(), DH4.end(), DH.begin() + 96);

	std::array<uint8_t, 32> SK = KDF(DH);
}