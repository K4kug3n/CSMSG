#include <Keys.hpp>

#include <CurveX25519.hpp>
#include <XEdDSA.hpp>
#include <X3DH.hpp>
#include <Utility.hpp>
#include <KDF.hpp>

PublicKey::PublicKey(std::array<uint8_t, 32> bytes) :
	m_repr(std::move(bytes)) { }

const std::array<uint8_t, 32>& PublicKey::to_bytes() const {
	return m_repr;
}

bool PublicKey::verify_signature(const std::vector<uint8_t>& msg, const std::array<uint8_t, 64>& signature) const {
	return XEdDSA_verify(m_repr, msg, signature);
}

PrivateKey::PrivateKey(std::array<uint8_t, 32> bytes) :
	m_repr(std::move(bytes)) {

	m_repr[0] &= 248;
	m_repr[31] &= 127;
	m_repr[31] |= 64;
}

std::array<uint8_t, 32> PrivateKey::compute_key_agreement(const PublicKey& key) const {
	return X25519(key.to_bytes(), m_repr);
}

PublicKey PrivateKey::compute_public_key() const {
	std::array<uint8_t, 32> pub = X25519(base_point_X25519(), m_repr);

	return PublicKey{ pub };
}

std::array<uint8_t, 64> PrivateKey::compute_signature(const std::vector<uint8_t>& msg) const {
	std::array<uint8_t, 64> nonce = random_bytes_array<64>();

	return XEdDSA_sign(m_repr, msg, nonce);
}

const std::array<uint8_t, 32>& PrivateKey::to_bytes() const {
	return m_repr;
}

std::ostream& operator<<(std::ostream& stream, const PrivateKey& key) {
	for (auto b : key.m_repr) {
		stream << int(b) << ", ";
	}

	return stream;
}

bool operator==(const PrivateKey& lhs, const PrivateKey& rhs) {
	return lhs.m_repr == rhs.m_repr;
}

bool operator!=(const PrivateKey& lhs, const PrivateKey& rhs) {
	return !(lhs == rhs);
}

bool operator==(const KeyPair& lhs, const KeyPair& rhs) {
	return (lhs.m_private_key == rhs.m_private_key) && (lhs.public_key == rhs.public_key);
}

bool operator!=(const KeyPair& lhs, const KeyPair& rhs) {
	return !(lhs == rhs);
}

std::ostream& operator<<(std::ostream& stream, const PublicKey& key) {
	for (auto b : key.m_repr) {
		stream << int(b) << ", ";
	}

	return stream;
}

bool operator==(const PublicKey& lhs, const PublicKey& rhs) {
	return lhs.m_repr == rhs.m_repr;
}

bool operator!=(const PublicKey& lhs, const PublicKey& rhs) {
	return !(lhs == rhs);
}

KeyPair::KeyPair(PrivateKey priv, PublicKey pub) :
	m_private_key(std::move(priv)), public_key(std::move(pub)) { }

std::array<uint8_t, 32> KeyPair::compute_key_agreement(const KeyPair& key) const {
	return m_private_key.compute_key_agreement(key.public_key);
}

std::array<uint8_t, 32> KeyPair::compute_key_agreement(const PublicKey& key) const {
	return m_private_key.compute_key_agreement(key);
}

std::array<uint8_t, 64> KeyPair::compute_signature(const std::vector<uint8_t>& msg) const {
	return m_private_key.compute_signature(msg);
}

KeyPair KeyPair::Generate() {
	PrivateKey priv{ random_bytes_array<32>() };
	PublicKey pub = priv.compute_public_key();

	return KeyPair{ std::move(priv), std::move(pub) };
}

KeyBundle KeyBundle::Generate() {
	KeyPair identity_key = KeyPair::Generate();
	KeyPair prekey = KeyPair::Generate();

	std::array<uint8_t, 32> prekey_bytes = prekey.public_key.to_bytes();
	std::array<uint8_t, 64> prekey_signature = identity_key.compute_signature({ prekey_bytes.begin(), prekey_bytes.end() });

	std::vector<KeyPair> onetime_prekeys;
	for(size_t i = 0; i < 3; ++i) {
		onetime_prekeys.push_back(KeyPair::Generate());
	}

	return KeyBundle{ std::move(identity_key), std::move(prekey) , std::move(prekey_signature) , std::move(onetime_prekeys) };
}

KeyBundle::KeyBundle(KeyPair identity, KeyPair prekey, std::array<uint8_t, 64> prekey_signature, std::vector<KeyPair> onetime_keys) :
	identity_key(std::move(identity)), prekey(std::move(prekey)),
	prekey_signature(std::move(prekey_signature)), onetime_prekeys(std::move(onetime_keys)),
	m_used_onetime_prekeys() { }

KeyPair KeyBundle::find_used_onetime_prekeys(const PublicKey& used_onetime_public_key) {
	for (const auto key_pair : m_used_onetime_prekeys) {
		if (key_pair.public_key == used_onetime_public_key) {
			return key_pair;
		}
	}

	throw std::runtime_error("onetime prekey not marked used");
}

SenderX3DHResult KeyBundle::compute_shared_secret(const PreKeyBundle& prekey_bundle) const {
	// X3DH protocol
	const std::array<uint8_t, 32>& prekey_bytes = prekey_bundle.prekey.to_bytes();
	if (!prekey_bundle.identity_key.verify_signature({ prekey_bytes.begin(), prekey_bytes.end() }, prekey_bundle.prekey_signature)) {
		throw std::runtime_error("Verify signature of prekey failed");
	}

	KeyPair ephemeral_key = KeyPair::Generate();

	const std::array<uint8_t, 32> DH1 = identity_key.compute_key_agreement(prekey_bundle.prekey);
	const std::array<uint8_t, 32> DH2 = ephemeral_key.compute_key_agreement(prekey_bundle.identity_key);
	const std::array<uint8_t, 32> DH3 = ephemeral_key.compute_key_agreement(prekey_bundle.prekey);

	std::vector<uint8_t> DH = std::vector<uint8_t>(96, 0);
	std::copy(DH1.begin(), DH1.end(), DH.begin());
	std::copy(DH2.begin(), DH2.end(), DH.begin() + 32);
	std::copy(DH3.begin(), DH3.end(), DH.begin() + 64);

	if(prekey_bundle.onetime_prekey) {
		const std::array<uint8_t, 32> DH4 = ephemeral_key.compute_key_agreement(prekey_bundle.onetime_prekey.value());
		DH.insert(DH.end(), DH4.begin(), DH4.end());
	}

	std::array<uint8_t, 64> AD = compute_additional_data(identity_key.public_key, prekey_bundle.identity_key);

	return SenderX3DHResult{ KDF(DH), std::move(AD), std::move(ephemeral_key.public_key) };
}

ReceiverX3DHResult KeyBundle::compute_shared_secret(const InitialMessage& intial_message) {
	// X3DH protocol 
	const std::array<uint8_t, 32> DH1 = prekey.compute_key_agreement(intial_message.identity_key);
	const std::array<uint8_t, 32> DH2 = identity_key.compute_key_agreement(intial_message.ephemeral_key);
	const std::array<uint8_t, 32> DH3 = prekey.compute_key_agreement(intial_message.ephemeral_key);
	
	std::vector<uint8_t> DH = std::vector<uint8_t>(96, 0);
	std::copy(DH1.begin(), DH1.end(), DH.begin());
	std::copy(DH2.begin(), DH2.end(), DH.begin() + 32);
	std::copy(DH3.begin(), DH3.end(), DH.begin() + 64);

	if (intial_message.used_onetime_prekey) {
		const KeyPair used_onetime_prekey = find_used_onetime_prekeys(intial_message.used_onetime_prekey.value());

		const std::array<uint8_t, 32> DH4 = used_onetime_prekey.compute_key_agreement(intial_message.ephemeral_key);
		DH.insert(DH.end(), DH4.begin(), DH4.end());
	}

	std::array<uint8_t, 64> AD = compute_additional_data(intial_message.identity_key, identity_key.public_key);

	return ReceiverX3DHResult{ KDF(DH), std::move(AD) };
}

PreKeyBundle KeyBundle::get_prekey_bundle() {	
	PublicKey public_identity_key = identity_key.public_key;
	PublicKey public_prekey = prekey.public_key;
	
	std::optional<PublicKey> public_onetime_prekey = std::nullopt;
	if(!onetime_prekeys.empty()) {
		KeyPair& onetime_prekey = onetime_prekeys.back();
		public_onetime_prekey = std::make_optional(onetime_prekey.public_key);
		
		m_used_onetime_prekeys.push_back(onetime_prekey);
		onetime_prekeys.pop_back();
	}
	
	return PreKeyBundle{ identity_key.public_key, prekey.public_key, prekey_signature, std::move(public_onetime_prekey) };
}

PreKeyBundle::PreKeyBundle(PublicKey identity, PublicKey prekey, std::array<uint8_t, 64> prekey_signature, std::optional<PublicKey> onetime_key) :
	identity_key(std::move(identity)), prekey(std::move(prekey)),
	prekey_signature(std::move(prekey_signature)), onetime_prekey(std::move(onetime_key)) { }
