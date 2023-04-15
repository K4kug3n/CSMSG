#include <Keys.hpp>

#include <CurveX25519.hpp>
#include <XEdDSA.hpp>
#include <Utility.hpp>

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

std::ostream& operator<<(std::ostream& stream, const PublicKey& key) {
	for (auto b : key.m_repr) {
		stream << int(b) << ", ";
	}

	return stream;
}

KeyPair::KeyPair(PrivateKey priv, PublicKey pub) :
	private_key(std::move(priv)), public_key(std::move(pub)) { }

std::array<uint8_t, 32> KeyPair::compute_key_agreement(const KeyPair& key) const {
	return private_key.compute_key_agreement(key.public_key);
}

KeyPair KeyPair::Generate() {
	PrivateKey priv{ random_bytes_array<32>() };
	PublicKey pub = priv.compute_public_key();

	return KeyPair{ std::move(priv), std::move(pub) };
}

PreKeyBundle::PreKeyBundle(const KeyPair& identity_key) :
	prekey(KeyPair::Generate()), one_time_prekey(KeyPair::Generate()) {
	const std::array<uint8_t, 32> prekey_bytes = prekey.public_key.to_bytes();

	prekey_signature = identity_key.private_key.compute_signature({ prekey_bytes.begin(), prekey_bytes.end() });
}
