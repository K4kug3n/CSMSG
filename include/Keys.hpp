#ifndef CSMSG_KEYS_HPP
#define CSMSG_KEYS_HPP

#include <array>
#include <vector>
#include <ostream>

class PublicKey {
public:
	PublicKey() = delete;
	PublicKey(std::array<uint8_t, 32> bytes);
	PublicKey(const PublicKey&) = default;
	PublicKey(PublicKey&&) = default;
	~PublicKey() = default;

	const std::array<uint8_t, 32>& to_bytes() const;
	bool verify_signature(const std::vector<uint8_t>& msg, const std::array<uint8_t, 64>& signature) const;

	PublicKey& operator=(const PublicKey&) = default;
	PublicKey& operator=(PublicKey&&) = default;

	friend std::ostream& operator<<(std::ostream& stream, const PublicKey& key);
	friend bool operator==(const PublicKey& lhs, const PublicKey& rhs);
	friend bool operator!=(const PublicKey& lhs, const PublicKey& rhs);

private:
	std::array<uint8_t, 32> m_repr;
};

class PrivateKey {
public:
	PrivateKey() = delete;
	PrivateKey(std::array<uint8_t, 32> bytes);
	PrivateKey(const PrivateKey&) = default;
	PrivateKey(PrivateKey&&) = default;
	~PrivateKey() = default;

	std::array<uint8_t, 32> compute_key_agreement(const PublicKey& key) const;
	PublicKey compute_public_key() const;
	std::array<uint8_t, 64> compute_signature(const std::vector<uint8_t>& msg) const;
	const std::array<uint8_t, 32>& to_bytes() const;

	PrivateKey& operator=(const PrivateKey&) = default;
	PrivateKey& operator=(PrivateKey&&) = default;

	friend std::ostream& operator<<(std::ostream& stream, const PrivateKey& key);
	friend bool operator==(const PrivateKey& lhs, const PrivateKey& rhs);
	friend bool operator!=(const PrivateKey& lhs, const PrivateKey& rhs);

private:
	std::array<uint8_t, 32> m_repr;
};

class KeyPair {
public:
	KeyPair() = delete;
	KeyPair(PrivateKey priv, PublicKey pub);
	KeyPair(const KeyPair&) = default;
	KeyPair(KeyPair&&) = default;
	~KeyPair() = default;

	std::array<uint8_t, 32> compute_key_agreement(const KeyPair& key) const;
	std::array<uint8_t, 32> compute_key_agreement(const PublicKey& key) const;

	PrivateKey private_key;
	PublicKey public_key;

	static KeyPair Generate();

	KeyPair& operator=(const KeyPair&) = default;
	KeyPair& operator=(KeyPair&&) = default;

	friend bool operator==(const KeyPair& lhs, const KeyPair& rhs);
	friend bool operator!=(const KeyPair& lhs, const KeyPair& rhs);
};

//class KeyBundle {
//public:
//	KeyBundle() = delete;
//	KeyBundle(const KeyBundle&) = default;
//	KeyBundle(KeyBundle&&) = default;
//	~KeyBundle() = default;
//
//	KeyBundle& operator=(const KeyBundle&) = default;
//	KeyBundle& operator=(KeyBundle&&) = default;
//};

class PreKeyBundle {
public:
	PreKeyBundle() = delete;
	PreKeyBundle(const KeyPair& identity_key);
	PreKeyBundle(const PreKeyBundle&) = default;
	PreKeyBundle(PreKeyBundle&&) = default;
	~PreKeyBundle() = default;

	KeyPair prekey;
	std::array<uint8_t, 64> prekey_signature;
	KeyPair one_time_prekey;

	PreKeyBundle& operator=(const PreKeyBundle&) = default;
	PreKeyBundle& operator=(PreKeyBundle&&) = default;
};

#endif