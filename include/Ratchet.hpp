#ifndef CSMSG_RATCHET_HPP
#define CSMSG_RATCHET_HPP

#include <Keys.hpp>

#include <array>
#include <optional>
#include <map>

class Message;

namespace Ratchet {
	class Header {
	public:
		Header() = delete;
		Header(const KeyPair& dh_pair, uint8_t pn, uint8_t n);
		Header(const Header&) = default;
		Header(Header&&) = default;

		static std::array<uint8_t, 98> Concatenate(const std::array<uint8_t, 64>& AD, const Header& header);

		PublicKey public_key;
		uint8_t previous_chain_length;
		uint8_t message_nb;

		Header& operator=(const Header&) = default;
		Header& operator=(Header&&) = default;
	};

	struct EncryptedMessage {
		Header header;
		std::vector<uint8_t> ciphertext;
	};

	class State {
	public:
		State() = delete;
		State(KeyPair DH_self);
		State(const State&) = default;
		State(State&&) = default;

		Message decrypt(const EncryptedMessage& message, const std::array<uint8_t, 64>& AD);
		EncryptedMessage encrypt(const Message& plaintext, const std::array<uint8_t, 64>& AD);

		static State Init_sender(std::array<uint8_t, 32> SK, PublicKey bob_public_key);
		static State Init_receiver(std::array<uint8_t, 32> SK, KeyPair bob_key_pair);
		static constexpr uint8_t MAX_SKIP = 10;

		State& operator=(const State&) = default;
		State& operator=(State&&) = default;

	private:
		void dh_ratchet(const Header& header);
		void skip_message_keys(uint8_t until);
		std::optional<std::vector<uint8_t>> try_skipped_message_keys(const Header& header, const std::vector<uint8_t>& ciphertext, const std::array<uint8_t, 64>& AD);
	
		KeyPair m_DH_self;
		std::optional<PublicKey> m_DH_receiver;
		std::optional<std::array<uint8_t, 32>> m_RK;

		std::optional<std::array<uint8_t, 32>> m_CK_sender;
		std::optional<std::array<uint8_t, 32>> m_CK_receiver;

		uint8_t m_N_sender;
		uint8_t m_N_receiver;
		uint8_t m_PN;

		std::map<std::pair<std::array<uint8_t, 32>, uint8_t>, std::array<uint8_t, 32>> m_MK_skipped;
	};
}

#endif