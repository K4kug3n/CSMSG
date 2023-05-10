#ifndef CSMSG_RATCHET_STATE_HPP
#define CSMSG_RATCHET_STATE_HPP

#include <Keys.hpp>

#include <array>
#include <optional>
#include <map>

namespace Ratchet {

	class Header {
	public:
		Header(const KeyPair& dh_pair, uint8_t pn, uint8_t n);

		static std::array<uint8_t, 98> Concatenate(const std::array<uint8_t, 64>& AD, const Header& header);

		PublicKey public_key;
		uint8_t previous_chain_length;
		uint8_t message_nb;
	};

	class State {
	public:
		State() = delete;
		State(KeyPair DH_sender);

		std::vector<uint8_t> decrypt(const Header& header, const std::vector<uint8_t>& complete_ciphertext, const std::array<uint8_t, 64>& AD);
		std::pair<Header, std::vector<uint8_t>> encrypt(const std::vector<uint8_t>& plaintext, const std::array<uint8_t, 64>& AD);

		KeyPair DH_sender;
		std::optional<PublicKey> DH_receiver;
		std::optional<std::array<uint8_t, 32>> RK;

		std::optional<std::array<uint8_t, 32>> CK_sender;
		std::optional<std::array<uint8_t, 32>> CK_receiver;

		uint8_t N_sender;
		uint8_t N_receiver;
		uint8_t PN;

		std::map<std::pair<std::array<uint8_t, 32>, uint8_t>, std::array<uint8_t, 32>> MK_skipped;

		static State Init_alice(std::array<uint8_t, 32> SK, PublicKey bob_public_key);
		static State Init_bob(std::array<uint8_t, 32> SK, KeyPair bob_key_pair);
		static constexpr uint8_t MAX_SKIP = 10;

	private:
		void dh_ratchet(const Header& header);
		void skip_message_keys(uint8_t until);
		std::optional<std::vector<uint8_t>> try_skipped_message_keys(const Header& header, const std::vector<uint8_t>& ciphertext, const std::array<uint8_t, 64>& AD);
	};
}

#endif CSMSG_RATCHET_STATE_HPP