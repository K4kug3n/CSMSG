#include <State.hpp>

#include <cassert>

#include <KDF.hpp>
#include <AES.hpp>

namespace Ratchet {
	Header::Header(const KeyPair& dh_pair, uint8_t pn, uint8_t n) :
		public_key(dh_pair.public_key), previous_chain_length(pn), message_nb(n) {}

	std::array<uint8_t, 98> Header::Concatenate(const std::array<uint8_t, 64>& AD, const Header& header) {
		std::array<uint8_t, 98> res;
		std::copy(AD.begin(), AD.end(), res.begin());
		
		std::array<uint8_t, 32> public_key = header.public_key.to_bytes();
		std::copy(public_key.begin(), public_key.end(), res.begin() + 64);

		res[96] = header.previous_chain_length;
		res[97] = header.message_nb;

		return res;
	}

	std::vector<uint8_t> encrypt_algo(const std::array<uint8_t, 32>& mk, const std::vector<uint8_t>& plaintext, const std::array<uint8_t, 98>& associated_data) {
		std::vector<uint8_t> hkdf_result = HKDF(std::vector<uint8_t>(64, 0), { mk.begin(), mk.end() }, { 'E', 'N', 'C', 'M', 'S', 'G' }, 80);
		assert(hkdf_result.size() == 80);

		std::array<uint8_t, 32> encryption_key;
		std::copy(hkdf_result.begin(), hkdf_result.begin() + 32, encryption_key.begin());
		std::array<uint8_t, 32> authentification_key;
		std::copy(hkdf_result.begin() + 32, hkdf_result.begin() + 64, authentification_key.begin());
		std::array<uint8_t, 16> IV;
		std::copy(hkdf_result.begin() + 64, hkdf_result.end(), IV.begin());

		std::vector<uint8_t> ciphertext = CBC_AES_encryption(plaintext, encryption_key, IV);

		std::vector<uint8_t> hmac_input = ciphertext;
		hmac_input.insert(hmac_input.begin(), associated_data.begin(), associated_data.end());
		std::array<uint8_t, 64> hmac_result = HMAC_512({ authentification_key.begin(), authentification_key.end() }, hmac_input);

		ciphertext.insert(ciphertext.end(), hmac_result.begin(), hmac_result.end());

		return ciphertext;
	}

	std::vector<uint8_t> decrypt_algo(const std::array<uint8_t, 32>& mk, const std::vector<uint8_t>& complete_ciphertext, const std::array<uint8_t, 98>& associated_data) {
		std::vector<uint8_t> hkdf_result = HKDF(std::vector<uint8_t>(64, 0), { mk.begin(), mk.end() }, { 'E', 'N', 'C', 'M', 'S', 'G' }, 80);
		assert(hkdf_result.size() == 80);

		std::array<uint8_t, 32> encryption_key;
		std::copy(hkdf_result.begin(), hkdf_result.begin() + 32, encryption_key.begin());
		std::array<uint8_t, 32> authentification_key;
		std::copy(hkdf_result.begin() + 32, hkdf_result.begin() + 64, authentification_key.begin());
		
		std::vector<uint8_t> ciphertext{ complete_ciphertext.begin(), complete_ciphertext.end() - 64 }; // Extract ciphertext
		std::vector<uint8_t> plaintext = CBC_AES_decryption(ciphertext, encryption_key);

		std::array<uint8_t, 64> hmac_received;
		std::copy(complete_ciphertext.end() - 64, complete_ciphertext.end(), hmac_received.begin());

		std::vector<uint8_t> hmac_input = ciphertext;
		hmac_input.insert(hmac_input.begin(), associated_data.begin(), associated_data.end());
		std::array<uint8_t, 64> hmac_result = HMAC_512({ authentification_key.begin(), authentification_key.end() }, hmac_input);

		if (hmac_received != hmac_result) {
			throw std::runtime_error("hmac_received != hmac_result");
		}

		return plaintext;
	}

	State::State(KeyPair DH_sender) :
		DH_sender(std::move(DH_sender)), DH_receiver(std::nullopt),
		RK(std::nullopt),
		CK_sender(std::nullopt), CK_receiver(std::nullopt),
		N_sender(0), N_receiver(0), PN(0),
		MK_skipped() { }

	std::vector<uint8_t> State::decrypt(const Header& header, const std::vector<uint8_t>& ciphertext, const std::array<uint8_t, 64>& AD) {
		std::optional<std::vector<uint8_t>> plaintext = try_skipped_message_keys(header, ciphertext, AD);
		if (plaintext) {
			return plaintext.value();
		}

		if (header.public_key != DH_receiver.value_or(PublicKey{ std::array<uint8_t, 32>{} })) {
			skip_message_keys(header.previous_chain_length);
			dh_ratchet(header);
		}

		skip_message_keys(header.message_nb);

		std::array<uint8_t, 32> mk;
		std::pair<std::array<uint8_t, 32>&, std::array<uint8_t, 32>&>(CK_receiver.value(), mk) = KDF_CK(CK_receiver.value());
		N_receiver += 1;

		return decrypt_algo(mk, ciphertext, Header::Concatenate(AD, header));
	}

	std::pair<Header, std::vector<uint8_t>> State::encrypt(const std::vector<uint8_t>& plaintext, const std::array<uint8_t, 64>& AD) {
		std::array<uint8_t, 32> mk;
		std::pair<std::array<uint8_t, 32>&, std::array<uint8_t, 32>&>(CK_sender.value(), mk) = KDF_CK(CK_sender.value());

		Header header{ DH_sender, PN, N_sender };

		N_sender += 1;

		return std::pair<Header, std::vector<uint8_t>>{ header, encrypt_algo(mk, plaintext, Header::Concatenate(AD, header)) };
	}

	State Ratchet::State::Init_alice(std::array<uint8_t, 32> SK, PublicKey bob_public_key) {
		State state{ KeyPair::Generate() };
		
		std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 32>> kdf_rk_result = KDF_RK(SK, state.DH_sender.compute_key_agreement(bob_public_key));
		state.RK = std::make_optional(kdf_rk_result.first);
		state.CK_sender = std::make_optional(kdf_rk_result.second);
		state.DH_receiver = std::move(bob_public_key);

		return state;
	}

	State Ratchet::State::Init_bob(std::array<uint8_t, 32> SK, KeyPair bob_key_pair) {
		State state{ std::move(bob_key_pair) };
		state.RK = std::move(SK);

		return state;
	}

	void State::dh_ratchet(const Header& header) {
		PN = N_sender;
		N_sender = 0;
		N_receiver = 0;
		DH_receiver = header.public_key;
		std::pair<std::array<uint8_t, 32>&, std::array<uint8_t, 32>&>(RK.value(), CK_receiver.value()) = KDF_RK(RK.value(), DH_sender.compute_key_agreement(DH_receiver.value()));
		DH_sender = KeyPair::Generate();
		std::pair<std::array<uint8_t, 32>&, std::array<uint8_t, 32>&>(RK.value(), CK_sender.value()) = KDF_RK(RK.value(), DH_sender.compute_key_agreement(DH_receiver.value()));
	}

	void State::skip_message_keys(uint8_t until) {
		if (int(N_receiver) + int(MAX_SKIP) < until) {
			throw std::runtime_error("state.Nr + MAX_SKIP < until");
		}

		if (CK_receiver) {
			while (N_receiver << until) {
				std::array<uint8_t, 32> mk;
				std::pair<std::array<uint8_t, 32>&, std::array<uint8_t, 32>&>(CK_receiver.value(), mk) = KDF_CK(CK_receiver.value());
				MK_skipped[std::make_pair(DH_receiver.value().to_bytes(), N_receiver)] = mk;
				N_receiver += 1;
			}
		}
	}

	std::optional<std::vector<uint8_t>> State::try_skipped_message_keys(const Header& header, const std::vector<uint8_t>& ciphertext, const std::array<uint8_t, 64>& AD) {
		if (MK_skipped.count(std::make_pair(header.public_key.to_bytes(), header.message_nb))) {
			std::array<uint8_t, 32> mk = MK_skipped[std::make_pair(header.public_key.to_bytes(), header.message_nb)];
			MK_skipped.erase(std::make_pair(header.public_key.to_bytes(), header.message_nb));

			return decrypt_algo(mk, ciphertext, Header::Concatenate(AD, header));
		}

		return std::nullopt;
	}
}


