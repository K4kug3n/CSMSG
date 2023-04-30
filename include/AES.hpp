#ifndef CSMSG_AES_HPP
#define CSMSG_AES_HPP

#include <array>
#include <vector>

std::array<uint8_t, 16> AES_block_encryption(const std::array<uint8_t, 16>& plaintext, const std::array<uint8_t, 32>& key);

std::array<uint8_t, 16> AES_block_decryption(const std::array<uint8_t, 16>& cyphertext, const std::array<uint8_t, 32>& key);

std::vector<uint8_t> CBC_AES_encryption(const std::vector<uint8_t>& msg, const std::array<uint8_t, 32>& key, std::array<uint8_t, 16> IV);

std::vector<uint8_t> CBC_AES_decryption(const std::vector<uint8_t>& cyphertext, const std::array<uint8_t, 32>& key);

#endif CSMSG_AES_HPP