#ifndef CSMSG_SHA_HPP
#define CSMSG_SHA_HPP

#include <vector>
#include <array>

std::array<uint64_t, 8> SHA_512(const std::vector<uint8_t>& message);

#endif