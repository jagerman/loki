#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace oxen::sent::devnet {
extern const std::unordered_map<std::string, std::string> addresses;
extern const std::pair<std::uint8_t, std::uint8_t> conv_ratio;
extern const std::unordered_map<std::string, std::uint64_t> transition_bonus;
}  // namespace oxen::sent::devnet

namespace oxen::sent::testnet {
extern const std::unordered_map<std::string, std::string> addresses;
extern const std::pair<std::uint8_t, std::uint8_t> conv_ratio;
extern const std::unordered_map<std::string, std::uint64_t> transition_bonus;
}  // namespace oxen::sent::testnet

namespace oxen::sent::mainnet {
extern const std::unordered_map<std::string, std::string> addresses;
extern const std::pair<std::uint8_t, std::uint8_t> conv_ratio;
extern const std::unordered_map<std::string, std::uint64_t> transition_bonus;
}  // namespace oxen::sent::mainnet
