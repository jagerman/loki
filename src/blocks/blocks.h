#pragma once

#include "cryptonote_config.h"
#include <string_view>

namespace blocks
{

using namespace std::literals;

template <cryptonote::network_type Network> std::string_view checkpoint_data() { return ""sv; }
template<> std::string_view checkpoint_data<cryptonote::network_type::MAINNET>();
template<> std::string_view checkpoint_data<cryptonote::network_type::STAGENET>();
template<> std::string_view checkpoint_data<cryptonote::network_type::TESTNET>();

inline std::string_view GetCheckpointsData(cryptonote::network_type network)
{
    if (network == cryptonote::network_type::MAINNET) return checkpoint_data<cryptonote::network_type::MAINNET>();
    if (network == cryptonote::network_type::TESTNET) return checkpoint_data<cryptonote::network_type::TESTNET>();
    if (network == cryptonote::network_type::STAGENET) return checkpoint_data<cryptonote::network_type::STAGENET>();
    return ""sv;
}

}
