// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <algorithm>
#include <cstdio>

#include "common/oxen.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "blockchain_db/blockchain_db.h"
#include "hardfork.h"
#include "version.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "hardfork"

namespace cryptonote {

// version 7 from the start of the blockchain, inhereted from Monero mainnet
static constexpr std::array mainnet_hard_forks =
{
  hard_fork{{7,0},         1, 1503046577 }, // Loki 0.1: Loki is born
  hard_fork{{8,0},     64324, 1533006000 /*2018-07-31 03:00 UTC*/ }, // Loki 0.2: New emissions schedule
  hard_fork{{9,0},    101250, 1537444800 /*2018-09-20 12:00 UTC*/ }, // Loki 1: Service nodes launched
  hard_fork{{10,0},   161849, 1544743800 /*2018-12-13 23:30 UTC*/ }, // Loki 2: Bulletproofs, gov fee batching
  hard_fork{{11,0},   234767, 1554170400 /*2019-03-26 13:00 AEDT*/ }, // Loki 3: Infinite staking, CN-Turtle
  hard_fork{{12,0},   321467, 1563940800 /*2019-07-24 14:00 AEDT*/ }, // Loki 4: Checkpointing, RandomXL, decommissioning, Storage Server launched
  hard_fork{{13,0},   385824, 1571850000 /*2019-10-23 19:00 AEDT*/ }, // Loki 5: Checkpointing enforced
  hard_fork{{14,0},   442333, 1578528000 /*2020-01-09 00:00 UTC*/ }, // Loki 6: Blink, Lokinet launched on mainnet
  hard_fork{{15,0},   496969, 1585105200 /*2020-03-25 14:00 AEDT (03:00 UTC)*/ }, // Loki 7: ONS (Session)
  hard_fork{{16,0},   641111, 1602464400 /*2020-10-12 12:00 AEDT (01:00 UTC)*/ }, // Loki 8: Pulse
  hard_fork{{17,0},   770711, 1618016400 /*Saturday, April 10, 2021 1:00:00 UTC*/ },  // Oxen 8: Eliminate 6/block emissions after 180 days (not a separate release)
  hard_fork{{18,0},   785000, 1619736143 /*Thursday, April 29, 2021 22:42:23 UTC*/ }, // Oxen 9: Timesync, new proofs, reasons, wallet ONS
//hard_fork{{19,32},  ??????, ?????????? /*?????????????????????????????????????*/ }, // Oxen 10: Magic
};

static constexpr std::array testnet_hard_forks =
{
  hard_fork{{7,0},         1, 1533631121 }, // Testnet was rebooted during Loki 3 development
  hard_fork{{8,0},         2, 1533631122 },
  hard_fork{{9,0},         3, 1533631123 },
  hard_fork{{10,0},        4, 1542681077 },
  hard_fork{{11,0},        5, 1551223964 },
  hard_fork{{12,0},    75471, 1561608000 }, // 2019-06-28 14:00 AEDT
  hard_fork{{13,0},   127028, 1568440800 }, // 2019-09-13 16:00 AEDT
  hard_fork{{14,0},   174630, 1575075600 }, // 2019-11-30 07:00 UTC
  hard_fork{{15,0},   244777, 1583940000 }, // 2020-03-11 15:20 UTC
  hard_fork{{16,0},   382222, 1600468200 }, // 2020-09-18 22:30 UTC
  hard_fork{{17,0},   447275, 1608276840 }, // 2020-12-18 05:34 UTC
  hard_fork{{18,0},   501750, 1616631051 }, // 2021-03-25 12:10 UTC
  hard_fork{{19,0},   551773, 1621375273 }, // 2021-05-18 FIXME TODO finalize this!
};

static constexpr std::array devnet_hard_forks =
{
  hard_fork{{7,0},         1, 1599848400 },
  hard_fork{{16,0},        2, 1599848400 }, // 2020-09-11 18:20 UTC
};

template <size_t N>
static constexpr bool is_ordered(const std::array<hard_fork, N>& forks, bool mainnet = true) {
  if (N == 0 || forks[0].version < network_version{7,0})
    return false;
  for (size_t i = 1; i < N; i++) {
    auto& hf = forks[i];
    auto& prev = forks[i-1];
    if ( // On mainnet: major version must be > prev major version; on testnet major.minor must be > prev major.minor
        (mainnet ? hf.version.first <= prev.version.first : hf.version <= prev.version)
        || hf.height <= prev.height || hf.time < prev.time)
      return false;
  }
  return true;
}

template <size_t N>
static constexpr bool no_mainnet_hardfork_versions(const std::array<hard_fork, N>& forks) {
  for (auto& hf : forks)
    if (hf.version.second >= 32)
      return false;
  return true;
}

static_assert(is_ordered(mainnet_hard_forks),
    "Invalid mainnet hard forks: version must start at 7, major versions and heights must be strictly increasing, and timestamps must be non-decreasing");
static_assert(is_ordered(testnet_hard_forks, false) && no_mainnet_hardfork_versions(testnet_hard_forks),
    "Invalid testnet hard forks: version must start at 7, versions and heights must be strictly increasing, and timestamps must be non-decreasing");
static_assert(is_ordered(devnet_hard_forks, false) && no_mainnet_hardfork_versions(devnet_hard_forks),
    "Invalid devnet hard forks: version must start at 7, versions and heights must be strictly increasing, and timestamps must be non-decreasing");

std::vector<hard_fork> fakechain_hardforks;

std::pair<const hard_fork*, const hard_fork*> get_hard_forks(network_type type)
{
  if (type == network_type::MAINNET) return {&mainnet_hard_forks[0], &mainnet_hard_forks[mainnet_hard_forks.size()]};
  if (type == network_type::TESTNET) return {&testnet_hard_forks[0], &testnet_hard_forks[testnet_hard_forks.size()]};
  if (type == network_type::DEVNET) return {&devnet_hard_forks[0], &devnet_hard_forks[devnet_hard_forks.size()]};
  if (type == network_type::FAKECHAIN) return {fakechain_hardforks.data(), fakechain_hardforks.data() + fakechain_hardforks.size()};
  return {nullptr, nullptr};
}

std::pair<std::optional<uint64_t>, std::optional<uint64_t>> get_hard_fork_heights(network_type nettype, network_version version) {
  std::pair<std::optional<uint64_t>, std::optional<uint64_t>> found;
  for (auto [it, end] = get_hard_forks(nettype); it != end; it++) {
    if (it->version > version) { // This (and anything else) are in the future
      if (found.first) // Found something suitable in the previous iteration, so one before this hf is the max
        found.second = it->height - 1;
      break;
    } else if (it->version.first == version.first) {
      // We found a version with the same major version and isn't >, so this is a valid starting
      // height (but possibly a later fork on the same major version -- e.g. for testnet -- might
      // overwrite this, which is fine, because testnet has minor version hardforks).
      found.first = it->height;
    }
  }
  return found;
}

network_version hard_fork_ceil(network_type nettype, network_version version) {
  auto [it, end] = get_hard_forks(nettype);
  for (; it != end; it++)
    if (it->version >= version)
      return it->version;

  // We didn't find any enabling hardfork, so return the requested version plus 1
  if (nettype == network_type::MAINNET) {
    if (std::prev(end)->version.first == version.first)
      return {version.first + 1, 0}; // There can't be another hf with the same major version on mainnet
    else
      return version; // We don't know for sure but it *could* be a hard fork.
  } else {
    // testnet: 
    return {version.first, version.second+1};
  }
}

// We use a varint to encode the block version values which requires >1 byte for values above 127,
// so use 127 as our max to signal a "waiting for the next major hardfork".
inline constexpr uint8_t MAX_MINOR = 127;

std::pair<network_version, network_version>
get_network_versions_for_height(network_type nettype, uint64_t height)
{
  std::pair<network_version, network_version> result{{7,0}, {7,MAX_MINOR}};
  auto& [from, to] = result;

  auto [it, end] = get_hard_forks(nettype);
  for (; it != end; it++) {
    if (height >= it->height) {
      from = it->version;
      auto next = std::next(it);
      to =
        next != end ? std::min<network_version>({next->version.first, next->version.second-1}, {from.first, MAX_MINOR}) :
        nettype == network_type::MAINNET ? network_version{from.first, MAX_MINOR} :
        from;
      break;
    }
  }
  return result;
}

bool is_hard_fork_at_least(network_type type, network_version version, uint64_t height) {
  auto [min, max] = get_network_versions_for_height(type, height);
  return min >= version;
}

bool is_hard_fork_beyond(network_type type, network_version version, uint64_t height) {
  auto [min, max] = get_network_versions_for_height(type, height);
  return version > max;
}

network_version
get_ideal_network_version(network_type nettype, uint64_t height)
{
  auto [min, max] = get_network_versions_for_height(nettype, height);
  if (nettype != network_type::MAINNET)
    return max;
  if (mainnet_hard_forks.back().version == min)
    // We are on the top mainnet hardfork, so ideal is that major version and 32*min+patch for minor
    // version.
    return {min.first, std::max<uint8_t>(min.second, OXEN_VERSION[1]*32 + OXEN_VERSION[2])};

  // Otherwise we know about a hard fork but haven't yet switched to it, so use the maximum
  // pre-hard-fork permitted major/minor version (which will be something like 20.127):
  return max;
}

}
