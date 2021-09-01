// Copyright (c) 2014-2019, The Monero Project
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

#pragma once

#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote
{
  // Defines where hard fork (i.e. new minimum network versions) begin: all blocks must be >=
  // `version` beginning at height `height`, estimated to arrive at `time`.
  struct hard_fork {
    network_version version;
    uint64_t height;
    time_t time;
  };

  // Stick your fake hard forks in here if you're into that sort of thing.
  extern std::vector<hard_fork> fakechain_hardforks;

  // Returns an iteratable range over hard fork values for the given network.
  std::pair<const hard_fork*, const hard_fork*> get_hard_forks(network_type type);

  // Returns the height range for which the given block/network version is valid.  Returns a pair of
  // heights {A, B} where A/B is the first/last height at which the version is acceptable.  Returns
  // nullopt for A if the version indicates a hardfork we do not know about (i.e. we are likely
  // outdated), and returns nullopt for B if the version indicates that top network version we know
  // about (i.e. there is no subsequent hardfork scheduled).
  //
  // Note that network versions with a minor version less than the first major version are never
  // valid and will return std::nullopt for both arguments (for example, when the first 20.x hard
  // fork is at 20.32 then 20.19 returns a nullopt pair).
  std::pair<std::optional<uint64_t>, std::optional<uint64_t>>
  get_hard_fork_heights(network_type type, network_version version);

  // Returns the smallest hardfork network version not less than the given version.  In other words,
  // this gives the minimum network/block version at which the given version becomes guaranteed
  // supported by all nodes on the network.  This is particularly useful for feature testing: some
  // feature introduced in the dev version 10.0.3 (network version 19.3) first becomes available on
  // mainnet at the 10.1.0 mainnet hardfork (network version 19.32).
  //
  // If there is no known next hard fork enabling the given feature, this returns the next version at
  // which there *could* be a hard fork.  For mainnet, this is the version itself if there is no
  // hardfork with the same major version at all, or (currentmajor+1).0 if there is a major version
  // hardfork but with an earlier minor version.  For testnet, this is always the requested version
  // (since it could be a hardfork).
  //
  // For example, if there are hardforks at 19.32, 20.33, and 21.32 then:
  //     hard_fork_ceil(19.31) = 19.32
  //     hard_fork_ceil(19.32) = 19.32
  //     hard_fork_ceil(19.35) = 20.33
  //     hard_fork_ceil(20.0) = 20.33
  //     hard_fork_ceil(20.32) = 20.33
  //     hard_fork_ceil(20.33) = 20.33
  //     hard_fork_ceil(20.34) = 21.32
  //     hard_fork_ceil(21.32) = 21.32
  //     hard_fork_ceil(21.33) = 22.0 # No hardfork >= 21.33 is known, but we have a 21.x hard fork so 22.0 is the earlier possible enabling hard fork.
  //     hard_fork_ceil(22.7) = 22.7 # We don't know when the 22.7 hardfork occurs, but it *could* be at 22.7.
  // etc.
  network_version hard_fork_ceil(network_state net);

  // Returns the largest hardfork network version not greater than the given version.  In other
  // words, given a network/block version, this gives the largest network version that we know about
  // that is guaranteed to be supported by the network *given* that we are on the provided
  // `version`.
  //
  // For example, if there are hardforks at 19.32, 20.33, and 21.32 then:
  //     hard_fork_floor(19.32) = 19.32
  //     hard_fork_floor(19.35) = 19.32
  //     hard_fork_floor(20.32) = 19.32
  //     hard_fork_floor(20.33) = 20.33
  //     hard_fork_floor(20.34) = 20.33
  //     hard_fork_floor(21.32) = 21.32
  //     hard_fork_floor(57.0) = 21.32  # The largest HF we know about.
  network_version hard_fork_floor(network_state net);

  // Returns true if `needed` is enabled by the network given an active network version of `given`.
  // This is conceptually similar to `given >= needed` but with hard-fork granularity:
  // - `needed` gets rounded *up* (via hard_fork_ceil) to the next hardfork
  // - `given` gets rounded *down* (via hard_fork_floor) to the last hardfork
  //
  // This differs from a simpler inequality in some exceptional cases, e.g.:
  // - hardfork @ 20.32, needed=20.33, given=20.34 -- returns false because 20.33 features are not
  // guaranteed until the following hard fork.
  // 
  inline bool is_network_version_enabled(network_version needed, network_state given) {
    return hard_fork_ceil({given.first, needed}) <= hard_fork_floor(given);
  }

  // Returns true if `needed` is enabled by the network given an active network version of `given`
  // and that it is still on the same hard fork.  Essentially equivalent to
  // `is_network_version_enabled(needed, given) && !is_network_version_enabled(NEXT, given)` where
  // NEXT is the next hardfork after the one that first enables `needed`.
  inline bool is_network_version_only(network_version needed, network_state given) {
      return hard_fork_floor({given.first, needed}) == hard_fork_floor(given);
  }

  // Returns true if the given height is sufficiently high to be at or after the hard fork height
  // that enable the given network version features.
  bool is_hard_fork_at_least(network_type type, network_version version, uint64_t height);

  // Returns true if the given height is sufficiently high to be at least one hardfork *beyond* the
  // one where the given network version became universally supported.  E.g. if there is a hardfork
  // at 19.7 and 20.3 then this would start returning true at the 20.3 fork height for network
  // versions 19.6, 19.7 (but not 19.8 which isn't guaranteed to be supported everywhere on the
  // network until the 20.3 fork height).
  bool is_hard_fork_beyond(network_type type, network_version version, uint64_t height);

  // Returns true if the current network state `curr` is at least one hard fork beyond the hard fork
  // that enabled `version`.  Equivalent to `hard_fork_floor(curr) > hard_fork_floor(version)`.
  inline bool is_hard_fork_beyond(network_version version, network_state curr) {
      return hard_fork_floor(curr) > hard_fork_floor({curr.first, version});
  }

  // Returns the minimum and maximum network versions acceptable for the given height.  For mainnet,
  // where there can only be one hardfork per major version, this will be something like
  // {19.32,19.127} (e.g. accept all 19.x blocks >= 19.32).  (The .32 is because, typically, the
  // mainnet fork comes in the x.1.0 release which yields a minor version of 32).
  //
  // For testnet/devnet this is a bit more complicated:
  // - if the current x.y is the highest HF we know about then min=max=x.y, because we want to allow
  //   x.(y+1) to be a potential hardfork that we don't know about yet.
  // - if we *do* know about a higher hf with the same major version, then the highest we accept is
  //   one less than that (e.g. if we are 20.7 and the next HF is 20.10 then we accept 20.7-20.9).
  // - if the next hf we know about bumps major version then max is x.127 (as in the mainnet case).
  std::pair<network_version, network_version>
  get_network_versions_for_height(network_type nettype, uint64_t height);

  // Returns the "ideal" network version that we want to use on blocks we create, which is to use a
  // minor version of 32*x + y for oxen version z.x.y on the top known HF, on mainnet, and otherwise
  // will be MAJOR.127 when we know about a higher hardfork.
  //
  // On testnet, the minor value is determined by the hard-fork table: if we know of a scheduled
  // future hardfork we use its major.(minor-1); otherwise we use the largest hard fork value we
  // know of.
  network_version get_ideal_network_version(network_type nettype, uint64_t height);

  // Returns true if `a` and `b` are in the same hard fork and same major version: that is, they
  // both have the same valid block range and the same major version.  For example, with hard forks
  // at 19.32 and 20.33, then any two `19.x` and `19.y` values will return true as long as both x
  // and y are >= 32, but `19.35` and `20.4` will not be equal, nor will 20.x and 20.y if either x
  // or y is < 33 (because with such a HF table, 20.x blocks are only valid starting at 20.33).
  //
  // This is generally the method you want to use to compare whether a block is acceptable (by
  // comparing whether an incoming block is the same hard fork as the current ideal version).
  //
  // This should *not* be used for feature tests (because for those the feature version is often not
  // a valid block height, e.g. with a version < the first fork on a major version).
  inline bool is_same_hard_fork(network_type type, network_version a, network_version b) {
      auto ahf = get_hard_fork_heights(type, a);
      auto bhf = get_hard_fork_heights(type, b);
      return ahf.first && bhf.first && ahf == bhf;
  }

  namespace detail {
#ifndef NDEBUG
    template <typename T>
    constexpr bool network_version check_descending_versions(network_version, T) { return true; }
    template <typename T, typename... More>
    constexpr bool network_version check_descending_versions(network_version a, network_version b, More&&... args) {
        return a < b && check_descending_versions(b, std::forward<More>(args)...);
    }
#endif

    template <typename T>
    T network_dependent_value_impl(network_type, network_version, T final_value) { return final_value; }
    template <typename T, typename... More>
    T network_dependent_value_impl(network_type nettype, network_version given_floor, network_version ifthis, T that, More&&... args) {
      if (hard_fork_ceil({nettype, ifthis}) <= given_floor) return that;
      return network_dependent_value_impl<T>(nettype, given_floor, std::forward<More>(args)...);
    }
  }

  // Simplifies determining a network-version-dependent value.
  //     Blah val = network_dependent_value(given, X, blah1, Y, blah2, blah3);
  // is a shortcut for:
  //    Blah val =
  //        is_network_version_enabled(X, given) ? blah1 :
  //        is_network_version_enabled(Y, given) ? blah2 :
  //        blah3;
  // The value/return type (Blah) is determined from the *first* value argument (blah1 in the
  // example above); subsequent arguments need to agree or be implicitly convertible.
  //
  // Dependent network versions given must be in descending order.
  template <typename T, typename... More, typename = std::enable_if_t<sizeof...(More) % 2 == 1>>
  T network_dependent_value(network_state given, network_version ifthis, T that, More&&... args) {
      assert(detail::check_descending_versions<T>(ifthis, std::forward<More>(args)...));
      return detail::network_dependent_value_impl<T>(given.first, hard_fork_floor(given), ifthis, that, std::forward<More>(args)...);
  }

}  // namespace cryptonote
