#pragma once

#include <limits>
#include <string_view>
#include <unordered_map>

#include "blockchain_db/sqlite/db_sqlite.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_config.h"
#include "cryptonote_core/service_node_list.h"

namespace oxen::sent {

using cryptonote::network_type;

cryptonote::account_public_address parse_oxen_addr(std::string_view addr);
eth::address parse_eth_addr(std::string_view addr);

// This is the ratio of the SENT staking requirement to OXEN staking requirement at the time of the
// transition, as a reduced form fraction.
inline constexpr std::pair<uint32_t, uint32_t> OXEN_SENT_STAKING_RATIO = {
        SENT_STAKING_REQUIREMENT / std::gcd(SENT_STAKING_REQUIREMENT, OXEN_STAKING_REQUIREMENT),
        OXEN_STAKING_REQUIREMENT / std::gcd(SENT_STAKING_REQUIREMENT, OXEN_STAKING_REQUIREMENT)};

// Same as above, but for testnet/devnet:
inline constexpr std::pair<uint32_t, uint32_t> OXEN_SENT_TESTNET_STAKING_RATIO = {
        SENT_STAKING_REQUIREMENT_TESTNET /
                std::gcd(SENT_STAKING_REQUIREMENT_TESTNET, OXEN_STAKING_REQUIREMENT_TESTNET),
        OXEN_STAKING_REQUIREMENT_TESTNET /
                std::gcd(SENT_STAKING_REQUIREMENT_TESTNET, OXEN_STAKING_REQUIREMENT_TESTNET)};

// This ensure that the ratios above are sufficiently reduced that we won't overflow when
// calculating 'atomic_oxen_stake * numerator'.  Most maximum stakes are 15k, but there are a few
// very old registered nodes with higher staking requirements (up to just under 21825 OXEN),
// registered before the staking requirement dropped to 15k, with a maximum single contribution of
// 17493.
static_assert(
        OXEN_SENT_STAKING_RATIO.first < std::numeric_limits<uint64_t>::max() / 17500'000000000);
static_assert(
        OXEN_SENT_TESTNET_STAKING_RATIO.first <
        std::numeric_limits<uint64_t>::max() / 100'000000000);

/// Returns the mapping of OXEN -> SENT addresses for the given network type.
const std::unordered_map<cryptonote::account_public_address, eth::address>& addresses(
        network_type net);

/// Returns the OXEN -> SENT conversion ratio to apply to conversion-registered wallets at the
/// SENT hardfork.  The first value is the numerator, second is the denominator (e.g. a return
/// of [2, 3] means 1 OXEN becomes 0.666666666 SENT.  (This is a ratio because the conversion is
/// performed precisely, avoiding floating point math).
const std::pair<uint8_t, uint8_t>& conversion_ratio(network_type net);

/// Returns SENT SN contributor transition bonus amounts (from the SN bonus program) as a map of eth
/// address -> atomic (1e-9) value.
const std::unordered_map<eth::address, uint64_t>& transition_bonus(network_type net);

/// Performs the SENT service node transition, updating the service node list to replace OXEN
/// addresses with ETH addresses, updating stakes to reflect the SENT staking requirement, and
/// converting any pending batched rewards to SENT.  After this is called, all services nodes will
/// be updated to contain only ETH address, and service nodes that cannot survive (due to
/// insufficient stakes or unregistered contributors) will be turned into a "zombie" state of 0
/// contributions; such zombie SNs earn no rewards and will be evicted from the network via quorum
/// testing.
///
/// Any converted SENT funds that are not staked (e.g. because a contributor has more than needed,
/// or has some nodes that are being disbanded or some combination of both) are added to the
/// batching database as a one-time transition "reward" that can be redeemed by the wallet.
///
/// Non-converting pending OXEN rewards balances (i.e. unregistered wallets) are not updated by
/// this; they will be paid in final batching reward calculations over the regular 3.5-day payout
/// schedule following the fork.
///
/// Additionally we replace the primary pubkey of any old Oxen nodes with differing "pubkey" and
/// "ed25519_pubkey" values (generally: SNs set up before Oxen 8) with the ed25519 pubkey; as of the
/// SENT HF these are unifed, and SNs will start ignoring a non-ed25519 service node pubkey.
void transition(
        service_nodes::service_node_list& sns, cryptonote::BlockchainSQLite& sql, network_type net);

}  // namespace oxen::sent
