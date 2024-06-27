#include "sent_transition.h"

#include <ranges>

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

namespace oxen::sent {

using addrmap_t = std::unordered_map<cryptonote::account_public_address, eth::address>;
using conv_ratio_t = std::pair<std::uint8_t, std::uint8_t>;
using bonus_map_t = std::unordered_map<eth::address, std::uint64_t>;

namespace devnet {
    const addrmap_t addresses;
    const conv_ratio_t conv_ratio;
    const bonus_map_t transition_bonus;
}  // namespace devnet
namespace testnet {
    const addrmap_t addresses;
    const conv_ratio_t conv_ratio;
    const bonus_map_t transition_bonus;
}  // namespace testnet
namespace mainnet {
    const addrmap_t addresses;
    const conv_ratio_t conv_ratio;
    const bonus_map_t transition_bonus;
}  // namespace mainnet

const conv_ratio_t& conversion_ratio(network_type net) {
    return net == network_type::DEVNET  ? devnet::conv_ratio
         : net == network_type::TESTNET ? testnet::conv_ratio
                                        : mainnet::conv_ratio;
}

const addrmap_t& addresses(network_type net) {
    return net == network_type::DEVNET  ? devnet::addresses
         : net == network_type::TESTNET ? testnet::addresses
                                        : mainnet::addresses;
}

const bonus_map_t& transition_bonus(network_type net) {
    return net == network_type::DEVNET  ? devnet::transition_bonus
         : net == network_type::TESTNET ? testnet::transition_bonus
                                        : mainnet::transition_bonus;
}

void transition(
        service_nodes::service_node_list::state_t& snl_state,
        cryptonote::BlockchainSQLite& sql,
        network_type net) {
    const auto& conv_ratio = conversion_ratio(net);
    const auto& sent_addrs = addresses(net);

    auto oxen_to_sent = [&conv_ratio](uint64_t oxen) {
        return oxen * conv_ratio.first / conv_ratio.second;
    };

    // We start out by finding the total amount of SENT owed to each ETH address: starting from the
    // SN bonus, then we'll add converted amounts for any batched rewards, then convert existing
    // stakes.  Then, once we know each address's total, we'll go back and try to re-fill as many
    // SNs as we can from the unallocated amounts.
    std::unordered_map<eth::address, uint64_t> unallocated = transition_bonus(net);

    // Convert any balances for registered accounts in the batching db, removing it from the
    // batching db.  (If there is SENT left over at the end we'll put it back in, but under the
    // converted SENT address).

    std::vector<cryptonote::batch_sn_payment> converted_rewards;
    auto [accrued_addr, accrued_value] = sql.get_all_accrued_earnings();
    assert(accrued_addr.size() == accrued_value.size());
    for (size_t i = 0; i < accrued_addr.size(); i++) {
        auto& addr = accrued_addr[i];
        auto& val = accrued_value[i];

        cryptonote::address_parse_info api;
        if (!get_account_address_from_str(api, net, addr) || api.has_payment_id ||
            api.is_subaddress)
            throw std::runtime_error{
                    "Unable to perform SENT transition: batching database contains invalid, unparseable, or non-OXEN address '{}'"_format(
                            addr)};
        const auto& oxen_addr = api.address;

        auto it = sent_addrs.find(oxen_addr);
        if (it == sent_addrs.end())
            continue;

        const auto& eth_addr = it->second;
        unallocated[eth_addr] += oxen_to_sent(val);
        converted_rewards.emplace_back(oxen_addr, val);
    }

    // Clear out all the old OXEN rewards that we've now converted (into `unallocated`).  We'll add
    // anything left over back in (under the ETH address) at the end.
    sql.subtract_sn_rewards(converted_rewards);

    // Pass one: convert all stakes (of registered users) to our SENT bucket.  We'll leave the
    // values in place for now; we come back and update everything later.
    for (const auto& [pubkey, info] : snl_state.service_nodes_infos) {
        for (auto& contributor : info->contributors) {
            if (auto it = sent_addrs.find(contributor.address); it != sent_addrs.end()) {
                // Although the sum of .locked_contributions.amount is *usually* the same as
                // .amount, it's possible for a small over-contribution to have been accepted which
                // would show up in the locked amounts but not the aggregate amount (for example: if
                // a SN has 123.456 available and someone contributes 123.5)
                uint64_t total = 0;
                for (const auto& lc : contributor.locked_contributions)
                    total += lc.amount;
                unallocated[it->second] += oxen_to_sent(total);
            }
        }
    }

    // We consider service nodes from oldest to most recent, replacing OXEN allocations with the
    // same proportion of SENT allocations for each contributor, and replacing contributor addresses
    // with their SENT addresses.
    //
    // By going oldest to newest we prioritize nodes that have been online the longest, which means
    // they are more likely to be good, solid nodes, and (for multi-contributor nodes) the
    // contributors appear to be happy with them since they haven't unstaked. (We could sort just
    // about any way we like, but this seems a reasonable choice).  In the case of two equal age
    // nodes, we break the tie by sorting by pubkey.
    //
    // As we transition we first figure out whether a node can survive:
    // - all contributors (including the operator) must be registered for the swap
    // - all contributors (including the operator) must have enough so-far unallocated SENT to be
    //   able to commit the same proportional amount of SENT (e.g. a staker with 31% of the OXEN
    //   staking contribution needs to have 31% of the required SENT staking contribution).
    //
    // If it can survive, we update the staking addresses to the ETH addresses, update the stakes to
    // the SENT amount, and remove that amounts from the unallocated funds bucket.
    //
    // If it can't survive (either because of unregistered contributors, or because of insufficient
    // staking funds), we mark it as a zombie, which means no contributors and a zero stake.  This
    // zombification also immediately releases any OXEN (The testing swarms will take care of
    // ejecting these off the network over the blocks after the fork).
    //
    std::vector<std::pair<crypto::public_key, const service_nodes::service_node_info*>> sorted_sns;
    sorted_sns.reserve(snl_state.service_nodes_infos.size());
    for (const auto& [pk, sn] : snl_state.service_nodes_infos)
        sorted_sns.emplace_back(pk, sn.get());

    std::sort(sorted_sns.begin(), sorted_sns.end(), [](auto& a, auto& b) {
        return std::tie(a.second->registration_height, a.first) <
               std::tie(b.second->registration_height, b.first);
    });

    // This will contain our *new* list of service nodes, with only SENT contributors/stakes
    // converted from `sorted_sns`.
    std::vector<std::pair<crypto::public_key, std::shared_ptr<service_nodes::service_node_info>>>
            living_sns;

    std::unordered_set<crypto::public_key> zombies;

    const auto& staking_requirement = net == network_type::MAINNET
                                            ? SENT_STAKING_REQUIREMENT
                                            : SENT_STAKING_REQUIREMENT_TESTNET;
    const auto& staking_ratio = net == network_type::MAINNET ? OXEN_SENT_STAKING_RATIO
                                                             : OXEN_SENT_TESTNET_STAKING_RATIO;

    for (const auto& [pk, sni] : sorted_sns) {
        bool zombie = false;

        // We have 5 exceptions to the 15k staking requirement on the OXEN mainnet, registered
        // continuously since before the staking requirement was fixed at 15k (HF16, i.e. Oxen 8).
        std::optional<std::pair<uint32_t, uint32_t>> extra_ratio;
        if (net == network_type::MAINNET && sni->staking_requirement > 15000'000000000) {
            // +1 because we want this ratio to err on the size of being too small so that we are
            // guaranteed to have a sum of contributions at the end that are <= the required amount.
            // This is computed in tenths of an OXEN to ensure we won't overflow when applying the
            // ratio while still being able to get reasonably close to the precise number.
            extra_ratio.emplace(15000'0, sni->staking_requirement / 100'000'000 + 1);

            // The maximum OXEN contribution amount we have is just under 17500, which means in the
            // code below we could (as an intermediate step) end up calculating up to just under 7/6
            // of the SENT staking requirement; thus we want to ensure that when we multiply such a
            // value by extra_ratio.first, we won't overflow:
            static_assert(
                    std::numeric_limits<uint64_t>::max() / 15000'0 >
                    (SENT_STAKING_REQUIREMENT * 7 + 5) / 6 /* ceiling division */);
        }

        // Partially funded nodes at the time of transition just get dropped and will have to be
        // re-registered via a SENT multi-contributor contract.
        if (!sni->is_fully_funded())
            zombie = true;

        // Now compute how much SENT must be staked in order to maintain the same relative stake in
        // this SN.  E.g. if you had a 21% stake before (3150 OXEN) and the SENT staking requirement
        // is 20k then your SENT stake in this node will become 21% of 20k (4200 SENT).
        std::unordered_map<eth::address, uint64_t> sent_stake;
        if (!zombie) {
            auto* stakers =
                    std::get_if<std::vector<service_nodes::service_node_info::oxen_contributor>>(
                            &sni->stakes);
            if (!stakers)
                throw std::runtime_error{
                        "Unable to perform SENT transition: SN {} has unexpected lack of OXEN contributions!"_format(
                                pk)};
            for (auto& contributor : *stakers) {
                auto it = sent_addrs.find(contributor.address);
                if (it == sent_addrs.end()) {
                    zombie = true;
                    break;
                }

                uint64_t sent_required =
                        contributor.amount * staking_ratio.first / staking_ratio.second;
                if (extra_ratio)
                    sent_required = sent_required * extra_ratio->first / extra_ratio->second;

                sent_stake[it->second] += sent_required;
            }
        }

        eth::address sn_op = crypto::null<eth::address>;

        // Make sure all the contributors have enough unallocated SENT to actually carry over the
        // stake; if any don't then the SN becomes a zombie to be deregistered.
        if (!zombie) {
            if (auto* oxen_op_addr =
                        std::get_if<cryptonote::account_public_address>(&sni->operator_address))
                sn_op = sent_addrs.at(*oxen_op_addr);
            else
                throw std::runtime_error{
                        "Unable to perform SENT transition: SN {} has a non-OXEN operator address!"_format(
                                pk)};

            // Our truncating integer divisions above will likely have slightly undercalculated some
            // of the staking requirements, so add the missing atomic amount to the operator
            // requirement
            uint64_t deficit = staking_requirement;
            for (const auto& [eth, reqd] : sent_stake) {
                assert(reqd <= staking_requirement);
                deficit -= reqd;
            }
            if (deficit)
                sent_stake[sn_op] += deficit;

            for (const auto& [eth, reqd] : sent_stake) {
                assert(unallocated.count(eth));
                if (unallocated[eth] < reqd) {
                    zombie = true;
                    break;
                }
            }
        }

        // We're going to rewrite the service node info now *regardless* of whether it's a zombie or
        // not, but if a zombie we're deliberately writing data that will get it kicked out shortly
        // after the fork.
        auto new_state = std::make_shared<service_nodes::service_node_info>(*sni);
        auto& sn = *new_state;

        // Compress the [0, 18446744073709551612] value into a [0, 10000] value:
        sn.portions_for_operator = sni->portions_for_operator / 184467440737095;

        auto& stakers =
                sn.stakes.emplace<std::vector<service_nodes::service_node_info::sent_stake>>();

        if (!zombie) {
            sn.total_contributed = staking_requirement;
            sn.total_reserved = staking_requirement;
            sn.staking_requirement = staking_requirement;

            // Insert the operator first, then after that we sort by stake size descending, and then
            // address to break ties of equal-stake stakers.
            {
                auto it = sent_stake.find(sn_op);
                assert(it != sent_stake.end());
                stakers.emplace_back(it->first, it->second);
                sent_stake.erase(it);
            }
            std::vector<std::pair<eth::address, uint64_t>> stakes_desc{
                    sent_stake.begin(), sent_stake.end()};
            std::sort(stakes_desc.begin(), stakes_desc.end(), [](auto& a, auto& b) {
                if (a.second != b.second)
                    return a.second > b.second;  // a comes first if the *value* is larger
                return a.first <
                       b.first;  // same value: a comes first if the *address* is "smaller"
            });
            for (const auto& [eth, stake] : stakes_desc)
                stakers.emplace_back(eth, stake);
        } else {
            // This SN is a zombie, i.e. its dying and will get deregged shortly after the fork.
            // We're leaving it technically registered, but just a husk: it has no contributors and
            // a 0 staking requirement/total.

            sn.total_contributed = 0;
            sn.total_reserved = 0;
            sn.staking_requirement = 0;
        }
    }

    // TODO: set BLS keys
    // TODO: replace primary pubkey with ed25519 pubkey if different
}

// TODO: *permanently* blacklist the key images of all converted stakes (but not
// unconverted ones), so that you can't go back to the OXEN wallet and then convert
// them through the external SENT conversion process.
}

}  // namespace oxen::sent
