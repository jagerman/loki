#include "core_rpc_server_commands_defs.h"
#include <nlohmann/json.hpp>
#include <oxenmq/base64.h>

namespace cryptonote::rpc {

void RPC_COMMAND::set_bt() {
  bt = true;
  response_b64.format = json_binary_proxy::fmt::bt;
  response_hex.format = json_binary_proxy::fmt::bt;
}

KV_SERIALIZE_MAP_CODE_BEGIN(STATUS)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(EMPTY)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GETBLOCKTEMPLATE::request)
  KV_SERIALIZE(reserve_size)
  KV_SERIALIZE(wallet_address)
  KV_SERIALIZE(prev_block)
  KV_SERIALIZE(extra_nonce)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GETBLOCKTEMPLATE::response)
  KV_SERIALIZE(difficulty)
  KV_SERIALIZE(height)
  KV_SERIALIZE(reserved_offset)
  KV_SERIALIZE(expected_reward)
  KV_SERIALIZE(prev_hash)
  KV_SERIALIZE(blocktemplate_blob)
  KV_SERIALIZE(blockhashing_blob)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
  KV_SERIALIZE(seed_hash)
  KV_SERIALIZE(next_seed_hash)
KV_SERIALIZE_MAP_CODE_END()


bool SUBMITBLOCK::request::load(epee::serialization::portable_storage& ps, epee::serialization::section* hparent_section)
{
  return epee::serialization::perform_serialize<false>(blob, ps, hparent_section, "blob");
}
bool SUBMITBLOCK::request::store(epee::serialization::portable_storage& ps, epee::serialization::section* hparent_section)
{
  return epee::serialization::perform_serialize<true>(blob, ps, hparent_section, "blob");
}


KV_SERIALIZE_MAP_CODE_BEGIN(GENERATEBLOCKS::request)
  KV_SERIALIZE(amount_of_blocks)
  KV_SERIALIZE(wallet_address)
  KV_SERIALIZE(prev_block)
  KV_SERIALIZE_OPT(starting_nonce, (uint32_t)0)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GENERATEBLOCKS::response)
  KV_SERIALIZE(height)
  KV_SERIALIZE(blocks)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(block_header_response)
  KV_SERIALIZE(major_version)
  KV_SERIALIZE(minor_version)
  KV_SERIALIZE(timestamp)
  KV_SERIALIZE(prev_hash)
  KV_SERIALIZE(nonce)
  KV_SERIALIZE(orphan_status)
  KV_SERIALIZE(height)
  KV_SERIALIZE(depth)
  KV_SERIALIZE(hash)
  KV_SERIALIZE(difficulty)
  KV_SERIALIZE(cumulative_difficulty)
  KV_SERIALIZE(reward)
  KV_SERIALIZE(miner_reward)
  KV_SERIALIZE(block_size)
  KV_SERIALIZE_OPT(block_weight, (uint64_t)0)
  KV_SERIALIZE(num_txes)
  KV_SERIALIZE(pow_hash)
  KV_SERIALIZE_OPT(long_term_weight, (uint64_t)0)
  KV_SERIALIZE(miner_tx_hash)
  KV_SERIALIZE(tx_hashes)
  KV_SERIALIZE(service_node_winner)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_LAST_BLOCK_HEADER::request)
  KV_SERIALIZE_OPT(fill_pow_hash, false);
  KV_SERIALIZE_OPT(get_tx_hashes, false);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_LAST_BLOCK_HEADER::response)
  KV_SERIALIZE(block_header)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADER_BY_HASH::request)
  KV_SERIALIZE(hash)
  KV_SERIALIZE(hashes)
  KV_SERIALIZE_OPT(fill_pow_hash, false);
  KV_SERIALIZE_OPT(get_tx_hashes, false);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADER_BY_HASH::response)
  KV_SERIALIZE(block_header)
  KV_SERIALIZE(block_headers)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADER_BY_HEIGHT::request)
  KV_SERIALIZE(height)
  KV_SERIALIZE(heights)
  KV_SERIALIZE_OPT(fill_pow_hash, false);
  KV_SERIALIZE_OPT(get_tx_hashes, false);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADER_BY_HEIGHT::response)
  KV_SERIALIZE(block_header)
  KV_SERIALIZE(block_headers)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK::request)
  KV_SERIALIZE(hash)
  KV_SERIALIZE(height)
  KV_SERIALIZE_OPT(fill_pow_hash, false);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK::response)
  KV_SERIALIZE(block_header)
  KV_SERIALIZE(tx_hashes)
  KV_SERIALIZE(status)
  KV_SERIALIZE(blob)
  KV_SERIALIZE(json)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_PEER_LIST::peer)
  KV_SERIALIZE(id)
  KV_SERIALIZE(host)
  KV_SERIALIZE(ip)
  KV_SERIALIZE(port)
  KV_SERIALIZE_OPT(rpc_port, (uint16_t)0)
  KV_SERIALIZE(last_seen)
  KV_SERIALIZE_OPT(pruning_seed, (uint32_t)0)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_PEER_LIST::request)
  KV_SERIALIZE_OPT(public_only, true)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_PEER_LIST::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(white_list)
  KV_SERIALIZE(gray_list)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(public_node)
  KV_SERIALIZE(host)
  KV_SERIALIZE(last_seen)
  KV_SERIALIZE(rpc_port)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_PUBLIC_NODES::request)
  KV_SERIALIZE_OPT(gray, false)
  KV_SERIALIZE_OPT(white, true)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_PUBLIC_NODES::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(gray)
  KV_SERIALIZE(white)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SET_LOG_LEVEL::request)
  KV_SERIALIZE(level)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SET_LOG_CATEGORIES::request)
  KV_SERIALIZE(categories)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SET_LOG_CATEGORIES::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(categories)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADERS_RANGE::request)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(end_height)
  KV_SERIALIZE_OPT(fill_pow_hash, false);
  KV_SERIALIZE_OPT(get_tx_hashes, false);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADERS_RANGE::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(headers)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(SET_BOOTSTRAP_DAEMON::request)
  KV_SERIALIZE(address)
  KV_SERIALIZE(username)
  KV_SERIALIZE(password)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(OUT_PEERS::request)
  KV_SERIALIZE_OPT(set, true)
  KV_SERIALIZE(out_peers)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(OUT_PEERS::response)
  KV_SERIALIZE(out_peers)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(IN_PEERS::request)
  KV_SERIALIZE_OPT(set, true)
  KV_SERIALIZE(in_peers)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(IN_PEERS::response)
  KV_SERIALIZE(in_peers)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GETBANS::ban)
  KV_SERIALIZE(host)
  KV_SERIALIZE(ip)
  KV_SERIALIZE(seconds)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GETBANS::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(bans)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SETBANS::ban)
  KV_SERIALIZE(host)
  KV_SERIALIZE(ip)
  KV_SERIALIZE(ban)
  KV_SERIALIZE(seconds)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SETBANS::request)
  KV_SERIALIZE(bans)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(BANNED::request)
  KV_SERIALIZE(address)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(BANNED::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(banned)
  KV_SERIALIZE(seconds)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(FLUSH_TRANSACTION_POOL::request)
  KV_SERIALIZE(txids)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_HISTOGRAM::request)
  KV_SERIALIZE(amounts);
  KV_SERIALIZE(min_count);
  KV_SERIALIZE(max_count);
  KV_SERIALIZE(unlocked);
  KV_SERIALIZE(recent_cutoff);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_HISTOGRAM::entry)
  KV_SERIALIZE(amount);
  KV_SERIALIZE(total_instances);
  KV_SERIALIZE(unlocked_instances);
  KV_SERIALIZE(recent_instances);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_HISTOGRAM::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(histogram)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_VERSION::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(version)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_COINBASE_TX_SUM::request)
  KV_SERIALIZE(height);
  KV_SERIALIZE(count);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_COINBASE_TX_SUM::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(emission_amount)
  KV_SERIALIZE(fee_amount)
  KV_SERIALIZE(burn_amount)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BASE_FEE_ESTIMATE::request)
  KV_SERIALIZE(grace_blocks)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BASE_FEE_ESTIMATE::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(fee_per_byte)
  KV_SERIALIZE(fee_per_output)
  KV_SERIALIZE(blink_fee_per_byte)
  KV_SERIALIZE(blink_fee_per_output)
  KV_SERIALIZE(blink_fee_fixed)
  KV_SERIALIZE_OPT(quantization_mask, (uint64_t)1)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_ALTERNATE_CHAINS::chain_info)
  KV_SERIALIZE(block_hash)
  KV_SERIALIZE(height)
  KV_SERIALIZE(length)
  KV_SERIALIZE(difficulty)
  KV_SERIALIZE(block_hashes)
  KV_SERIALIZE(main_chain_parent_block)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_ALTERNATE_CHAINS::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(chains)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(RELAY_TX::request)
  KV_SERIALIZE(txids)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION::request)
  KV_SERIALIZE(amounts)
  KV_SERIALIZE_OPT(from_height, (uint64_t)0)
  KV_SERIALIZE_OPT(to_height, (uint64_t)0)
  KV_SERIALIZE_OPT(cumulative, false)
  KV_SERIALIZE_OPT(binary, true)
  KV_SERIALIZE_OPT(compress, false)
KV_SERIALIZE_MAP_CODE_END()


namespace
{
  template<typename T>
  std::string compress_integer_array(const std::vector<T> &v)
  {
    std::string s;
    s.reserve(tools::VARINT_MAX_LENGTH<T>);
    auto ins = std::back_inserter(s);
    for (const T &t: v)
      tools::write_varint(ins, t);
    return s;
  }

  template<typename T>
  std::vector<T> decompress_integer_array(const std::string &s)
  {
    std::vector<T> v;
    for (auto it = s.begin(); it < s.end(); )
    {
      int read = tools::read_varint(it, s.end(), v.emplace_back());
      CHECK_AND_ASSERT_THROW_MES(read > 0, "Error decompressing data");
    }
    return v;
  }
}

KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION::distribution)
  KV_SERIALIZE(amount)
  KV_SERIALIZE_N(data.start_height, "start_height")
  KV_SERIALIZE(binary)
  KV_SERIALIZE(compress)
  if (binary)
  {
    if (is_store)
    {
      if (compress)
      {
        const_cast<std::string&>(compressed_data) = compress_integer_array(data.distribution);
        KV_SERIALIZE(compressed_data)
      }
      else
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(data.distribution, "distribution")
    }
    else
    {
      if (compress)
      {
        KV_SERIALIZE(compressed_data)
        const_cast<std::vector<uint64_t>&>(data.distribution) = decompress_integer_array<uint64_t>(compressed_data);
      }
      else
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(data.distribution, "distribution")
    }
  }
  else
    KV_SERIALIZE_N(data.distribution, "distribution")
  KV_SERIALIZE_N(data.base, "base")
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(distributions)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(POP_BLOCKS::request)
  KV_SERIALIZE(nblocks);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(POP_BLOCKS::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(height)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(PRUNE_BLOCKCHAIN::request)
  KV_SERIALIZE_OPT(check, false)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(PRUNE_BLOCKCHAIN::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(pruned)
  KV_SERIALIZE(pruning_seed)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_QUORUM_STATE::request)
  KV_SERIALIZE_OPT(start_height, HEIGHT_SENTINEL_VALUE)
  KV_SERIALIZE_OPT(end_height, HEIGHT_SENTINEL_VALUE)
  KV_SERIALIZE_OPT(quorum_type, ALL_QUORUMS_SENTINEL_VALUE)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_QUORUM_STATE::quorum_t)
  KV_SERIALIZE(validators)
  KV_SERIALIZE(workers)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_QUORUM_STATE::quorum_for_height)
  KV_SERIALIZE(height)
  KV_SERIALIZE(quorum_type)
  KV_SERIALIZE(quorum)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_QUORUM_STATE::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(quorums)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_REGISTRATION_CMD_RAW::request)
  KV_SERIALIZE(args)
  KV_SERIALIZE(make_friendly)
  KV_SERIALIZE(staking_requirement)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_REGISTRATION_CMD_RAW::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(registration_cmd)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_REGISTRATION_CMD::contribution_t)
  KV_SERIALIZE(address)
  KV_SERIALIZE(amount)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_REGISTRATION_CMD::request)
  KV_SERIALIZE(operator_cut)
  KV_SERIALIZE(contributions)
  KV_SERIALIZE(staking_requirement)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_KEYS::response)
  KV_SERIALIZE(service_node_pubkey)
  KV_SERIALIZE(service_node_ed25519_pubkey)
  KV_SERIALIZE(service_node_x25519_pubkey)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_PRIVKEYS::response)
  KV_SERIALIZE(service_node_privkey)
  KV_SERIALIZE(service_node_ed25519_privkey)
  KV_SERIALIZE(service_node_x25519_privkey)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(STORAGE_SERVER_PING::request)
  KV_SERIALIZE(version);
  KV_SERIALIZE(https_port);
  KV_SERIALIZE(omq_port);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(LOKINET_PING::request)
  KV_SERIALIZE(version);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_STAKING_REQUIREMENT::request)
  KV_SERIALIZE(height)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_STAKING_REQUIREMENT::response)
  KV_SERIALIZE(staking_requirement)
  KV_SERIALIZE(height)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::entry)
  KV_SERIALIZE(key_image)
  KV_SERIALIZE(unlock_height)
  KV_SERIALIZE(amount)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::response)
  KV_SERIALIZE(blacklist)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_CHECKPOINTS::request)
  KV_SERIALIZE_OPT(start_height, HEIGHT_SENTINEL_VALUE)
  KV_SERIALIZE_OPT(end_height, HEIGHT_SENTINEL_VALUE)
  KV_SERIALIZE_OPT(count, NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_CHECKPOINTS::quorum_signature_serialized)
  KV_SERIALIZE(voter_index);
  KV_SERIALIZE(signature);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_CHECKPOINTS::checkpoint_serialized)
  KV_SERIALIZE(version);
  KV_SERIALIZE(type);
  KV_SERIALIZE(height);
  KV_SERIALIZE(block_hash);
  KV_SERIALIZE(signatures);
  KV_SERIALIZE(prev_height);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_CHECKPOINTS::response)
  KV_SERIALIZE(checkpoints)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SN_STATE_CHANGES::request)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE_OPT(end_height, HEIGHT_SENTINEL_VALUE)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SN_STATE_CHANGES::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
  KV_SERIALIZE(total_deregister)
  KV_SERIALIZE(total_ip_change_penalty)
  KV_SERIALIZE(total_decommission)
  KV_SERIALIZE(total_recommission)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(end_height)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(REPORT_PEER_STATUS::request)
  KV_SERIALIZE(type)
  KV_SERIALIZE(pubkey)
  KV_SERIALIZE(passed)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(ONS_NAMES_TO_OWNERS::request_entry)
  KV_SERIALIZE(name_hash)
  KV_SERIALIZE(types)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(ONS_NAMES_TO_OWNERS::request)
  KV_SERIALIZE(entries)
  KV_SERIALIZE(include_expired)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(ONS_NAMES_TO_OWNERS::response_entry)
  KV_SERIALIZE(entry_index)
  KV_SERIALIZE_ENUM(type)
  KV_SERIALIZE(name_hash)
  KV_SERIALIZE(owner)
  KV_SERIALIZE(backup_owner)
  KV_SERIALIZE(encrypted_value)
  KV_SERIALIZE(update_height)
  KV_SERIALIZE(expiration_height)
  KV_SERIALIZE(txid)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(ONS_NAMES_TO_OWNERS::response)
  KV_SERIALIZE(entries)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(ONS_OWNERS_TO_NAMES::request)
  KV_SERIALIZE(entries)
  KV_SERIALIZE(include_expired)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(ONS_OWNERS_TO_NAMES::response_entry)
  KV_SERIALIZE(request_index)
  KV_SERIALIZE_ENUM(type)
  KV_SERIALIZE(name_hash)
  KV_SERIALIZE(owner)
  KV_SERIALIZE(backup_owner)
  KV_SERIALIZE(encrypted_value)
  KV_SERIALIZE(update_height)
  KV_SERIALIZE(expiration_height)
  KV_SERIALIZE(txid)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(ONS_OWNERS_TO_NAMES::response)
  KV_SERIALIZE(entries)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(FLUSH_CACHE::request)
  KV_SERIALIZE_OPT(bad_txs, false)
  KV_SERIALIZE_OPT(bad_blocks, false)
KV_SERIALIZE_MAP_CODE_END()

}
