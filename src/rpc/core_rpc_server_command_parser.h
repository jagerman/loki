#pragma once

#include "core_rpc_server_commands_defs.h"
#include <nlohmann/json.hpp>
#include <oxenmq/bt_serialize.h>

namespace cryptonote::rpc {

  using rpc_input = std::variant<std::monostate, nlohmann::json, oxenmq::bt_dict_consumer>;

  inline void parse_request(NO_ARGS&, rpc_input) {}

  void parse_request(ONS_RESOLVE& ons, rpc_input in);
  void parse_request(GET_SERVICE_NODES& sns, rpc_input in);
  void parse_request(START_MINING& start_mining, rpc_input in);
  void parse_request(GET_OUTPUTS& get_outputs, rpc_input in);
  void parse_request(GET_TRANSACTION_POOL_STATS& pstats, rpc_input in);
  void parse_request(GET_TRANSACTIONS& hfinfo, rpc_input in);
  void parse_request(HARD_FORK_INFO& hfinfo, rpc_input in);
  void parse_request(SET_LIMIT& limit, rpc_input in);
  void parse_request(IS_KEY_IMAGE_SPENT& spent, rpc_input in);
  void parse_request(SUBMIT_TRANSACTION& tx, rpc_input in);
  void parse_request(GET_BLOCK_HASH& bh, rpc_input in);
  void parse_request(GET_PEER_LIST& bh, rpc_input in);
  void parse_request(SET_LOG_LEVEL& set_log_level, rpc_input in);
  void parse_request(SET_LOG_CATEGORIES& set_log_categories, rpc_input in);
  void parse_request(BANNED& banned, rpc_input in);
  void parse_request(FLUSH_TRANSACTION_POOL& flush_transaction_pool, rpc_input in);
  void parse_request(GET_COINBASE_TX_SUM& get_coinbase_tx_sum, rpc_input in);
  void parse_request(GET_BASE_FEE_ESTIMATE& get_base_fee_estimate, rpc_input in);
  void parse_request(OUT_PEERS& out_peers, rpc_input in);
  void parse_request(IN_PEERS& in_peers, rpc_input in);
  void parse_request(POP_BLOCKS& pop_blocks, rpc_input in);
}
