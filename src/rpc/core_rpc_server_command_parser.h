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
  void parse_request(STOP_MINING& stop_mining, rpc_input in);
  void parse_request(MINING_STATUS& mining_status, rpc_input in);
  void parse_request(GET_TRANSACTION_POOL_STATS& get_transaction_pool_stats, rpc_input in);
  void parse_request(GET_TRANSACTION_POOL_BACKLOG& get_transaction_pool_backlog, rpc_input in);
  void parse_request(GET_TRANSACTION_POOL_HASHES& get_transaction_pool_hashes, rpc_input in);
  void parse_request(GETBLOCKCOUNT& getblockcount, rpc_input in);
  void parse_request(STOP_DAEMON& stop_daemon, rpc_input in);
  void parse_request(SAVE_BC& save_bc, rpc_input in);
  void parse_request(GET_OUTPUTS& get_outputs, rpc_input in);
}
