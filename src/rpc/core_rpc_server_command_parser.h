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
}
