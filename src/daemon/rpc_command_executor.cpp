// Copyright (c) 2018-2020, The Loki Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "common/string_util.h"
#include "epee/string_tools.h"
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "common/pruning.h"
#include "common/hex.h"
#include "daemon/rpc_command_executor.h"
#include "epee/int-util.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_core/service_node_rules.h"
#include "cryptonote_basic/hardfork.h"
#include "checkpoints/checkpoints.h"
#include <exception>
#include <oxenmq/base32z.h>
#include <date/date.h>
#include <fmt/core.h>

#include "common/oxen_integration_test_hooks.h"

#include <fstream>
#include <ctime>
#include <oxenmq/connections.h>
#include <string>
#include <numeric>
#include <stack>
#include <type_traits>

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "daemon"

using namespace cryptonote::rpc;

using nlohmann::json;

namespace daemonize {

namespace {
  enum class input_line_result { yes, no, cancel, back, };

  std::string input_line(std::string const &prompt)
  {
    std::cout << prompt << std::flush;
    std::string result;
#if defined (OXEN_ENABLE_INTEGRATION_TEST_HOOKS)
    integration_test::write_buffered_stdout();
    result = integration_test::read_from_pipe();
#else
    rdln::suspend_readline pause_readline;
    std::cin >> result;
#endif

    return result;
  }

  input_line_result input_line_yes_no_back_cancel(char const *msg)
  {
    std::string prompt = std::string(msg);
    prompt += " (Y/Yes/N/No/B/Back/C/Cancel): ";
    std::string input = input_line(prompt);

    if (command_line::is_yes(input))  return input_line_result::yes;
    if (command_line::is_no(input))   return input_line_result::no;
    if (command_line::is_back(input)) return input_line_result::back;
    return input_line_result::cancel;
  }

  input_line_result input_line_yes_no_cancel(char const *msg)
  {
    std::string prompt = msg;
    prompt += " (Y/Yes/N/No/C/Cancel): ";
    std::string input = input_line(prompt);

    if (command_line::is_yes(input)) return input_line_result::yes;
    if (command_line::is_no(input))  return input_line_result::no;
    return input_line_result::cancel;
  }


  input_line_result input_line_back_cancel_get_input(char const *msg, std::string &input)
  {
    std::string prompt = msg;
    prompt += " (B/Back/C/Cancel): ";
    input   = input_line(prompt);

    if (command_line::is_back(input))   return input_line_result::back;
    if (command_line::is_cancel(input)) return input_line_result::cancel;
    return input_line_result::yes;
  }

  void print_peer(std::string const & prefix, GET_PEER_LIST::peer const & peer, bool pruned_only, bool publicrpc_only)
  {
    if (pruned_only && peer.pruning_seed == 0)
      return;
    if (publicrpc_only && peer.rpc_port == 0)
      return;

    time_t now = std::time(nullptr);
    time_t last_seen = static_cast<time_t>(peer.last_seen);

    std::string elapsed = peer.last_seen == 0 ? "never" : epee::misc_utils::get_time_interval_string(now - last_seen);
    std::string id_str = epee::string_tools::pad_string(epee::string_tools::to_string_hex(peer.id), 16, '0', true);
    std::string addr_str = peer.host + ":" + std::to_string(peer.port);
    std::string rpc_port = peer.rpc_port ? std::to_string(peer.rpc_port) : "-";
    std::string pruning_seed = epee::string_tools::to_string_hex(peer.pruning_seed);
    tools::msg_writer() << fmt::format("{:<10} {:<25} {:<25} {:<5} %{:-4} {}", prefix, id_str, addr_str, rpc_port, pruning_seed, elapsed);
  }

  void print_block_header(block_header_response const & header)
  {
    tools::success_msg_writer()
      << "timestamp: " << header.timestamp << " (" << tools::get_human_readable_timestamp(header.timestamp) << ")" << "\n"
      << "previous hash: " << header.prev_hash << "\n"
      << "nonce: " << header.nonce << "\n"
      << "is orphan: " << header.orphan_status << "\n"
      << "height: " << header.height << "\n"
      << "depth: " << header.depth << "\n"
      << "hash: " << header.hash << "\n"
      << "difficulty: " << header.difficulty << "\n"
      << "cumulative_difficulty: " << header.cumulative_difficulty << "\n"
      << "POW hash: " << header.pow_hash.value_or("N/A") << "\n"
      << "block size: " << header.block_size << "\n"
      << "block weight: " << header.block_weight << "\n"
      << "long term weight: " << header.long_term_weight << "\n"
      << "num txes: " << header.num_txes << "\n"
      << "reward: " << cryptonote::print_money(header.reward) << "\n"
      << "miner reward: " << cryptonote::print_money(header.miner_reward) << "\n"
      << "service node winner: " << header.service_node_winner << "\n"
      << "miner tx hash: " << header.miner_tx_hash;
  }

  std::string get_human_time_ago(std::chrono::seconds ago, bool abbreviate = false)
  {
    if (ago == 0s)
      return "now";
    auto dt = ago > 0s ? ago : -ago;
    std::string s;
    if (dt < 90s)
      s = std::to_string(dt.count()) + (abbreviate ? "sec" : dt == 1s ? " second" : " seconds");
    else if (dt < 90min)
      s = fmt::format("{:.1f}{:s}", ((float)dt.count()/60), abbreviate ? "min" : " minutes");
    else if (dt < 36h)
      s = fmt::format("{:.1f}{:s}", ((float)dt.count()/3600), abbreviate ? "hr" : " hours");
    else
      s = fmt::format("{:.1f} days", ((float)dt.count()/86400));
    if (abbreviate) {
        if (ago < 0s)
            return s + " (in fut.)";
        return s;
    }
    return s + " " + (ago < 0s ? "in the future" : "ago");
  }

  std::string get_human_time_ago(std::time_t t, std::time_t now, bool abbreviate = false) {
    return get_human_time_ago(std::chrono::seconds{now - t}, abbreviate);
  }
}

rpc_command_executor::rpc_command_executor(
    std::string http_url,
    const std::optional<tools::login>& login)
  : m_rpc{std::in_place_type<cryptonote::rpc::http_client>, http_url}
{
  if (login)
    std::get<cryptonote::rpc::http_client>(m_rpc).set_auth(
        login->username, std::string{login->password.password().view()});
}

rpc_command_executor::rpc_command_executor(oxenmq::OxenMQ& omq, oxenmq::ConnectionID conn)
  : m_rpc{std::move(conn)}, m_omq{&omq}
{}

template <typename Callback>
static auto try_running(Callback code, std::string_view error_prefix) -> std::optional<decltype(code())> {
  try {
    return code();
  } catch (const std::exception& e) {
    tools::fail_msg_writer() << error_prefix << ": " << e.what();
    return std::nullopt;
  }
}

json rpc_command_executor::invoke(
    std::string_view method,
    bool public_method,
    std::optional<json> params,
    bool check_status_ok) {

  json result;

  if (auto* rpc_client = std::get_if<cryptonote::rpc::http_client>(&m_rpc)) {
    result = rpc_client->json_rpc(method, std::move(params));
  } else {
    assert(m_omq);
    auto conn = std::get<oxenmq::ConnectionID>(m_rpc);
    auto endpoint = (public_method ? "rpc." : "admin.") + std::string{method};
    std::promise<json> result_p;
    m_omq->request(conn, endpoint, [&result_p](bool success, auto data) {
        try {
          if (!success)
            throw std::runtime_error{"Request timed out"};
          if (data.size() >= 2 && data[0] == "200")
            result_p.set_value(json::parse(data[1]));
          else
            throw std::runtime_error{"RPC method failed: " + (
                data.empty() ? "empty response" :
                tools::join(" ", data))};
        } catch (...) {
          result_p.set_exception(std::current_exception());
        }
      },
      params ? params->dump() : "{}");

    result = result_p.get_future().get();
  }

  if (check_status_ok) {
    if (auto it = result.find("status");
        it == result.end() || it->get<std::string_view>() != cryptonote::rpc::STATUS_OK)
      throw std::runtime_error{"Received status " + (it == result.end() ? "(empty)" : it->get_ref<const std::string&>()) + " != OK"};
  }

  return result;
}

bool rpc_command_executor::print_checkpoints(uint64_t start_height, uint64_t end_height, bool print_json)
{
  GET_CHECKPOINTS::request  req{start_height, end_height};
  if (req.start_height == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE &&
      req.end_height   == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE)
  {
    req.count = GET_CHECKPOINTS::NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT;
  }
  else if (req.start_height == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE ||
           req.end_height   == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE)
  {
    req.count = 1;
  }
  // Otherwise, neither heights are set to HEIGHT_SENTINEL_VALUE, so get all the checkpoints between start and end

  GET_CHECKPOINTS::response res{};
  if (!invoke<GET_CHECKPOINTS>(std::move(req), res, "Failed to query blockchain checkpoints"))
    return false;

  std::string entry;
  if (print_json) entry.append("{\n\"checkpoints\": [");
  for (size_t i = 0; i < res.checkpoints.size(); i++)
  {
    GET_CHECKPOINTS::checkpoint_serialized &checkpoint = res.checkpoints[i];
    if (print_json)
    {
      entry.append("\n");
      entry.append(epee::serialization::store_t_to_json(checkpoint));
      entry.append(",\n");
    }
    else
    {
      entry.append("[");
      entry.append(std::to_string(i));
      entry.append("]");

      entry.append(" Type: ");
      entry.append(checkpoint.type);

      entry.append(" Height: ");
      entry.append(std::to_string(checkpoint.height));

      entry.append(" Hash: ");
      entry.append(checkpoint.block_hash);
      entry.append("\n");
    }
  }

  if (print_json)
  {
    entry.append("]\n}");
  }
  else
  {
    if (entry.empty())
      entry.append("No Checkpoints");
  }

  tools::success_msg_writer() << entry;
  return true;
}

bool rpc_command_executor::print_sn_state_changes(uint64_t start_height, uint64_t end_height)
{
  GET_SN_STATE_CHANGES::request  req{};
  GET_SN_STATE_CHANGES::response res{};

  req.start_height = start_height;
  req.end_height   = end_height;

  if (!invoke<GET_SN_STATE_CHANGES>(std::move(req), res, "Failed to query service nodes state changes"))
    return false;

  std::stringstream output;

  output << "Service Node State Changes (blocks " << res.start_height << "-" << res.end_height << ")" << std::endl;
  output << " Recommissions:\t\t" << res.total_recommission << std::endl;
  output << " Unlocks:\t\t" << res.total_unlock << std::endl;
  output << " Decommissions:\t\t" << res.total_decommission << std::endl;
  output << " Deregistrations:\t" << res.total_deregister << std::endl;
  output << " IP change penalties:\t" << res.total_ip_change_penalty << std::endl;

  tools::success_msg_writer() << output.str();
  return true;
}

bool rpc_command_executor::print_peer_list(bool white, bool gray, size_t limit, bool pruned_only, bool publicrpc_only) {
  GET_PEER_LIST::response res{};

  if (!invoke<GET_PEER_LIST>({}, res, "Couldn't retrieve peer list"))
    return false;

  if (white)
  {
    auto peer = res.white_list.cbegin();
    const auto end = limit ? peer + std::min(limit, res.white_list.size()) : res.white_list.cend();
    for (; peer != end; ++peer)
    {
      print_peer("white", *peer, pruned_only, publicrpc_only);
    }
  }

  if (gray)
  {
    auto peer = res.gray_list.cbegin();
    const auto end = limit ? peer + std::min(limit, res.gray_list.size()) : res.gray_list.cend();
    for (; peer != end; ++peer)
    {
      print_peer("gray", *peer, pruned_only, publicrpc_only);
    }
  }

  return true;
}

bool rpc_command_executor::print_peer_list_stats() {
  GET_PEER_LIST::response res{};

  if (!invoke<GET_PEER_LIST>({}, res, "Couldn't retrieve peer list"))
    return false;

  tools::msg_writer()
    << "White list size: " << res.white_list.size() << "/" << P2P_LOCAL_WHITE_PEERLIST_LIMIT << " (" << res.white_list.size() *  100.0 / P2P_LOCAL_WHITE_PEERLIST_LIMIT << "%)" << std::endl
    << "Gray list size: " << res.gray_list.size() << "/" << P2P_LOCAL_GRAY_PEERLIST_LIMIT << " (" << res.gray_list.size() *  100.0 / P2P_LOCAL_GRAY_PEERLIST_LIMIT << "%)";

  return true;
}

bool rpc_command_executor::save_blockchain() {
  return invoke_simple<SAVE_BC>("Couldn't save blockchain", "Blockchain saved");
}

bool rpc_command_executor::show_difficulty() {
  auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
  if (!maybe_info)
    return false;
  auto& info = *maybe_info;

  auto msg = tools::success_msg_writer();
  msg <<   "HEIGHT: " << info["height"].get<uint64_t>()
      << ", HASH: " << info["top_block_hash"].get<std::string_view>();
  if (info.value("pulse", false))
    msg << ", PULSE";
  else
    msg << ", DIFF: " << info["difficulty"].get<uint64_t>()
        << ", CUM_DIFF: " << info["cumulative_difficulty"].get<uint64_t>()
        << ", HR: " << info["difficulty"].get<uint64_t>() / info["target"].get<uint64_t>() << " H/s";

  return true;
}

static std::string get_mining_speed(uint64_t hr)
{
  if (hr >= 1e9) return fmt::format("{:.2f} GH/s", hr*1e-9);
  if (hr >= 1e6) return fmt::format("{:.2f} MH/s", hr*1e-6);
  if (hr >= 1e3) return fmt::format("{:.2f} kH/s", hr*1e-3);
  return fmt::format("{:d} H/s", hr);
}

static std::ostream& print_fork_extra_info(std::ostream& o, uint64_t t, uint64_t now, std::chrono::seconds block_time)
{
  double blocks_per_day = 24h / block_time;

  if (t == now)
    return o << " (forking now)";
  if (t < now)
    return o;
  uint64_t dblocks = t - now;
  if (dblocks > blocks_per_day * 30)
    return o;
  o << " (next fork in ";
  if (dblocks <= 30)
    return o << dblocks << " blocks)";
  if (dblocks <= blocks_per_day / 2)
    return o << fmt::format("{:.1f} hours)", dblocks / blocks_per_day * 24);
  return o << fmt::format("{:.1f} days)", dblocks / blocks_per_day);
}

static float get_sync_percentage(uint64_t height, uint64_t target_height)
{
  target_height = target_height ? target_height < height ? height : target_height : height;
  float pc = 100.0f * height / target_height;
  if (height < target_height && pc > 99.9f)
    return 99.9f; // to avoid 100% when not fully synced
  return pc;
}

bool rpc_command_executor::show_status() {
  auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
  if (!maybe_info)
    return false;
  auto& info = *maybe_info;

  auto maybe_hf = try_running([this] { return invoke<HARD_FORK_INFO>(); },
      "Failed to retrieve hard fork info");
  if (!maybe_hf)
    return false;
  auto& hfinfo = *maybe_hf;
  bool has_mining_info = false, mining_active = false;
  long mining_hashrate = 0;

  bool mining_busy = false;
  bool restricted_response = false;
  if (auto it = info.find("start_time"); it != info.end() && it->get<uint64_t>() > 0) // This will only be non-null if we were recognized as admin (which we need for mining info)
  {
    restricted_response = true;
    if (auto maybe_mining_info = try_running([this] { return invoke<MINING_STATUS>(false); }, "Failed to retrieve mining info")) {
      has_mining_info = true;
      auto& mres = *maybe_mining_info;
      if (mres["status"] == STATUS_BUSY)
        mining_busy = true;
      else if (mres["status"] != STATUS_OK) {
        tools::fail_msg_writer() << "Failed to retrieve mining info";
        return false;
      } else {
        mining_active = mres["active"].get<bool>();
        if (mining_active)
          mining_hashrate = mres["speed"].get<long>();
      }
    } else {
      return false;
    }
  }

  std::string my_sn_key;
  int64_t my_decomm_remaining = 0;
  uint64_t my_sn_last_uptime = 0;
  bool my_sn_registered = false, my_sn_staked = false, my_sn_active = false;
  uint16_t my_reason_all = 0, my_reason_any = 0;
  if (info["service_node"].get<bool>()) {
    GET_SERVICE_KEYS::response res{};

    if (!invoke<GET_SERVICE_KEYS>({}, res, "Failed to retrieve service node keys"))
      return false;

    my_sn_key = std::move(res.service_node_pubkey);

    auto maybe_sns = try_running([&] { return invoke<GET_SERVICE_NODES>(json{{"service_node_pubkeys", json::array({my_sn_key})}}); }, "Failed to retrieve service node info");
    if (maybe_sns) {
      if (auto it = maybe_sns->find("service_node_states"); it != maybe_sns->end() && it->is_array() && it->size() > 0) {
        auto& state = it->front();
        my_sn_registered = true;
        my_sn_staked = state["total_contributed"].get<uint64_t>() >= state["staking_requirement"].get<uint64_t>();
        my_sn_active = state["active"].get<bool>();
        my_decomm_remaining = state["earned_downtime_blocks"].get<uint64_t>();
        my_sn_last_uptime = state["last_uptime_proof"].get<uint64_t>();
        my_reason_all = state["last_decommission_reason_consensus_all"].get<uint16_t>();
        my_reason_any = state["last_decommission_reason_consensus_any"].get<uint16_t>();
      }
    }
  }

  uint64_t height = info["height"].get<uint64_t>();
  uint64_t net_height = std::max(info["target_height"].get<uint64_t>(), height);
  std::string bootstrap_msg;

  std::ostringstream str;
  str << "Height: " << height;
  if (height != net_height)
    str << fmt::format("/{} ({:.1f}%)", net_height, get_sync_percentage(height, net_height));

  auto net = info["nettype"].get<std::string_view>();
  if (net == "testnet")     str << " ON TESTNET";
  else if (net == "devnet") str << " ON DEVNET";

  if (height < net_height)
    str << ", syncing";

  if (info.value("was_bootstrap_ever_used", false))
  {
    str << ", bootstrap " << info["bootstrap_daemon_address"].get<std::string_view>();
    if (info.value("untrusted", false)) {
      auto hwb = info["height_without_bootstrap"].get<uint64_t>();
      str << fmt::format(", local height: {} ({:.1f}%)", hwb, get_sync_percentage(hwb, net_height));
    }
    else
      str << " was used";
  }

  auto hf_version = hfinfo["version"].get<uint8_t>();
  if (hf_version < HF_VERSION_PULSE && !has_mining_info)
    str << ", mining info unavailable";
  if (has_mining_info && !mining_busy && mining_active)
    str << ", mining at " << get_mining_speed(mining_hashrate);

  if (hf_version < HF_VERSION_PULSE)
    str << ", net hash " << get_mining_speed(info["difficulty"].get<uint64_t>() / info["target"].get<uint64_t>());

  str << ", v" << info["version"].get<std::string_view>();
  str << "(net v" << +hf_version << ')';
  auto earliest = hfinfo.value("earliest_height", uint64_t{0});
  if (earliest)
    print_fork_extra_info(str, earliest, net_height, 1s * info["target"].get<uint64_t>());

  std::time_t now = std::time(nullptr);

  if (restricted_response)
  {
    std::chrono::seconds uptime{now - info["start_time"].get<std::time_t>()};
    str << ", " << info["outgoing_connections_count"].get<int>() << "(out)+" << info["incoming_connections_count"].get<int>() << "(in) connections"
      << ", uptime "
      << tools::friendly_duration(uptime);
  }

  tools::success_msg_writer() << str.str();

  if (!my_sn_key.empty()) {
    str.str("");
    str << "SN: " << my_sn_key << ' ';
    if (!my_sn_registered)
      str << "not registered";
    else
      str << (!my_sn_staked ? "awaiting" : my_sn_active ? "active" : "DECOMMISSIONED (" + std::to_string(my_decomm_remaining) + " blocks credit)")
        << ", proof: " << (my_sn_last_uptime ? get_human_time_ago(my_sn_last_uptime, now) : "(never)");
    str << ", last pings: ";
    if (auto last_ss_ping = info["last_storage_server_ping"].get<uint64_t>(); last_ss_ping > 0)
        str << get_human_time_ago(last_ss_ping, now, true /*abbreviate*/);
    else
        str << "NOT RECEIVED";
    str << " (storage), ";

    if (auto last_lokinet_ping = info["last_lokinet_ping"].get<uint64_t>(); last_lokinet_ping > 0)
        str << get_human_time_ago(last_lokinet_ping, now, true /*abbreviate*/);
    else
        str << "NOT RECEIVED";
    str << " (lokinet)";

    tools::success_msg_writer() << str.str();

    if (my_sn_registered && my_sn_staked && !my_sn_active && (my_reason_all | my_reason_any)) {
      str.str("Decomm reasons: ");
      if (auto reasons = cryptonote::readable_reasons(my_reason_all); !reasons.empty())
        str << tools::join(", ", reasons);
      if (auto reasons = cryptonote::readable_reasons(my_reason_any & ~my_reason_all); !reasons.empty()) {
        for (auto& r : reasons)
          r += "(some)";
        str << (my_reason_all ? ", " : "") << tools::join(", ", reasons);
      }
      tools::fail_msg_writer() << str.str();
    }
  }

  return true;
}

bool rpc_command_executor::mining_status() {
  auto maybe_mining_info = try_running([this] { return invoke<MINING_STATUS>(false); }, "Failed to retrieve mining info");
  if (!maybe_mining_info)
    return false;

  bool mining_busy = false;
  auto& mres = *maybe_mining_info;
  if (mres["status"] == STATUS_BUSY)
    mining_busy = true;
  else if (mres["status"] != STATUS_OK) {
    tools::fail_msg_writer() << "Failed to retrieve mining info";
    return false;
  }
  bool active = mres["active"].get<bool>();
  long speed = mres["speed"].get<long>();
  if (mining_busy || !active)
    tools::msg_writer() << "Not currently mining";
  else {
    tools::msg_writer() << "Mining at " << get_mining_speed(speed) << " with " << mres["threads_count"].get<int>() << " threads";
    tools::msg_writer() << "Mining address: " << mres["address"].get<std::string_view>();
  }
  tools::msg_writer() << "PoW algorithm: " << mres["pow_algorithm"].get<std::string_view>();

  return true;
}

bool rpc_command_executor::print_connections() {
  auto maybe_conns = try_running([this] { return invoke<GET_CONNECTIONS>(); }, "Failed to retrieve connection info");
  if (!maybe_conns)
    return false;
  auto& conns = *maybe_conns;

  constexpr auto hdr_fmt = "{:<30}{:<8}{:<20}{:<30}{:<25}{:<20}{:<12s}{:<14s}{:<10s}{:<13s}"sv;
  constexpr auto row_fmt = "{:<30}{:<8}{:<20}{:<30}{:<25}{:<20}{:<12.1f}{:<14.1f}{:<10.1f}{:<13.1f}{}{}"sv;
  tools::msg_writer() << fmt::format(hdr_fmt,
      "Remote Host", "Type", "Peer id", "Recv/Sent (inactive,sec)", "State", "Livetime(sec)",
      "Down (kB/sec)", "Down(now)", "Up (kB/s)", "Up(now)");

  for (auto& info : conns)
  {
    std::string address = info["incoming"].get<bool>() ? "INC " : "OUT ";
    address += info["ip"].get<std::string_view>();
    address += ':';
    address += tools::int_to_string(info["port"].get<uint16_t>());
    tools::msg_writer() << fmt::format(row_fmt,
        address,
        info["address_type"].get<epee::net_utils::address_type>(),
        info["peer_id"].get<std::string_view>(),
        fmt::format("{}({}/{})", info["recv_count"].get<uint64_t>(),
          tools::friendly_duration(1ms * info["recv_idle_ms"].get<int64_t>()),
          tools::friendly_duration(1ms * info["send_idle_ms"].get<int64_t>())),
        info["state"].get<std::string_view>(),
        tools::friendly_duration(1ms * info["live_ms"].get<int64_t>()),
        info["avg_download"].get<uint64_t>() / 1000.,
        info["current_download"].get<uint64_t>() / 1000.,
        info["avg_upload"].get<uint64_t>() / 1000.,
        info["current_upload"].get<uint64_t>() / 1000.,
        info.value("localhost", false) ? "[LOCALHOST]" : "",
        info.value("local_ip", false) ? "[LAN]" : "");
  }

  return true;
}

bool rpc_command_executor::print_net_stats()
{
  auto maybe_stats = try_running([this] { return invoke<GET_NET_STATS>(); }, "Failed to retrieve net statistics");
  auto maybe_limit = try_running([this] { return invoke<GET_LIMIT>(); }, "Failed to retrieve bandwidth limits");
  if (!maybe_stats || !maybe_limit)
    return false;
  auto& stats = *maybe_stats;
  auto& limit = *maybe_limit;
  auto uptime = time(nullptr) - stats["start_time"].get<std::time_t>();

  for (bool in : {true, false}) {
    auto bytes = stats[in ? "total_bytes_in" : "total_bytes_out"].get<uint64_t>();
    double average = uptime > 0 ? bytes / (double) uptime : 0.0;
    uint64_t lim = limit[in ? "limit_down" : "limit_up"].get<uint64_t>() * 1024; // convert to bytes, as limits are always kB/s
    tools::success_msg_writer() << fmt::format("{} {} in {} packets, average {}/s = {:.2f}% of the limit of {}/s",
        in ? "Received" : "Sent",
        tools::get_human_readable_bytes(bytes),
        stats[in ? "total_packets_in" : "total_packets_out"].get<uint64_t>(),
        tools::get_human_readable_bytes(average),
        average / lim * 100.0,
        tools::get_human_readable_bytes(lim));
  }

  return true;
}

bool rpc_command_executor::print_blockchain_info(int64_t start_block_index, uint64_t end_block_index) {
  GET_BLOCK_HEADERS_RANGE::request req{};
  GET_BLOCK_HEADERS_RANGE::response res{};

  // negative: relative to the end
  if (start_block_index < 0)
  {
    auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
    if (!maybe_info)
      return false;
    auto& info = *maybe_info;

    if (start_block_index < 0 && -start_block_index >= info["height"].get<int64_t>())
    {
      tools::fail_msg_writer() << "start offset is larger than blockchain height";
      return false;
    }

    start_block_index += info["height"].get<int64_t>();
    end_block_index += start_block_index - 1;
  }

  req.start_height = start_block_index;
  req.end_height = end_block_index;
  req.fill_pow_hash = false;

  if (!invoke<GET_BLOCK_HEADERS_RANGE>(std::move(req), res, "Failed to retrieve block headers"))
    return false;

  bool first = true;
  for (auto & header : res.headers)
  {
    if (first)
      first = false;
    else
      tools::msg_writer() << "\n";

    tools::msg_writer()
      << "height: " << header.height << ", timestamp: " << header.timestamp << " (" << tools::get_human_readable_timestamp(header.timestamp) << ")"
      << ", size: " << header.block_size << ", weight: " << header.block_weight << " (long term " << header.long_term_weight << "), transactions: " << header.num_txes
      << "\nmajor version: " << (unsigned)header.major_version << ", minor version: " << (unsigned)header.minor_version
      << "\nblock id: " << header.hash << ", previous block id: " << header.prev_hash
      << "\ndifficulty: " << header.difficulty << ", nonce " << header.nonce << ", reward " << cryptonote::print_money(header.reward) << "\n";
  }

  return true;
}

bool rpc_command_executor::print_quorum_state(uint64_t start_height, uint64_t end_height)
{
  GET_QUORUM_STATE::request req{};
  GET_QUORUM_STATE::response res{};

  req.start_height = start_height;
  req.end_height   = end_height;
  req.quorum_type  = GET_QUORUM_STATE::ALL_QUORUMS_SENTINEL_VALUE;

  if (!invoke<GET_QUORUM_STATE>(std::move(req), res, "Failed to retrieve quorum state"))
    return false;

  std::string output;
  output.append("{\n\"quorums\": [");
  for (GET_QUORUM_STATE::quorum_for_height const &quorum : res.quorums)
  {
    output.append("\n");
    output.append(epee::serialization::store_t_to_json(quorum));
    output.append(",\n");
  }
  output.append("]\n}");
  tools::success_msg_writer() << output;
  return true;
}


bool rpc_command_executor::set_log_level(int8_t level) {
  SET_LOG_LEVEL::response res{};
  if (!invoke<SET_LOG_LEVEL>({level}, res, "Failed to set log level"))
    return false;

  tools::success_msg_writer() << "Log level is now " << std::to_string(level);

  return true;
}

bool rpc_command_executor::set_log_categories(std::string categories) {
  SET_LOG_CATEGORIES::response res{};

  if (!invoke<SET_LOG_CATEGORIES>({std::move(categories)}, res, "Failed to set log categories"))
    return false;

  tools::success_msg_writer() << "Log categories are now " << res.categories;

  return true;
}

bool rpc_command_executor::print_height() {
  if (auto height = try_running([this] {
    return invoke<GET_HEIGHT>().at("height").get<int>();
  }, "Failed to retrieve height")) {
    tools::success_msg_writer() << *height;
    return true;
  }
  return false;
}

bool rpc_command_executor::print_block(GET_BLOCK::request&& req, bool include_hex) {
  req.fill_pow_hash = true;
  GET_BLOCK::response res{};

  if (!invoke<GET_BLOCK>(std::move(req), res, "Block retrieval failed"))
    return false;

  if (include_hex)
    tools::success_msg_writer() << res.blob << std::endl;
  print_block_header(res.block_header);
  tools::success_msg_writer() << res.json << "\n";

  return true;
}

bool rpc_command_executor::print_block_by_hash(const crypto::hash& block_hash, bool include_hex) {
  GET_BLOCK::request req{};
  req.hash = tools::type_to_hex(block_hash);
  return print_block(std::move(req), include_hex);
}

bool rpc_command_executor::print_block_by_height(uint64_t height, bool include_hex) {
  GET_BLOCK::request req{};
  req.height = height;
  return print_block(std::move(req), include_hex);
}

bool rpc_command_executor::print_transaction(const crypto::hash& transaction_hash,
  bool include_metadata,
  bool include_hex,
  bool include_json) {

  auto maybe_tx = try_running([this, &transaction_hash] {
    return invoke<GET_TRANSACTIONS>(json{
      {"tx_hashes", json::array({tools::type_to_hex(transaction_hash)})},
      {"split", true}});
  }, "Transaction retrieval failed");
  if (!maybe_tx)
    return false;

  auto& txi = *maybe_tx;
  auto txs = txi["txs"];
  if (txs.size() != 1) {
    tools::fail_msg_writer() << "Transaction wasn't found: " << transaction_hash << "\n";
    return true;
  }

  auto tx = txs.front();
  auto prunable_hash = tx.value<std::string_view>("prunable_hash", ""sv);
  auto prunable_hex = tx.value<std::string_view>("prunable", ""sv);
  bool pruned = !prunable_hash.empty() && prunable_hex.empty();

  bool in_pool = tx["in_pool"].get<bool>();
  if (in_pool)
    tools::success_msg_writer() << "Found in pool";
  else
    tools::success_msg_writer() << "Found in blockchain at height " << tx["block_height"].get<uint64_t>() << (pruned ? " (pruned)" : "");

  auto pruned_hex = tx["pruned"].get<std::string_view>(); // Always included with req.split=true

  std::optional<cryptonote::transaction> t;
  if (include_metadata || include_json)
  {
    if (oxenmq::is_hex(pruned_hex) && oxenmq::is_hex(prunable_hex))
    {
      std::string blob = oxenmq::from_hex(pruned_hex);
      if (!prunable_hex.empty())
        blob += oxenmq::from_hex(prunable_hex);

      bool parsed = pruned
        ? cryptonote::parse_and_validate_tx_base_from_blob(blob, t.emplace())
        : cryptonote::parse_and_validate_tx_from_blob(blob, t.emplace());
      if (!parsed)
      {
        tools::fail_msg_writer() << "Failed to parse transaction data";
        t.reset();
      }
    }
  }

  // Print metadata if requested
  if (include_metadata)
  {
    if (!in_pool) {
      auto ts = tx["block_timestamp"].get<std::time_t>();
      tools::msg_writer() << "Block timestamp: " << ts << " (" << tools::get_human_readable_timestamp(ts) << ")";
    }
    tools::msg_writer() << "Size: " << tx["size"].get<int>();
    if (t)
      tools::msg_writer() << "Weight: " << cryptonote::get_transaction_weight(*t);
  }

  // Print raw hex if requested
  if (include_hex)
    tools::success_msg_writer() << pruned_hex << prunable_hex << '\n';

  // Print json if requested
  if (include_json && t)
      tools::success_msg_writer() << cryptonote::obj_to_json_str(*t) << '\n';

  return true;
}

bool rpc_command_executor::is_key_image_spent(const std::vector<crypto::key_image>& ki) {

  auto maybe_spent = try_running([this, &ki] {
      auto kis = json::array();
      for (auto& k : ki) kis.push_back(tools::type_to_hex(k));
      return invoke<IS_KEY_IMAGE_SPENT>(json{{"key_images", std::move(kis)}}); },
    "Failed to retrieve key image status");
  if (!maybe_spent)
    return false;
  auto& spent_status = (*maybe_spent)["spent_status"];

  if (spent_status.size() != ki.size()) {
    tools::fail_msg_writer() << "key image status could not be determined\n";
    return false;
  }

  for (size_t i = 0; i < ki.size(); i++) {
    int status = spent_status[i].get<int>();
    tools::success_msg_writer() << ki[i] << ": "
      << (status == 0 ? "unspent" : status == 1 ? "spent" : status == 2 ? "spent (in pool)" : "unknown");
  }
  return true;
}

static void print_pool(const json& txs) {
  if (txs.empty())
  {
    tools::msg_writer() << "Pool is empty\n";
    return;
  }
  const time_t now = time(nullptr);
  tools::msg_writer() << txs.size() << " Transactions:\n";
  std::vector<std::string> lines;
  for (auto &tx : txs)
  {
    std::vector<std::string_view> status;
    if (tx.value("blink", false)) status.push_back("blink"sv);
    status.push_back(tx["relayed"].get<bool>() ? "relayed"sv : "not relayed"sv);
    if (tx.value("do_not_relay", false)) status.push_back("do not relay"sv);
    if (tx.value("double_spend_seen", false)) status.push_back("double spend"sv);
    if (tx.value("kept_by_block", false)) status.push_back("from popped block"sv);

    lines.clear();
    lines.push_back(tx["tx_hash"].get_ref<const std::string&>() + ":"s);
    lines.push_back(fmt::format("size/weight: {}/{}", tx["size"].get<int>(), tx["weight"].get<int>()));
    lines.push_back(fmt::format("fee: {} ({}/byte)",
          cryptonote::print_money(tx["fee"].get<uint64_t>()), cryptonote::print_money(tx["fee"].get<double>() / tx["weight"].get<double>())));
    lines.push_back(fmt::format("received: {} ({})", tx["received_timestamp"].get<std::time_t>(), get_human_time_ago(tx["received_timestamp"].get<std::time_t>(), now)));
    lines.push_back("status: " + tools::join(", ", status));
    lines.push_back(fmt::format("top required block: {} ({})", tx["max_used_height"].get<uint64_t>(), tx["max_used_block"]));
    if (tx.count("last_failed_height"))
      lines.push_back(fmt::format("last failed block: {} ({})", tx["last_failed_height"].get<uint64_t>(), tx["last_failed_block"].get<std::string_view>()));
    if (auto extra = tx.find("extra"); extra != tx.end()) {
      lines.push_back("transaction extra: ");
      for (auto c : extra->dump(2)) {
        if (c == '\n')
          lines.back() += "\n    "sv;
        else
          lines.back() += c;
      }
    }
    tools::msg_writer() << tools::join("\n    ", lines) << "\n";
  }
}

bool rpc_command_executor::print_transaction_pool(bool long_format) {
  json args{{"memory_pool", true}};
  if (long_format) args["tx_extra"] = true;
  auto maybe_pool = try_running([this, &args] { return invoke<GET_TRANSACTIONS>(args); },
      "Failed to retrieve transaction pool details");
  if (!maybe_pool)
    return false;
  auto& pool = *maybe_pool;

  print_pool(pool["txs"]);

  if (long_format) {
    // We used to have a warning here when we had transactions but no key_images; but that can
    // happen on Oxen with 0-output tx state change transactions.

    if (!pool["mempool_key_images"].empty())
    {
      tools::msg_writer() << "\nSpent key images: ";
      for (const auto& [key, tx_hashes] : pool["mempool_key_images"].items())
      {
        tools::msg_writer() << "key image: " << key;
        if (tx_hashes.size() == 1)
          tools::msg_writer() << "  tx: " << tx_hashes.front().get<std::string_view>();
        else if (tx_hashes.empty())
          tools::msg_writer() << "  WARNING: spent key image has no txs associated!";
        else
        {
          tools::msg_writer() << fmt::format("  NOTE: key image for multiple transactions ({}):", tx_hashes.size());
          for (const auto& txid : tx_hashes)
            tools::msg_writer() << "  - " << txid.get<std::string_view>();
        }
      }
      if (pool["txs"].empty())
        tools::msg_writer() << "WARNING: Inconsistent pool state - key images but no no transactions";
    }
  }

  return true;
}

bool rpc_command_executor::print_transaction_pool_stats() {

  auto full_reward_zone = try_running([this] {
    return invoke<GET_INFO>().at("block_size_limit").get<uint64_t>() / 2;
  }, "Failed to retrieve node info");
  if (!full_reward_zone)
    return false;

  auto maybe_stats = try_running([this] { return invoke<GET_TRANSACTION_POOL_STATS>(json{{"include_unrelayed", true}}); },
      "Failed to retrieve transaction pool statistics");
  if (!maybe_stats)
    return false;
  auto& pstats = maybe_stats->at("pool_stats");

  size_t n_transactions = pstats["txs_total"].get<int>();
  const uint64_t now = time(NULL);
  auto bytes_total = pstats["bytes_total"].get<uint64_t>();
  size_t avg_bytes = n_transactions ? bytes_total / n_transactions : 0;

  std::string backlog_message = "no backlog";
  if (bytes_total > *full_reward_zone)
  {
    uint64_t backlog = (bytes_total + *full_reward_zone - 1) / *full_reward_zone;
    backlog_message = "estimated " + std::to_string(backlog) + " block (" + std::to_string(backlog * TARGET_BLOCK_TIME / 1min) + " minutes)";
  }

  uint64_t fee_total = pstats["fee_total"].get<uint64_t>();
  std::time_t oldest = pstats["oldest"].get<std::time_t>();
  tools::msg_writer() << n_transactions << " tx(es), "
    << bytes_total << " bytes total (min " << pstats["bytes_min"].get<uint64_t>() << ", max " << pstats["bytes_max"].get<uint64_t>()
    << ", avg " << avg_bytes << ", median " << pstats["bytes_med"].get<uint64_t>() << ')'
    << '\n'
    << "fees " << cryptonote::print_money(fee_total) << " (avg " << cryptonote::print_money(n_transactions ? fee_total / n_transactions : 0) << " per tx, "
    << cryptonote::print_money(bytes_total ? fee_total / bytes_total : 0) << " per byte)"
    << '\n'
    << pstats["num_double_spends"].get<uint64_t>() << " double spends, "
    << pstats["num_not_relayed"].get<uint64_t>() << " not relayed, "
    << pstats["num_failing"].get<uint64_t>() << " failing, "
    << pstats["num_10m"].get<uint64_t>() << " older than 10 minutes (oldest "
    << (oldest == 0 ? "-" : get_human_time_ago(oldest, now)) << "), "
    << backlog_message;

  auto histo = pstats["histo"].get<std::vector<std::pair<uint64_t, uint64_t>>>();
  if (n_transactions > 1 && !histo.empty())
  {
    std::array<uint64_t, 11> times;
    bool last_is_gt = false;
    if (auto it = pstats.find("histo_98pc"); it != pstats.end())
    {
      auto histo98 = it->get<uint64_t>();
      for (size_t i = 0; i < 11; i++)
        times[i] = i * histo98 / 9;
      last_is_gt = true;
    }
    else
    {
      auto histo_max = pstats["histo_max"].get<uint64_t>();
      for (size_t i = 0; i < 11; i++)
        times[i] = i * histo_max / 10;
    }

    constexpr auto hist_fmt = "{:>10} - {:<14} {:>7} {:>11}"sv;
    tools::msg_writer() << fmt::format("{:^23}     {:>7} {:>11}", "Age", "Txes", "Bytes");
    for (size_t i = 0; i < 10; i++)
      tools::msg_writer()
        << fmt::format(hist_fmt,
            get_human_time_ago(times[i] * 1s, true),
            (last_is_gt && i == 10 ? "" : get_human_time_ago(times[i+1] * 1s, true) + " ago"),
            histo[i].first,
            histo[i].second);
  }
  tools::msg_writer();

  return true;
}

bool rpc_command_executor::start_mining(const cryptonote::account_public_address& address, int num_threads, int num_blocks, cryptonote::network_type nettype) {
  json args{
    {"num_blocks", num_blocks},
    {"threads_count", num_threads},
    {"miner_address", cryptonote::get_account_address_as_str(nettype, false, address)}};
  if (!try_running([this, &args] { return invoke<START_MINING>(args); }, "Unable to start mining"))
    return false;

  tools::success_msg_writer()
    << fmt::format("Mining started with {} thread(s).", std::max(num_threads, 1))
    << (num_blocks ? fmt::format(" Will stop after {} blocks", num_blocks) : "");
  return true;
}

bool rpc_command_executor::stop_mining() {
  return invoke_simple<STOP_MINING>("Couldn't stop mining", "Mining stopped");
}

bool rpc_command_executor::stop_daemon()
{
  return invoke_simple<STOP_DAEMON>("Couldn't stop daemon", "Stop signal sent");
}

bool rpc_command_executor::get_limit()
{
  auto maybe_limit = try_running([this] { return invoke<GET_LIMIT>(); }, "Failed to retrieve current traffic limits");
  if (!maybe_limit)
    return false;
  auto& limit = *maybe_limit;

  tools::msg_writer() << fmt::format("Current limits are {} kiB/s down, {} kiB/s up",
      limit["limit_down"].get<uint64_t>(), limit["limit_up"].get<uint64_t>());
  return true;
}

bool rpc_command_executor::set_limit(int64_t limit_down, int64_t limit_up)
{
  json args{
    {"limit_down", limit_down},
    {"limit_up", limit_up}};
  auto maybe_limit = try_running([this, &args] { return invoke<SET_LIMIT>(args); }, "Failed to set traffic limits");
  if (!maybe_limit)
    return false;
  auto& limit = *maybe_limit;

  tools::success_msg_writer() << fmt::format("New limits are {} kiB/s down, {} kiB/s up",
    limit["limit_down"].get<uint64_t>(), limit["limit_up"].get<uint64_t>());
  return true;
}


bool rpc_command_executor::out_peers(bool set, uint32_t limit)
{
    OUT_PEERS::request req{set, limit};
	OUT_PEERS::response res{};
    if (!invoke<OUT_PEERS>(std::move(req), res, "Failed to set max out peers"))
      return false;

	const std::string s = res.out_peers == (uint32_t)-1 ? "unlimited" : std::to_string(res.out_peers);
	tools::msg_writer() << "Max number of out peers set to " << s << std::endl;

	return true;
}

bool rpc_command_executor::in_peers(bool set, uint32_t limit)
{
    IN_PEERS::request req{set, limit};
	IN_PEERS::response res{};
    if (!invoke<IN_PEERS>(std::move(req), res, "Failed to set max in peers"))
      return false;

	const std::string s = res.in_peers == (uint32_t)-1 ? "unlimited" : std::to_string(res.in_peers);
	tools::msg_writer() << "Max number of in peers set to " << s << std::endl;

	return true;
}

bool rpc_command_executor::print_bans()
{
    GETBANS::response res{};

    if (!invoke<GETBANS>({}, res, "Failed to retrieve ban list"))
      return false;

    if (!res.bans.empty())
    {
        for (auto i = res.bans.begin(); i != res.bans.end(); ++i)
        {
            tools::msg_writer() << i->host << " banned for " << i->seconds << " seconds";
        }
    }
    else
        tools::msg_writer() << "No IPs are banned";

    return true;
}

bool rpc_command_executor::ban(const std::string &address, time_t seconds, bool clear_ban)
{
    SETBANS::request req{};
    SETBANS::response res{};

    req.bans.emplace_back();
    auto& ban = req.bans.back();
    ban.host = address;
    ban.ip = 0;
    ban.ban = !clear_ban;
    ban.seconds = seconds;

    if (!invoke<SETBANS>(std::move(req), res, clear_ban ? "Failed to clear ban" : "Failed to set ban"))
      return false;

    // TODO(doyle): Work around because integration tests break when using
    // mlog_set_categories(""), so emit the block message using msg writer
    // instead of the logging system.
#if defined(OXEN_ENABLE_INTEGRATION_TEST_HOOKS)
    tools::success_msg_writer() << "Host " << address << (clear_ban ? " unblocked." : " blocked.");
#endif

    return true;
}

bool rpc_command_executor::unban(const std::string &address)
{
    return ban(std::move(address), 0, true);
}

bool rpc_command_executor::banned(const std::string &address)
{
    BANNED::request req{};
    BANNED::response res{};

    req.address = address;

    if (!invoke<BANNED>({address}, res, "Failed to retrieve ban information"))
      return false;

    if (res.banned)
      tools::msg_writer() << address << " is banned for " << res.seconds << " seconds";
    else
      tools::msg_writer() << address << " is not banned";

    return true;
}

bool rpc_command_executor::flush_txpool(std::string txid)
{
    FLUSH_TRANSACTION_POOL::request req{};
    FLUSH_TRANSACTION_POOL::response res{};

    if (!txid.empty())
      req.txids.push_back(std::move(txid));

    if (!invoke<FLUSH_TRANSACTION_POOL>(std::move(req), res, "Failed to flush tx pool"))
      return false;

    tools::success_msg_writer() << "Pool successfully flushed";
    return true;
}

bool rpc_command_executor::output_histogram(const std::vector<uint64_t> &amounts, uint64_t min_count, uint64_t max_count)
{
    GET_OUTPUT_HISTOGRAM::request req{};
    GET_OUTPUT_HISTOGRAM::response res{};

    req.amounts = amounts;
    req.min_count = min_count;
    req.max_count = max_count;
    req.unlocked = false;
    req.recent_cutoff = 0;

    if (!invoke<GET_OUTPUT_HISTOGRAM>(std::move(req), res, "Failed to retrieve output histogram"))
      return false;

    std::sort(res.histogram.begin(), res.histogram.end(),
        [](const auto& e1, const auto& e2)->bool { return e1.total_instances < e2.total_instances; });
    for (const auto &e: res.histogram)
    {
        tools::msg_writer() << e.total_instances << "  " << cryptonote::print_money(e.amount);
    }

    return true;
}

bool rpc_command_executor::print_coinbase_tx_sum(uint64_t height, uint64_t count)
{
  GET_COINBASE_TX_SUM::response res{};
  if (!invoke<GET_COINBASE_TX_SUM>({height, count}, res, "Failed to retrieve coinbase info"))
    return false;

  tools::msg_writer() << "Sum of coinbase transactions between block heights ["
    << height << ", " << (height + count) << ") is "
    << cryptonote::print_money(res.emission_amount + res.fee_amount) << " "
    << "consisting of " << cryptonote::print_money(res.emission_amount)
    << " in emissions, and " << cryptonote::print_money(res.fee_amount) << " in fees";
  return true;
}

bool rpc_command_executor::alt_chain_info(const std::string &tip, size_t above, uint64_t last_blocks)
{
  auto height = try_running([this] {
    return invoke<GET_INFO>().at("height").get<uint64_t>();
  }, "Failed to retrieve node info");
  if (!height)
    return false;

  GET_ALTERNATE_CHAINS::response res{};

  if (!invoke<GET_ALTERNATE_CHAINS>({}, res, "Failed to retrieve alt chain data"))
    return false;

  if (tip.empty())
  {
    auto chains = res.chains;
    std::sort(chains.begin(), chains.end(), [](const GET_ALTERNATE_CHAINS::chain_info &info0, GET_ALTERNATE_CHAINS::chain_info &info1){ return info0.height < info1.height; });
    std::vector<size_t> display;
    for (size_t i = 0; i < chains.size(); ++i)
    {
      const auto &chain = chains[i];
      if (chain.length <= above)
        continue;
      const uint64_t start_height = (chain.height - chain.length + 1);
      if (last_blocks > 0 && *height - 1 - start_height >= last_blocks)
        continue;
      display.push_back(i);
    }
    tools::msg_writer() << display.size() << " alternate chains found:";
    for (const size_t idx: display)
    {
      const auto &chain = chains[idx];
      const uint64_t start_height = (chain.height - chain.length + 1);
      tools::msg_writer() << chain.length << " blocks long, from height " << start_height << " (" << (*height - start_height - 1)
          << " deep), diff " << chain.difficulty << ": " << chain.block_hash;
    }
  }
  else
  {
    const uint64_t now = time(NULL);
    const auto i = std::find_if(res.chains.begin(), res.chains.end(), [&tip](GET_ALTERNATE_CHAINS::chain_info &info){ return info.block_hash == tip; });
    if (i != res.chains.end())
    {
      const auto &chain = *i;
      tools::success_msg_writer() << "Found alternate chain with tip " << tip;
      uint64_t start_height = (chain.height - chain.length + 1);
      tools::msg_writer() << chain.length << " blocks long, from height " << start_height << " (" << (*height - start_height - 1)
          << " deep), diff " << chain.difficulty << ":";
      for (const std::string &block_id: chain.block_hashes)
        tools::msg_writer() << "  " << block_id;
      tools::msg_writer() << "Chain parent on main chain: " << chain.main_chain_parent_block;
      GET_BLOCK_HEADER_BY_HASH::request bhreq{};
      GET_BLOCK_HEADER_BY_HASH::response bhres{};
      bhreq.hashes = chain.block_hashes;
      bhreq.hashes.push_back(chain.main_chain_parent_block);
      bhreq.fill_pow_hash = false;
      if (!invoke<GET_BLOCK_HEADER_BY_HASH>(std::move(bhreq), bhres, "Failed to query block header by hash"))
        return false;

      if (bhres.block_headers.size() != chain.length + 1)
      {
        tools::fail_msg_writer() << "Failed to get block header info for alt chain";
        return true;
      }
      uint64_t t0 = bhres.block_headers.front().timestamp, t1 = t0;
      for (const block_header_response &block_header: bhres.block_headers)
      {
        t0 = std::min<uint64_t>(t0, block_header.timestamp);
        t1 = std::max<uint64_t>(t1, block_header.timestamp);
      }
      const uint64_t dt = t1 - t0;
      const uint64_t age = std::max(dt, t0 < now ? now - t0 : 0);
      tools::msg_writer() << "Age: " << tools::get_human_readable_timespan(std::chrono::seconds(age));
      if (chain.length > 1)
      {
        tools::msg_writer() << "Time span: " << tools::get_human_readable_timespan(std::chrono::seconds(dt));
        cryptonote::difficulty_type start_difficulty = bhres.block_headers.back().difficulty;
        if (start_difficulty > 0)
          tools::msg_writer() << "Approximated " << 100.f * tools::to_seconds(TARGET_BLOCK_TIME) * chain.length / dt << "% of network hash rate";
        else
          tools::fail_msg_writer() << "Bad cmumulative difficulty reported by dameon";
      }
    }
    else
      tools::fail_msg_writer() << "Block hash " << tip << " is not the tip of any known alternate chain";
  }
  return true;
}

bool rpc_command_executor::print_blockchain_dynamic_stats(uint64_t nblocks)
{
  auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
  if (!maybe_info)
    return false;
  auto& info = *maybe_info;

  auto maybe_hf = try_running([this] { return invoke<HARD_FORK_INFO>(); },
      "Failed to retrieve hard fork info");
  if (!maybe_hf)
    return false;
  auto& hfinfo = *maybe_hf;

  GET_BASE_FEE_ESTIMATE::response feres{};
  if (!invoke<GET_BASE_FEE_ESTIMATE>({}, feres, "Failed to retrieve current fee info"))
    return false;

  auto height = info["height"].get<uint64_t>();
  tools::msg_writer() << "Height: " << height << ", diff " << info["difficulty"].get<uint64_t>() << ", cum. diff " << info["cumulative_difficulty"].get<uint64_t>()
      << ", target " << info["target"].get<int>() << " sec" << ", dyn fee " << cryptonote::print_money(feres.fee_per_byte) << "/" << (hfinfo["enabled"].get<bool>() ? "byte" : "kB")
      << " + " << cryptonote::print_money(feres.fee_per_output) << "/out";

  if (nblocks > 0)
  {
    if (nblocks > height)
      nblocks = height;

    GET_BLOCK_HEADERS_RANGE::request bhreq{};
    GET_BLOCK_HEADERS_RANGE::response bhres{};

    bhreq.start_height = height - nblocks;
    bhreq.end_height = height - 1;
    bhreq.fill_pow_hash = false;
    if (!invoke<GET_BLOCK_HEADERS_RANGE>(std::move(bhreq), bhres, "Failed to retrieve block headers"))
      return false;

    double avgdiff = 0;
    double avgnumtxes = 0;
    double avgreward = 0;
    std::vector<uint64_t> weights;
    weights.reserve(nblocks);
    uint64_t earliest = std::numeric_limits<uint64_t>::max(), latest = 0;
    std::map<unsigned, std::pair<unsigned, unsigned>> versions; // version -> {majorcount, minorcount}
    for (const auto &bhr: bhres.headers)
    {
      avgdiff += bhr.difficulty;
      avgnumtxes += bhr.num_txes;
      avgreward += bhr.reward;
      weights.push_back(bhr.block_weight);
      versions[bhr.major_version].first++;
      versions[bhr.minor_version].second++;
      earliest = std::min(earliest, bhr.timestamp);
      latest = std::max(latest, bhr.timestamp);
    }
    avgdiff /= nblocks;
    avgnumtxes /= nblocks;
    avgreward /= nblocks;
    uint64_t median_block_weight = epee::misc_utils::median(weights);
    tools::msg_writer() << "Last " << nblocks << ": avg. diff " << (uint64_t)avgdiff << ", " << (latest - earliest) / nblocks << " avg sec/block, avg num txes " << avgnumtxes
        << ", avg. reward " << cryptonote::print_money(avgreward) << ", median block weight " << median_block_weight;

    std::ostringstream s;
    bool first = true;
    for (auto& v : versions)
    {
      if (first) first = false;
      else s << "; ";
      s << "v" << v.first << " (" << v.second.first << "/" << v.second.second << ")";
    }
    tools::msg_writer() << "Block versions (major/minor): " << s.str();
  }
  return true;
}

bool rpc_command_executor::relay_tx(const std::string &txid)
{
    RELAY_TX::response res{};
    if (!invoke<RELAY_TX>({{txid}}, res, "Failed to relay tx"))
      return false;

    tools::success_msg_writer() << "Transaction successfully relayed";
    return true;
}

bool rpc_command_executor::sync_info()
{
  auto maybe_sync = try_running([this] { return invoke<SYNC_INFO>(); }, "Failed to retrieve sync info");
  if (!maybe_sync)
    return false;
  auto& sync = *maybe_sync;

  uint64_t height = sync["height"].get<uint64_t>();
  uint64_t target = std::max(sync.value("target_height", height), height);
  tools::success_msg_writer() << "Height: " << height << ", target: " << target << " (" << (100.0 * height / target) << "%)";
  auto& spans = sync["spans"];
  auto& peers = sync["peers"];
  uint64_t current_download = 0;
  for (const auto& p: peers)
    current_download += p["current_download"].get<uint64_t>();
  tools::success_msg_writer() << "Downloading at " << current_download/1000.0 << " kB/s";
  if (auto nnps = sync.value("next_needed_pruning_seed", 0))
    tools::success_msg_writer() << "Next needed pruning seed: " << nnps;

  tools::success_msg_writer() << std::to_string(peers.size()) << " peers";
  for (const auto& [cid, p]: peers.items())
  {
    std::string address = epee::string_tools::pad_string(p["ip"].get<std::string>() + ":" + std::to_string(p["port"].get<uint16_t>()), 24);
    uint64_t nblocks = 0, size = 0;
    for (const auto& s: spans) {
      if (s["connection_id"] == cid) {
        nblocks += s["nblocks"].get<uint64_t>();
        size += s["size"].get<uint64_t>();
      }
    }
    tools::success_msg_writer() << address << "  " << p["peer_id"].get<std::string_view>() << "  " <<
      epee::string_tools::pad_string(p["state"].get<std::string>(), 16) << "  " <<
      //epee::string_tools::pad_string(epee::string_tools::to_string_hex(p.info.pruning_seed), 8) << "  " <<
      p["height"].get<uint64_t>() << "  "  <<
      p["current_download"].get<uint64_t>() / 1000. << " kB/s, " <<
      nblocks << " blocks / " << size/1'000'000. << " MB queued";
  }

  uint64_t total_size = 0;
  for (const auto& s: spans)
    total_size += s["size"].get<uint64_t>();
  tools::success_msg_writer() << std::to_string(spans.size()) << " spans, " << total_size/1e6 << " MB";
  if (auto overview = sync["overview"].get<std::string_view>(); overview != "[]"sv)
    tools::success_msg_writer() << overview;
  for (const auto& s: spans)
  {
    auto& c = peers[s["connection_id"].get_ref<const std::string&>()];
    std::string address = "(unknown)";
    if (c.is_object())
      address = c["ip"].get<std::string>() + ":" + std::to_string(c["port"].get<uint16_t>());
    address = epee::string_tools::pad_string(std::move(address), 24);
    //std::string pruning_seed = epee::string_tools::to_string_hex(tools::get_pruning_seed(s.start_block_height, std::numeric_limits<uint64_t>::max(), CRYPTONOTE_PRUNING_LOG_STRIPES));
    auto size = s["size"].get<uint64_t>();
    auto start = s["start_block_height"].get<uint64_t>();
    auto nblocks = s["nblocks"].get<uint64_t>();
    {
      auto writer = tools::success_msg_writer();
      writer << address << "  " << nblocks << /*"/" << pruning_seed <<*/ " (" << start << " - " << (start + nblocks - 1);
      if (size == 0)
        writer << ")  -";
      else
        writer << ", " << size/1000. << " kB)  " << s["rate"].get<uint64_t>() / 1000. << " kB/s (" << s["speed"].get<uint64_t>() / 100. << ")";
    }
  }

  return true;
}

static std::string to_string_rounded(double d, int precision) {
  std::ostringstream ss;
  ss << std::fixed << std::setprecision(precision) << d;
  return ss.str();
}

template <typename E, typename EPrinter>
void print_votes(std::ostream& o, const json& elem, const std::string& key, EPrinter eprint) {
  std::vector<E> voted, missed;
  if (auto it = elem.find(key); it != elem.end()) {
    (*it)["voted"].get_to(voted);
    (*it)["missed"].get_to(missed);
  }
  if (voted.empty() && missed.empty())
    o << "(Awaiting votes from service node)";
  else {
    o << voted.size() << " voted";
    if (!voted.empty())
      o << " [" << tools::join_transform(" ", voted, eprint) << "]";
    if (missed.empty())
      o << ", none missed.";
    else
      o << ", " << missed.size() << " MISSED VOTES [" << tools::join_transform(" ", missed, eprint) << "]";
  }
}

static void append_printable_service_node_list_entry(cryptonote::network_type nettype, bool detailed_view, uint64_t blockchain_height, uint64_t entry_index, const json& entry, std::string& buffer)
{
  const char indent1[] = "  ";
  const char indent2[] = "    ";
  const char indent3[] = "      ";
  bool is_funded = entry["funded"].get<bool>();

  std::ostringstream stream;

  // Print Funding Status
  {
    stream << indent1 << "[" << entry_index << "] " << "Service Node: " << entry["service_node_pubkey"].get<std::string_view>() << " ";
    if (auto e = entry.find("service_node_version"); e != entry.end())
      stream << "v" << tools::join(".", entry["service_node_version"].get<std::vector<int>>()) << "\n";
    else
      stream << "v(unknown)\n";

    if (detailed_view)
    {
      stream << indent2 << "Total Contributed/Staking Requirement: " << cryptonote::print_money(entry["total_contributed"].get<uint64_t>())
        << "/" << cryptonote::print_money(entry["staking_requirement"].get<uint64_t>()) << "\n";
      if (auto it = entry.find("total_reserved"); it != entry.end())
        stream << indent2 << "Total Reserved: " << cryptonote::print_money(it->get<uint64_t>()) << "\n";
    }
  }

  // Print expiry information
  uint64_t const now = time(nullptr);
  {
    auto expiry_height = entry["requested_unlock_height"].get<uint64_t>();

    stream << indent2 << "Registration: Hardfork Version: " << entry["registration_hf_version"].get<int>()
      << "; Height: " << entry["registration_height"].get<uint64_t>()
      << "; Expiry: ";
    if (expiry_height == service_nodes::KEY_IMAGE_AWAITING_UNLOCK_HEIGHT)
        stream << "Staking Infinitely (stake unlock not requested)\n";
    else
    {
      uint64_t delta_height = (blockchain_height >= expiry_height) ? 0 : expiry_height - blockchain_height;
      auto expiry_epoch_time = now + (delta_height * tools::to_seconds(TARGET_BLOCK_TIME));
      stream << expiry_height << " (in " << delta_height << ") blocks\n";

      stream << indent2 << "Expiry Date (estimated): " <<
          date::format("%Y-%m-%d %I:%M:%S %p UTC", std::chrono::system_clock::from_time_t(expiry_epoch_time)) <<
          " (" << get_human_time_ago(expiry_epoch_time, now) << ")\n";
    }
  }

  if (detailed_view && is_funded) // Print reward status
  {
    stream << indent2 << "Last Reward (Or Penalty) At (Height/TX Index): " << entry["last_reward_block_height"].get<uint64_t>() << "/" << entry["last_reward_transaction_index"].get<uint64_t>() << "\n";
  }

  if (detailed_view) // Print operator information
  {
    stream << indent2 << "Operator Fee: " << to_string_rounded(entry["operator_fee"].get<int>() / 1000., 3) << "%\n";
    stream << indent2 << "Operator Address: " << entry["operator_address"].get<std::string_view>() << "\n";
  }

  if (is_funded) // Print service node tests
  {
    auto proof_time = entry.value("last_uptime_proof", uint64_t{0});
    epee::console_colors uptime_proof_color = proof_time ? epee::console_color_red : epee::console_color_green;

    stream << indent2 << "Last Uptime Proof Received: " <<
      (proof_time == 0 ? "(Awaiting confirmation from network)" :
       get_human_time_ago(proof_time, time(nullptr)));

    //
    // NOTE: Node Identification
    //
    stream << "\n";
    stream << indent2 << "IP Address & Ports: ";
    if (entry.value("public_ip", "0.0.0.0"s) == "0.0.0.0")
      stream << "(Awaiting confirmation from network)";
    else
      stream << entry["public_ip"].get<std::string_view>() << " :" << entry["storage_port"].get<uint16_t>() << " (storage https), :"
        << entry["storage_lmq_port"].get<uint16_t>() << " (storage omq), :" << entry["quorumnet_port"].get<uint16_t>() << " (quorumnet)";

    stream << "\n";
    if (detailed_view) {
      auto ed_pk = entry.value("pubkey_ed25519", ""sv);
      stream << indent2 << "Auxiliary Public Keys:\n"
             << indent3 << (ed_pk.empty() ? "(not yet received)"sv : ed_pk) << " (Ed25519)\n"
             << indent3 << (ed_pk.empty() ? "(not yet received)"s : oxenmq::to_base32z(oxenmq::from_hex(ed_pk)) + ".snode") << " (Lokinet)\n"
             << indent3 << entry.value("pubkey_x25519", "(not yet received)"sv) << " (X25519)\n";
    }

    //
    // NOTE: Storage Server Test
    //
    auto print_reachable = [&stream, &now] (const json& j, const std::string& prefix) {
      auto first_unreachable = j.value<time_t>(prefix + "_first_unreachable", 0),
           last_unreachable = j.value<time_t>(prefix + "_last_unreachable", 0),
           last_reachable = j.value<time_t>(prefix + "_last_reachable", 0);

      if (first_unreachable == 0) {
        if (last_reachable == 0)
          stream << "Not yet tested";
        else {
          stream << "Yes (last tested " << get_human_time_ago(last_reachable, now);
          if (last_unreachable)
            stream << "; last failure " << get_human_time_ago(last_unreachable, now);
          stream << ")";
        }
      } else {
        stream << "NO";
        if (!j.value(prefix+"_reachable", false))
          stream << " - FAILING!";
        stream << " (last tested " << get_human_time_ago(last_unreachable, now)
          << "; failing since " << get_human_time_ago(first_unreachable, now);
        if (last_reachable)
          stream << "; last good " << get_human_time_ago(last_reachable, now);
        stream << ")";
      }
      stream << '\n';
    };
    stream << indent2 << "Storage Server Reachable: ";
    print_reachable(entry, "storage_server");
    stream << indent2 << "Lokinet Reachable: ";
    print_reachable(entry, "lokinet");

    //
    // NOTE: Component Versions
    //
    auto show_component_version = [] (const json& j, std::string_view name) {
      if (!j.is_array() || j.front().get<int>() == 0)
        return "("s + std::string{name} + " ping not yet received)"s;
      return tools::join(".", j.get<std::array<int, 3>>());
    };
    stream << indent2 << "Storage Server / Lokinet Router versions: "
      << show_component_version(entry["storage_server_version"], "Storage Server")
      << " / "
      << show_component_version(entry["storage_server_version"], "Lokinet")
      << "\n";

    //
    // NOTE: Print Voting History
    //
    stream << indent2 << "Checkpoints votes: ";
    print_votes<uint64_t>(stream, entry, "checkpoint_votes", [](uint64_t height) { return height; });

    stream << '\n' << indent2 << "Pulse blocks: ";
    print_votes<std::pair<uint64_t, uint8_t>>(stream, entry, "pulse_votes",
        [](const auto& val) { return tools::int_to_string(val.first) + (val.second ? " " + tools::int_to_string(val.second) : ""); });

    auto print_pass_fail = [&stream, &entry](const std::string& key) {
      std::pair<int, int> val;
      auto& [success, fail] = val;
      if (auto it = entry.find(key); it != entry.end())
        it->get_to(val);

      if (!success && !fail)
        stream << "(Awaiting test data)";
      else {
        stream << success << " passes, ";
        if (fail)
          stream << fail << " FAILURES";
        else
          stream << "no failures";
      }
    };

    stream << '\n' << indent2 << "Quorumnet tests: ";
    print_pass_fail("quorumnet_tests");

    stream << '\n' << indent2 << "Timesync tests: ";
    print_pass_fail("timesync_tests");
    stream << '\n';
  }

  if (detailed_view) // Print contributors
  {
    auto n_contributors = entry["contributors"].size();
    stream << indent2 << "Contributors (" << n_contributors << "):\n";
    for (auto& contributor : entry["contributors"])
    {
      stream << indent3 << contributor["address"].get<std::string_view>();
      auto amount = contributor["amount"].get<uint64_t>();
      auto reserved = contributor.value("reserved", amount);
      stream << " (" << cryptonote::print_money(amount, true);
      if (reserved != amount)
        stream << " / " << cryptonote::print_money(reserved, true);
      if (!is_funded || n_contributors > 1) {
        auto required = entry["staking_requirement"].get<uint64_t>();
        stream << " = " << std::round(reserved / (double) required * 10000.) / 100. << "%";
      }
      stream << ")\n";
    }
  }

  //
  // NOTE: Overall status
  //
  if (entry["active"].get<bool>()) {
    stream << indent2 << "Current Status: ACTIVE\n";
    auto downtime = entry["earned_downtime_blocks"].get<uint64_t>();
    stream << indent2 << "Downtime Credits: " << downtime << " blocks"
      << " (about " << to_string_rounded(downtime / (double) BLOCKS_EXPECTED_IN_HOURS(1), 2)  << " hours)";
    if (downtime < service_nodes::DECOMMISSION_MINIMUM)
      stream << " (Note: " << service_nodes::DECOMMISSION_MINIMUM << " blocks required to enable deregistration delay)";
  } else if (is_funded) {
    stream << indent2 << "Current Status: DECOMMISSIONED" ;
    auto reason_all = entry["last_decommission_reason_consensus_all"].get<uint16_t>();
    auto reason_any = entry["last_decommission_reason_consensus_any"].get<uint16_t>();
    if (reason_any)
      stream << " - ";
    if (auto reasons = cryptonote::readable_reasons(reason_all); !reasons.empty())
      stream << tools::join(", ", reasons);
    // Add any "any" reasons that aren't in all with a (some) qualifier
    if (auto reasons = cryptonote::readable_reasons(reason_any & ~reason_all); !reasons.empty()) {
      for (auto& r : reasons)
        r += "(some)";
      stream << (reason_all ? ", " : "") << tools::join(", ", reasons);
    }
    stream << "\n";
    stream << indent2 << "Remaining Decommission Time Until DEREGISTRATION: " << entry["earned_downtime_blocks"].get<uint64_t>() << " blocks";
  } else {
      stream << indent2 << "Current Status: awaiting contributions\n";
  }
  stream << "\n";

  buffer.append(stream.str());
}

bool rpc_command_executor::print_sn(const std::vector<std::string> &args, bool self)
{
    std::vector<std::string> pubkeys;

    bool detailed_view = false;
    for (auto& arg : args)
    {
      if (arg == "+json")
        tools::fail_msg_writer() << "+json is no longer supported";
      else if (arg == "+detail")
        detailed_view = true;
      else if (self) {
        tools::fail_msg_writer() << "print_sn_status takes no pubkey arguments";
        return false;
      } else
        pubkeys.push_back(arg);
    }

    auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
    if (!maybe_info)
      return false;
    auto& info = *maybe_info;

    cryptonote::network_type nettype =
      info.value("mainnet", false) ? cryptonote::MAINNET :
      info.value("devnet", false) ? cryptonote::DEVNET :
      info.value("testnet", false) ? cryptonote::TESTNET :
      cryptonote::UNDEFINED;
    uint64_t curr_height = info["height"].get<uint64_t>();

    std::vector<json> awaiting;
    std::vector<json> registered;

    std::string my_sn_pk;
    if (!self) {
      auto maybe_sns = try_running([&] { return invoke<GET_SERVICE_NODES>(json{{"service_node_pubkeys", pubkeys}}); },
          "Failed to retrieve service node data");
      if (!maybe_sns)
        return false;

      for (auto &entry : (*maybe_sns)["service_node_states"])
      {
        if (entry["total_contributed"].get<uint64_t>() == entry["staking_requirement"].get<uint64_t>())
          registered.push_back(std::move(entry));
        else
          awaiting.push_back(std::move(entry));
      }
    } else {
      auto maybe_sn = try_running([&] { return invoke<GET_SERVICE_NODE_STATUS>(); },
          "Failed to retrieve service node status");
      if (!maybe_sn)
        return false;
      auto& sn = (*maybe_sn)["service_node_state"];
      my_sn_pk = sn["service_node_pubkey"];
      if (sn.find("registration_height") != sn.end()) {
        if (sn["total_contributed"].get<uint64_t>() == sn["staking_requirement"].get<uint64_t>())
          registered.push_back(std::move(sn));
        else
          awaiting.push_back(std::move(sn));
      }
    }

    if (awaiting.size() == 0 && registered.size() == 0)
    {
      if (pubkeys.size() > 0)
        tools::msg_writer() << "No service node is currently known on the network: " << tools::join(", ", pubkeys);
      else if (self)
        tools::msg_writer() << "Service node " << my_sn_pk << " is not currently registered on the network";
      else
        tools::msg_writer() << "No service nodes are currently known on the network";

      return true;
    }


    std::sort(awaiting.begin(), awaiting.end(), [](const json& a, const json& b) {
        auto a_res = a.find("total_reserved");
        auto b_res = b.find("total_reserved");
        uint64_t total_a = (a_res == a.end() ? a["total_contributed"] : *a_res).get<uint64_t>();
        uint64_t total_b = (b_res == b.end() ? b["total_contributed"] : *b_res).get<uint64_t>();
        uint64_t a_remaining = a["staking_requirement"].get<uint64_t>() - total_a;
        uint64_t b_remaining = b["staking_requirement"].get<uint64_t>() - total_b;

        if (b_remaining == a_remaining)
          return b["portions_for_operator"].get<uint64_t>() < a["portions_for_operator"].get<uint64_t>();

        return b_remaining < a_remaining;
    });

    std::sort(registered.begin(), registered.end(), [](const json& a, const json& b) {
        return std::make_tuple(a["last_reward_block_height"].get<uint64_t>(), a["last_reward_transaction_index"].get<uint64_t>(), a["service_node_pubkey"].get<std::string_view>())
             < std::make_tuple(b["last_reward_block_height"].get<uint64_t>(), b["last_reward_transaction_index"].get<uint64_t>(), b["service_node_pubkey"].get<std::string_view>());
    });

    std::string awaiting_print_data;
    std::string registered_print_data;
    for (size_t i = 0; i < awaiting.size(); i++)
    {
      if (i > 0) awaiting_print_data += '\n';
      append_printable_service_node_list_entry(nettype, detailed_view, curr_height, i, awaiting[i], awaiting_print_data);
    }

    for (size_t i = 0; i < registered.size(); i++)
    {
      if (i > 0) registered_print_data += '\n';
      append_printable_service_node_list_entry(nettype, detailed_view, curr_height, i, registered[i], registered_print_data);
    }

    if (awaiting.size() > 0)
      tools::msg_writer() << "Service Node Awaiting State [" << awaiting.size() << "]\n" << awaiting_print_data;

    if (registered.size() > 0)
      tools::msg_writer() << "Service Node Registration State [" << registered.size() << "]\n"   << registered_print_data;

    return true;
}

bool rpc_command_executor::flush_cache(bool bad_txs, bool bad_blocks)
{
  FLUSH_CACHE::response res{};
  FLUSH_CACHE::request req{};
  req.bad_txs    = bad_txs;
  req.bad_blocks = bad_blocks;
  if (!invoke<FLUSH_CACHE>(std::move(req), res, "Failed to flush TX cache"))
      return false;
  return true;
}

bool rpc_command_executor::print_sn_status(std::vector<std::string> args)
{
  return print_sn(std::move(args), true);
}

bool rpc_command_executor::print_sr(uint64_t height)
{
  GET_STAKING_REQUIREMENT::response res{};
  if (!invoke<GET_STAKING_REQUIREMENT>({height}, res, "Failed to retrieve staking requirements"))
    return false;

  tools::success_msg_writer() << "Staking Requirement: " << cryptonote::print_money(res.staking_requirement);
  return true;
}

bool rpc_command_executor::pop_blocks(uint64_t num_blocks)
{
  POP_BLOCKS::response res{};
  if (!invoke<POP_BLOCKS>({num_blocks}, res, "Popping blocks failed"))
    return false;

  tools::success_msg_writer() << "new height: " << res.height;
  return true;
}

bool rpc_command_executor::print_sn_key()
{
  GET_SERVICE_KEYS::response res{};

  if (!invoke<GET_SERVICE_KEYS>({}, res, "Failed to retrieve service node keys"))
    return false;

  tools::success_msg_writer()
    <<   "Service Node Public Key: " << res.service_node_pubkey
    << "\n     Ed25519 Public Key: " << res.service_node_ed25519_pubkey
    << "\n      X25519 Public Key: " << res.service_node_x25519_pubkey;
  return true;
}

// Returns lowest x such that (STAKING_PORTIONS * x/amount) >= portions
static uint64_t get_amount_to_make_portions(uint64_t amount, uint64_t portions)
{
  uint64_t lo, hi, resulthi, resultlo;
  lo = mul128(amount, portions, &hi);
  if (lo > UINT64_MAX - (STAKING_PORTIONS - 1))
    hi++;
  lo += STAKING_PORTIONS-1;
  div128_64(hi, lo, STAKING_PORTIONS, &resulthi, &resultlo);
  return resultlo;
}

static uint64_t get_actual_amount(uint64_t amount, uint64_t portions)
{
  uint64_t lo, hi, resulthi, resultlo;
  lo = mul128(amount, portions, &hi);
  div128_64(hi, lo, STAKING_PORTIONS, &resulthi, &resultlo);
  return resultlo;
}

bool rpc_command_executor::prepare_registration(bool force_registration)
{
  // RAII-style class to temporarily clear categories and restore upon destruction (i.e. upon returning).
  struct clear_log_categories {
    std::string categories;
    clear_log_categories() { categories = mlog_get_categories(); mlog_set_categories(""); }
    ~clear_log_categories() { mlog_set_categories(categories.c_str()); }
  };
  auto scoped_log_cats = std::unique_ptr<clear_log_categories>(new clear_log_categories());

  // Check if the daemon was started in Service Node or not
  auto maybe_info = try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
  if (!maybe_info)
    return false;
  auto& info = *maybe_info;

  auto maybe_hf = try_running([this] { return invoke<HARD_FORK_INFO>(); },
      "Failed to retrieve hard fork info");
  if (!maybe_hf)
    return false;
  auto& hfinfo = *maybe_hf;

  GET_SERVICE_KEYS::response kres{};
  if (!invoke<GET_SERVICE_KEYS>({}, kres, "Failed to retrieve service node keys"))
    return false;

  if (!info.value("service_node", false))
  {
    tools::fail_msg_writer() << "Unable to prepare registration: this daemon is not running in --service-node mode";
    return false;
  }
  else if (auto last_lokinet_ping = info.value<std::time_t>("last_lokinet_ping", 0);
      last_lokinet_ping < (time(nullptr) - 60) && !force_registration)
  {
    tools::fail_msg_writer() << "Unable to prepare registration: this daemon has not received a ping from lokinet "
                             << (last_lokinet_ping == 0 ? "yet" : "since " + get_human_time_ago(last_lokinet_ping, std::time(nullptr)));
    return false;
  }
  else if (auto last_storage_server_ping = info.value<std::time_t>("last_storage_server_ping", 0);
      last_storage_server_ping < (time(nullptr) - 60) && !force_registration)
  {
    tools::fail_msg_writer() << "Unable to prepare registration: this daemon has not received a ping from the storage server "
                             << (last_storage_server_ping == 0 ? "yet" : "since " + get_human_time_ago(last_storage_server_ping, std::time(nullptr)));
    return false;
  }

  uint64_t block_height = std::max(info["height"].get<uint64_t>(), info["target_height"].get<uint64_t>());
  uint8_t hf_version = hfinfo["version"].get<uint8_t>();
#if defined(OXEN_ENABLE_INTEGRATION_TEST_HOOKS)
  cryptonote::network_type const nettype = cryptonote::FAKECHAIN;
#else
  cryptonote::network_type nettype =
    info.value("mainnet", false) ? cryptonote::MAINNET :
    info.value("devnet", false) ? cryptonote::DEVNET :
    info.value("testnet", false) ? cryptonote::TESTNET :
    info["nettype"].get<std::string_view>() == "fakechain" ? cryptonote::FAKECHAIN :
    cryptonote::UNDEFINED;
#endif

  // Query the latest block we've synced and check that the timestamp is sensible, issue a warning if not
  {
    GET_LAST_BLOCK_HEADER::response res{};

    if (!invoke<GET_LAST_BLOCK_HEADER>({}, res, "Get latest block failed, unable to check sync status"))
      return false;

    auto const& header = res.block_header;
    uint64_t const now = time(nullptr);

    if (now >= header.timestamp)
    {
      uint64_t delta = now - header.timestamp;
      if (delta > (60 * 60))
      {
        tools::fail_msg_writer() << "The last block this Service Node knows about was at least " << get_human_time_ago(header.timestamp, now)
                                 << "\nYour node is possibly desynced from the network or still syncing to the network."
                                 << "\n\nRegistering this node may result in a deregistration due to being out of date with the network\n";
      }
    }

    if (block_height >= header.height)
    {
      uint64_t delta = block_height - header.height;
      if (delta > 15)
      {
        tools::fail_msg_writer() << "The last block this Service Node synced is " << delta << " blocks away from the longest chain we know about."
                                 << "\n\nRegistering this node may result in a deregistration due to being out of date with the network\n";
      }
    }
  }

  const uint64_t staking_requirement =
    std::max(service_nodes::get_staking_requirement(nettype, block_height),
             service_nodes::get_staking_requirement(nettype, block_height + 30 * 24)); // allow 1 day

  // anything less than DUST will be added to operator stake
  const uint64_t DUST = MAX_NUMBER_OF_CONTRIBUTORS;
  std::cout << "Current staking requirement: " << cryptonote::print_money(staking_requirement) << " " << cryptonote::get_unit() << std::endl;

  enum struct register_step
  {
    ask_is_solo_stake = 0,
    is_solo_stake__operator_address_to_reserve,

    is_open_stake__get_operator_fee,
    is_open_stake__do_you_want_to_reserve_other_contributors,
    is_open_stake__how_many_more_contributors,
    is_open_stake__operator_amount_to_reserve,
    is_open_stake__operator_address_to_reserve,
    is_open_stake__contributor_address_to_reserve,
    is_open_stake__contributor_amount_to_reserve,
    is_open_stake__summary_info,
    final_summary,
    cancelled_by_user,
  };

  struct prepare_registration_state
  {
    register_step            prev_step                    = register_step::ask_is_solo_stake;
    bool                     is_solo_stake;
    size_t                   num_participants             = 1;
    uint64_t                 operator_fee_portions        = STAKING_PORTIONS;
    uint64_t                 portions_remaining           = STAKING_PORTIONS;
    uint64_t                 total_reserved_contributions = 0;
    std::vector<std::string> addresses;
    std::vector<uint64_t>    contributions;
  };

  prepare_registration_state state = {};
  std::stack<prepare_registration_state> state_stack;
  state_stack.push(state);

  bool finished = false;
  register_step step = register_step::ask_is_solo_stake;
  for (input_line_result last_input_result = input_line_result::yes; !finished;)
  {
    if (last_input_result == input_line_result::back)
    {
      step = state.prev_step;
      state_stack.pop();
      state = state_stack.top();
      std::cout << std::endl;
    }

    switch(step)
    {
      case register_step::ask_is_solo_stake:
      {
        last_input_result = input_line_yes_no_cancel("Will the operator contribute the entire stake?");
        if(last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        state.is_solo_stake = (last_input_result == input_line_result::yes);
        if (state.is_solo_stake)
        {
          std::cout << std::endl;
          step = register_step::is_solo_stake__operator_address_to_reserve;
        }
        else
        {
          step = register_step::is_open_stake__get_operator_fee;
        }

        state_stack.push(state);
        continue;
      }

      case register_step::is_solo_stake__operator_address_to_reserve:
      {
        std::string address_str;
        last_input_result = input_line_back_cancel_get_input("Enter the oxen address for the solo staker", address_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        state.addresses.push_back(address_str); // the addresses will be validated later down the line
        state.contributions.push_back(STAKING_PORTIONS);
        state.portions_remaining = 0;
        state.total_reserved_contributions += staking_requirement;
        state.prev_step = step;
        step            = register_step::final_summary;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__get_operator_fee:
      {
        std::string operator_fee_str;
        last_input_result = input_line_back_cancel_get_input("Enter operator fee as a percentage of the total staking reward [0-100]%", operator_fee_str);

        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        if (!service_nodes::get_portions_from_percent_str(operator_fee_str, state.operator_fee_portions))
        {
          std::cout << "Invalid value: " << operator_fee_str << ". Should be between [0-100]" << std::endl;
          continue;
        }

        step = register_step::is_open_stake__do_you_want_to_reserve_other_contributors;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__do_you_want_to_reserve_other_contributors:
      {
        last_input_result = input_line_yes_no_back_cancel("Do you want to reserve portions of the stake for other specific contributors?");
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        state.prev_step = step;
        if(last_input_result == input_line_result::yes)
        {
          step = register_step::is_open_stake__how_many_more_contributors;
        }
        else
        {
          std::cout << std::endl;
          step = register_step::is_open_stake__operator_address_to_reserve;
        }

        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__how_many_more_contributors:
      {
        std::string prompt = "Number of additional contributors [1-" + std::to_string(MAX_NUMBER_OF_CONTRIBUTORS - 1) + "]";
        std::string input;
        last_input_result = input_line_back_cancel_get_input(prompt.c_str(), input);

        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        long additional_contributors = strtol(input.c_str(), NULL, 10 /*base 10*/);
        if(additional_contributors < 1 || additional_contributors > (MAX_NUMBER_OF_CONTRIBUTORS - 1))
        {
          std::cout << "Invalid value. Should be between [1-" << (MAX_NUMBER_OF_CONTRIBUTORS - 1) << "]" << std::endl;
          continue;
        }

        std::cout << std::endl;
        state.num_participants += static_cast<size_t>(additional_contributors);
        state.prev_step = step;
        step            = register_step::is_open_stake__operator_address_to_reserve;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__operator_address_to_reserve:
      {
        std::string address_str;
        last_input_result = input_line_back_cancel_get_input("Enter the oxen address for the operator", address_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        state.addresses.push_back(address_str); // the addresses will be validated later down the line
        state.prev_step = step;
        step            = register_step::is_open_stake__operator_amount_to_reserve;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__operator_amount_to_reserve:
      {
        uint64_t min_contribution_portions = service_nodes::get_min_node_contribution_in_portions(hf_version, staking_requirement, 0, 0);
        const uint64_t min_contribution    = get_amount_to_make_portions(staking_requirement, min_contribution_portions);
        std::cout << "Minimum amount that can be reserved: " << cryptonote::print_money(min_contribution) << " " << cryptonote::get_unit() << std::endl;

        std::string contribution_str;
        last_input_result = input_line_back_cancel_get_input("How much oxen does the operator want to reserve in the stake?", contribution_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        uint64_t contribution;
        if(!cryptonote::parse_amount(contribution, contribution_str))
        {
          std::cout << "Invalid amount." << std::endl;
          continue;
        }

        uint64_t portions = service_nodes::get_portions_to_make_amount(staking_requirement, contribution);
        if(portions < min_contribution_portions)
        {
          std::cout << "The operator needs to contribute at least 25% of the stake requirement (" << cryptonote::print_money(min_contribution) << " " << cryptonote::get_unit() << "). Aborted." << std::endl;
          continue;
        }

        if(portions > state.portions_remaining)
        {
          std::cout << "The operator contribution is higher than the staking requirement. Any excess contribution will be locked for the staking duration, but won't yield any additional reward." << std::endl;
          portions = state.portions_remaining;
        }

        state.contributions.push_back(portions);
        state.portions_remaining -= portions;
        state.total_reserved_contributions += get_actual_amount(staking_requirement, portions);
        state.prev_step = step;

        if (state.num_participants > 1)
        {
          step = register_step::is_open_stake__contributor_address_to_reserve;
        }
        else
        {
          step = register_step::is_open_stake__summary_info;
        }

        std::cout << std::endl;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__contributor_address_to_reserve:
      {
        std::string const prompt = "Enter the oxen address for contributor " + std::to_string(state.contributions.size() + 1);
        std::string address_str;
        last_input_result = input_line_back_cancel_get_input(prompt.c_str(), address_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        // the addresses will be validated later down the line
        state.addresses.push_back(address_str);
        state.prev_step = step;
        step            = register_step::is_open_stake__contributor_amount_to_reserve;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__contributor_amount_to_reserve:
      {
        const uint64_t amount_left         = staking_requirement - state.total_reserved_contributions;
        uint64_t min_contribution_portions = service_nodes::get_min_node_contribution_in_portions(hf_version, staking_requirement, state.total_reserved_contributions, state.contributions.size());
        const uint64_t min_contribution    = service_nodes::portions_to_amount(staking_requirement, min_contribution_portions);

        std::cout << "The minimum amount possible to contribute is " << cryptonote::print_money(min_contribution) << " " << cryptonote::get_unit() << std::endl;
        std::cout << "There is " << cryptonote::print_money(amount_left) << " " << cryptonote::get_unit() << " left to meet the staking requirement." << std::endl;

        std::string contribution_str;
        std::string const prompt = "How much oxen does contributor " + std::to_string(state.contributions.size() + 1) + " want to reserve in the stake?";
        last_input_result        = input_line_back_cancel_get_input(prompt.c_str(), contribution_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        uint64_t contribution;
        if (!cryptonote::parse_amount(contribution, contribution_str))
        {
          std::cout << "Invalid amount." << std::endl;
          continue;
        }

        uint64_t portions = service_nodes::get_portions_to_make_amount(staking_requirement, contribution);
        if (portions < min_contribution_portions)
        {
          std::cout << "The amount is too small." << std::endl;
          continue;
        }

        if (portions > state.portions_remaining)
          portions = state.portions_remaining;

        state.contributions.push_back(portions);
        state.portions_remaining -= portions;
        state.total_reserved_contributions += get_actual_amount(staking_requirement, portions);
        state.prev_step = step;

        if (state.contributions.size() == state.num_participants)
          step = register_step::is_open_stake__summary_info;
        else
          step = register_step::is_open_stake__contributor_address_to_reserve;

        std::cout << std::endl;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__summary_info:
      {
        const uint64_t amount_left = staking_requirement - state.total_reserved_contributions;
        std::cout << "Total staking contributions reserved: " << cryptonote::print_money(state.total_reserved_contributions) << " " << cryptonote::get_unit() << std::endl;
        if (amount_left > DUST)
        {
          std::cout << "Your total reservations do not equal the staking requirement." << std::endl;
          std::cout << "You will leave the remaining portion of " << cryptonote::print_money(amount_left) << " " << cryptonote::get_unit() << " open to contributions from anyone, and the Service Node will not activate until the full staking requirement is filled." << std::endl;

          last_input_result = input_line_yes_no_back_cancel("Is this ok?\n");
          if(last_input_result == input_line_result::no || last_input_result == input_line_result::cancel)
          {
            step = register_step::cancelled_by_user;
            continue;
          }

          if(last_input_result == input_line_result::back)
            continue;

          state_stack.push(state);
          state.prev_step = step;
        }

        step = register_step::final_summary;
        continue;
      }

      case register_step::final_summary:
      {
        assert(state.addresses.size() == state.contributions.size());
        const uint64_t amount_left = staking_requirement - state.total_reserved_contributions;

        std::cout << "Summary:" << std::endl;
        std::cout << "Operating costs as % of reward: " << (state.operator_fee_portions * 100.0 / static_cast<double>(STAKING_PORTIONS)) << "%" << std::endl;
        printf("%-16s%-9s%-19s%-s\n", "Contributor", "Address", "Contribution", "Contribution(%)");
        printf("%-16s%-9s%-19s%-s\n", "___________", "_______", "____________", "_______________");

        for (size_t i = 0; i < state.num_participants; ++i)
        {
          const std::string participant_name = (i==0) ? "Operator" : "Contributor " + std::to_string(i);
          uint64_t amount = get_actual_amount(staking_requirement, state.contributions[i]);
          if (amount_left <= DUST && i == 0)
            amount += amount_left; // add dust to the operator.
          printf("%-16s%-9s%-19s%-.9f\n", participant_name.c_str(), state.addresses[i].substr(0,6).c_str(), cryptonote::print_money(amount).c_str(), (double)state.contributions[i] * 100 / (double)STAKING_PORTIONS);
        }

        if (amount_left > DUST)
        {
          printf("%-16s%-9s%-19s%-.2f\n", "(open)", "", cryptonote::print_money(amount_left).c_str(), amount_left * 100.0 / staking_requirement);
        }
        else if (amount_left > 0)
        {
          std::cout << "\nActual amounts may differ slightly from specification. This is due to\n" << std::endl;
          std::cout << "limitations on the way fractions are represented internally.\n" << std::endl;
        }

        std::cout << "\nBecause the actual requirement will depend on the time that you register, the\n";
        std::cout << "amounts shown here are used as a guide only, and the percentages will remain\n";
        std::cout << "the same." << std::endl << std::endl;

        last_input_result = input_line_yes_no_back_cancel("Do you confirm the information above is correct?");
        if(last_input_result == input_line_result::no || last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        if(last_input_result == input_line_result::back)
          continue;

        finished = true;
        continue;
      }

      case register_step::cancelled_by_user:
      {
        std::cout << "Cancel requested in prepare registration. Aborting." << std::endl;
        return true;
      }
    }
  }

  // <operator cut> <address> <fraction> [<address> <fraction> [...]]]
  std::vector<std::string> args;
  args.push_back(std::to_string(state.operator_fee_portions));
  for (size_t i = 0; i < state.num_participants; ++i)
  {
    args.push_back(state.addresses[i]);
    args.push_back(std::to_string(state.contributions[i]));
  }

  for (size_t i = 0; i < state.addresses.size(); i++)
  {
    for (size_t j = 0; j < i; j++)
    {
      if (state.addresses[i] == state.addresses[j])
      {
        std::cout << "Must not provide the same address twice" << std::endl;
        return true;
      }
    }
  }

  scoped_log_cats.reset();

  {
    GET_SERVICE_NODE_REGISTRATION_CMD_RAW::request req{};
    GET_SERVICE_NODE_REGISTRATION_CMD_RAW::response res{};

    req.args = args;
    req.make_friendly = true;
    req.staking_requirement = staking_requirement;

    if (!invoke<GET_SERVICE_NODE_REGISTRATION_CMD_RAW>(std::move(req), res, "Failed to validate registration arguments; "
          "check the addresses and registration parameters and that the Daemon is running with the '--service-node' flag"))
      return false;

    tools::success_msg_writer() << res.registration_cmd;
  }

  return true;
}

bool rpc_command_executor::prune_blockchain()
{
#if 0
    PRUNE_BLOCKCHAIN::response res{};
    if (!invoke<PRUNE_BLOCKCHAIN>({false}, res, "Failed to prune blockchain"))
      return false;

    tools::success_msg_writer() << "Blockchain pruned";
#else
    tools::fail_msg_writer() << "Blockchain pruning is not supported in Oxen yet";
#endif
    return true;
}

bool rpc_command_executor::check_blockchain_pruning()
{
    PRUNE_BLOCKCHAIN::response res{};
    if (!invoke<PRUNE_BLOCKCHAIN>({true}, res, "Failed to check blockchain pruning status"))
      return false;

    tools::success_msg_writer() << "Blockchain is" << (res.pruning_seed ? "" : " not") << " pruned";
    return true;
}

bool rpc_command_executor::set_bootstrap_daemon(
  const std::string &address,
  const std::string &username,
  const std::string &password)
{
    SET_BOOTSTRAP_DAEMON::request req{};
    req.address = address;
    req.username = username;
    req.password = password;

    SET_BOOTSTRAP_DAEMON::response res{};
    if (!invoke<SET_BOOTSTRAP_DAEMON>(std::move(req), res, "Failed to set bootstrap daemon to: " + address))
        return false;

    tools::success_msg_writer()
      << "Successfully set bootstrap daemon address to "
      << (!req.address.empty() ? req.address : "none");
    return true;
}

bool rpc_command_executor::version()
{
  auto version = try_running([this] {
    return invoke<GET_INFO>().at("version").get<std::string>();
  }, "Failed to retrieve node info");
  if (!version)
    return false;
  tools::success_msg_writer() << *version;
  return true;
}

bool rpc_command_executor::test_trigger_uptime_proof()
{
  TEST_TRIGGER_UPTIME_PROOF::request req{};
  TEST_TRIGGER_UPTIME_PROOF::response res{};
  return invoke<TEST_TRIGGER_UPTIME_PROOF>(std::move(req), res, "Failed to trigger uptime proof");
}

}// namespace daemonize
