#include "core_rpc_server_command_parser.h"
#include "oxenmq/bt_serialize.h"

#include <chrono>
#include <oxenmq/base64.h>
#include <oxenmq/hex.h>
#include <type_traits>
#include <utility>

namespace cryptonote::rpc {

  using nlohmann::json;

  namespace {

    // Checks that key names are given in ascending order
    template <typename... Ignore>
    void check_ascending_names(std::string_view name1, std::string_view name2, const Ignore&...) {
      if (!(name2 > name1))
        throw std::runtime_error{"Internal error: request values must be retrieved in ascending order"};
    }

    // Wrapper around a reference for get_values that is used to indicate that the value is
    // required, in which case an exception will be raised if the value is not found.  Usage:
    //
    //     int a_optional = 0, b_required;
    //     get_values(input,
    //         "a", a_optional,
    //         "b", required{b_required},
    //         // ...
    //     );
    template <typename T>
    struct required {
      T& value;
      required(T& ref) : value{ref} {}
    };
    template <typename T>
    constexpr bool is_required_wrapper = false;
    template <typename T>
    constexpr bool is_required_wrapper<required<T>> = true;

    template <typename T>
    constexpr bool is_std_optional = false;
    template <typename T>
    constexpr bool is_std_optional<std::optional<T>> = true;

    using oxenmq::bt_dict_consumer;

    using json_range = std::pair<json::const_iterator, json::const_iterator>;

    // Advances the dict consumer to the first element >= the given name.  Returns true if found,
    // false if it advanced beyond the requested name.  This is exactly the same as
    // `d.skip_until(name)`, but is here so we can also overload an equivalent function for json
    // iteration.
    bool skip_until(oxenmq::bt_dict_consumer& d, std::string_view name) {
      return d.skip_until(name);
    }
    // Equivalent to the above but for a json object iterator.
    bool skip_until(json_range& it_range, std::string_view name) {
      auto& [it, end] = it_range;
      while (it != end && it.key() < name)
        ++it;
      return it != end && it.key() == name;
    }

    // List types that are expandable; for these we emplace_back for each element of the input
    template <typename T> constexpr bool is_expandable_list = false;
    template <typename T> constexpr bool is_expandable_list<std::vector<T>> = true;
// Don't currently need these, but they will work fine if uncommented:
//    template <typename T> constexpr bool is_expandable_list<std::list<T>> = true;
//    template <typename T> constexpr bool is_expandable_list<std::forward_list<T>> = true;
//    template <typename T> constexpr bool is_expandable_list<std::deque<T>> = true;

    // Fixed size elements: tuples, pairs, and std::array's; we accept list input as long as the
    // list length matches exactly.
    template <typename T> constexpr bool is_tuple_like = false;
    template <typename T, size_t N> constexpr bool is_tuple_like<std::array<T, N>> = true;
    template <typename S, typename T> constexpr bool is_tuple_like<std::pair<S, T>> = true;
    template <typename... T> constexpr bool is_tuple_like<std::tuple<T...>> = true;

    template <typename TupleLike, size_t... Is>
    void load_tuple_values(oxenmq::bt_list_consumer&, TupleLike&, std::index_sequence<Is...>);

    // Consumes the next value from the dict consumer into `val`
    template <typename BTConsumer, typename T,
             std::enable_if_t<
                 std::is_same_v<BTConsumer, oxenmq::bt_dict_consumer>
                 || std::is_same_v<BTConsumer, oxenmq::bt_list_consumer>,
                int> = 0>
    void load_value(BTConsumer& c, T& val) {
      if constexpr (std::is_integral_v<T>)
        val = c.template consume_integer<T>();
      else if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>)
        val = c.consume_string_view();
      else if constexpr (is_binary_parameter<T>)
        load_binary_parameter(c.consume_string_view(), true /*allow raw*/, val);
      else if constexpr (is_expandable_list<T>) {
        auto lc = c.consume_list_consumer();
        val.clear();
        while (!lc.is_finished())
          load_value(lc, val.emplace_back());
      }
      else if constexpr (is_tuple_like<T>) {
        auto lc = c.consume_list_consumer();
        load_tuple_values(lc, val, std::make_index_sequence<std::tuple_size_v<T>>{});
      }
      else
        static_assert(std::is_same_v<T, void>, "Unsupported load_value type");
    }
    // Copies the next value from the json range into `val`, and advances the iterator.  Throws
    // on unconvertible values.
    template <typename T>
    void load_value(json_range& r, T& val) {
      auto& key = r.first.key();
      auto& e = *r.first;
      if constexpr (std::is_same_v<T, bool>) {
        if (e.is_boolean())
          val = e.get<bool>();
        else if (e.is_number_unsigned()) {
          // Also accept 0 or 1 for bools (mainly to be compatible with bt-encoding which doesn't
          // have a distinct bool type).
          auto b = e.get<uint64_t>();
          if (b <= 1)
            val = b;
          else
            throw std::domain_error{"Invalid value for '" + key + "': expected boolean"};
        } else {
          throw std::domain_error{"Invalid value for '" + key + "': expected boolean"};
        }
      } else if constexpr (std::is_unsigned_v<T>) {
        if (!e.is_number_unsigned())
          throw std::domain_error{"Invalid value for '" + key + "': non-negative value required"};
        auto i = e.get<uint64_t>();
        if (sizeof(T) < sizeof(uint64_t) && i > std::numeric_limits<T>::max())
          throw std::domain_error{"Invalid value for '" + key + "': value too large"};
        val = i;
      } else if constexpr (std::is_integral_v<T>) {
        if (!e.is_number_integer())
          throw std::domain_error{"Invalid value for '" + key + "': value is not an integer"};
        auto i = e.get<int64_t>();
        if (sizeof(T) < sizeof(int64_t)) {
          if (i < std::numeric_limits<T>::lowest())
            throw std::domain_error{"Invalid value for '" + key + "': negative value magnitude is too large"};
          else if (i > std::numeric_limits<T>::max())
            throw std::domain_error{"Invalid value for '" + key + "': value is too large"};
        }
        val = i;
      } else if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>) {
        val = e.get<std::string_view>();
      } else if constexpr (is_binary_parameter<T> || is_expandable_list<T> || is_tuple_like<T>) {
        try { e.get_to(val); }
        catch (const std::exception& e) { throw std::domain_error{"Invalid values in '" + key + "'"}; }
      } else {
        static_assert(std::is_same_v<T, void>, "Unsupported load type");
      }
      ++r.first;
    }

    template <typename TupleLike, size_t... Is>
    void load_tuple_values(oxenmq::bt_list_consumer& c, TupleLike& val, std::index_sequence<Is...>) {
      (load_value(c, std::get<Is>(val)), ...);
    }

    // Gets the next value from a json object iterator or bt_dict_consumer.  Leaves the iterator at
    // the next value, i.e.  found + 1 if found, or the next greater value if not found.  (NB:
    // nlohmann::json objects are backed by an *ordered* map and so both nlohmann iterators and
    // bt_dict_consumer behave analogously here).
    template <typename In, typename T>
    void get_next_value(In& in, std::string_view name, T& val) {
      if constexpr (std::is_same_v<std::monostate, In>)
        ;
      else if (skip_until(in, name)) {
        if constexpr (is_required_wrapper<T>)
          return load_value(in, val.value);
        else if constexpr (is_std_optional<T>)
          return load_value(in, val.emplace());
        else
          return load_value(in, val);
      }
      if constexpr (is_required_wrapper<T>)
        throw std::runtime_error{"Required key '" + std::string{name} + "' not found"};
    }

    /// Accessor for simple, flat value retrieval from a json or bt_dict_consumer.  In the later
    /// case note that the given bt_dict_consumer will be advanced, so you *must* take care to
    /// process keys in order, both for the keys passed in here *and* for use before and after this
    /// call.
    template <typename Input, typename T, typename... More>
    void get_values(Input& in, std::string_view name, T&& val, More&&... more) {
      if constexpr (std::is_same_v<rpc_input, Input>) {
        if (auto* json_in = std::get_if<json>(&in)) {
          json_range r{json_in->cbegin(), json_in->cend()};
          get_values(r, name, val, std::forward<More>(more)...);
        } else if (auto* dict = std::get_if<bt_dict_consumer>(&in)) {
          get_values(*dict, name, val, std::forward<More>(more)...);
        } else {
          // A monostate indicates that no parameters field was provided at all
          get_values(var::get<std::monostate>(in), name, val, std::forward<More>(more)...);
        }
      } else {
        static_assert(
            std::is_same_v<json_range, Input> ||
            std::is_same_v<bt_dict_consumer, Input> ||
            std::is_same_v<std::monostate, Input>);
        get_next_value(in, name, val);
        if constexpr (sizeof...(More) > 0) {
          check_ascending_names(name, more...);
          get_values(in, std::forward<More>(more)...);
        }
      }
    }
  }

  void parse_request(ONS_RESOLVE& ons, rpc_input in) {
    get_values(in,
        "name_hash", required{ons.request.name_hash},
        "type", required{ons.request.type});
  }

  void parse_request(GET_SERVICE_NODES& sns, rpc_input in) {
    // Remember: key access must be in sorted order (even across get_values() calls).
    get_values(in, "active_only", sns.request.active_only);
    bool fields_dict = false;
    if (auto* json_in = std::get_if<json>(&in)) {
        // Deprecated {"field":true, "field2":true, ...} handling:
      if (auto fit = json_in->find("fields"); fit != json_in->end() && fit->is_object()) {
        fields_dict = true;
        for (auto& [k, v] : fit->items()) {
          if (v.get<bool>()) {
            if (k == "all") {
              sns.request.fields.clear(); // Empty means all
              break; // The old behaviour just ignored everything else if you specified all
            }
            sns.request.fields.insert(k);
          }
        }
      }
    }
    if (!fields_dict) {
      std::vector<std::string_view> fields;
      get_values(in, "fields", fields);
      for (const auto& f : fields)
        sns.request.fields.emplace(f);
      // If the only thing given is "all" then just clear it (as a small optimization):
      if (sns.request.fields.size() == 1 && *sns.request.fields.begin() == "all")
        sns.request.fields.clear();
    }

    get_values(in,
        "limit", sns.request.limit,
        "poll_block_hash", sns.request.poll_block_hash,
        "service_node_pubkeys", sns.request.service_node_pubkeys);
  }
  void parse_request(START_MINING& start_mining, rpc_input in) {
    get_values(in,
        "miner_address", required{start_mining.request.miner_address},
        "num_blocks", start_mining.request.num_blocks,
        "slow_mining", start_mining.request.slow_mining,
        "threads_count", start_mining.request.threads_count);
  }
  void parse_request(GET_OUTPUTS& get_outputs, rpc_input in) {
    get_values(in,
        "as_tuple", get_outputs.request.as_tuple,
        "get_txid", get_outputs.request.get_txid);

    // "outputs" is trickier: for backwards compatibility we need to accept json of:
    //    [{"amount":0,"index":i1}, ...]
    // but that is incredibly wasteful and so we also want the more efficient (and we only accept
    // this for bt, since we don't have backwards compat to worry about):
    //    [i1, i2, ...]
    bool legacy_outputs = false;
    if (auto* json_in = std::get_if<json>(&in)) {
      if (auto outputs = json_in->find("outputs");
          outputs != json_in->end() && !outputs->empty() && outputs->is_array() && outputs->front().is_object()) {
        legacy_outputs = true;
        auto& reqoi = get_outputs.request.output_indices;
        reqoi.reserve(outputs->size());
        for (auto& o : *outputs)
          reqoi.push_back(o["index"].get<uint64_t>());
      }
    }
    if (!legacy_outputs)
      get_values(in, "outputs", get_outputs.request.output_indices);
  }

  void parse_request(GET_TRANSACTION_POOL_STATS& pstats, rpc_input in) {
    get_values(in, "include_unrelayed", pstats.request.include_unrelayed);
  }

  void parse_request(HARD_FORK_INFO& hfinfo, rpc_input in) {
    get_values(in,
        "height", hfinfo.request.height,
        "version", hfinfo.request.version);
    if (hfinfo.request.height && hfinfo.request.version)
      throw std::runtime_error{"Error: at most one of 'height'" + std::to_string(hfinfo.request.height) + "/" + std::to_string(hfinfo.request.version) + " and 'version' may be specified"};
  }

  void parse_request(GET_TRANSACTIONS& get, rpc_input in) {
    // Backwards compat for old stupid "txs_hashes" input name
    if (auto* json_in = std::get_if<json>(&in))
      if (auto it = json_in->find("txs_hashes"); it != json_in->end())
        (*json_in)["tx_hashes"] = std::move(*it);

    std::optional<bool> data;
    get_values(in,
      "data", data,
      "memory_pool", get.request.memory_pool,
      "prune", get.request.prune,
      "split", get.request.split,
      "tx_extra", get.request.tx_extra,
      "tx_hashes", get.request.tx_hashes);

    if (data)
        get.request.data = *data;
    else
        get.request.data = !(get.request.prune || get.request.split);

    if (get.request.memory_pool && !get.request.tx_hashes.empty())
      throw std::runtime_error{"Error: 'memory_pool' and 'tx_hashes' are mutually exclusive"};
  }

  void parse_request(SET_LIMIT& limit, rpc_input in) {
    get_values(in,
        "limit_down", limit.request.limit_down,
        "limit_up", limit.request.limit_up);
    if (limit.request.limit_down < -1)
      throw std::domain_error{"limit_down must be >= -1"};
    if (limit.request.limit_down < -1)
      throw std::domain_error{"limit_up must be >= -1"};
  }

  void parse_request(IS_KEY_IMAGE_SPENT& spent, rpc_input in) {
    get_values(in, "key_images", spent.request.key_images);
  }

  void parse_request(SUBMIT_TRANSACTION& tx, rpc_input in) {
    if (auto* json_in = std::get_if<json>(&in))
      if (auto it = json_in->find("tx_as_hex"); it != json_in->end())
        (*json_in)["tx"] = std::move(*it);

    auto& tx_data = tx.request.tx;
    get_values(in,
        "blink", tx.request.blink,
        "tx", required{tx_data});

    if (tx_data.empty()) // required above will make sure it's specified, but doesn't guarantee against an empty value
      throw std::domain_error{"Invalid 'tx' value: cannot be empty"};

    // tx can be specified as base64, hex, or binary, so try to figure out which one we have by
    // looking at the beginning.
    //
    // An encoded transaction always starts with the version byte, currently 0-4 (though 0 isn't
    // actually used), with higher future values possible.  That means in hex we get something like:
    // `04...` and in base64 we get `B` (because the first 6 bits are 000001, and the b64 alphabet
    // begins at `A` for 0).  Thus the first bytes, for tx versions 0 through 48, are thus:
    //
    // binary: (31 binary control characters through 0x1f ... )          (space) ! " # $ % & ' ( ) * + , - . / 0
    // base64: A A A A B B B B C C C C D D D D E E E E F F F F G G G G H H H H I I I I J J J J K K K K L L L L M
    // hex:    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 3
    //
    // and so we run into the first ambiguity at version 48.  Since we are currently only at version
    // 4 (and Oxen started at version 2) this is likely to be sufficient for an extremely long time.
    //
    // Thus our heuristic:
    //     'A'-'L' => base64
    //     '0'-'2' => hex
    //     \x00-\x2f => bytes
    // anything else we reject as garbage.
    auto tx0 = tx_data.front();
    bool good = false;
    if (tx0 <= 0x2f) {
      good = true;
    } else if (tx0 >= 'A' && tx0 <= 'L') {
      if (oxenmq::is_base64(tx_data)) {
        auto end = oxenmq::from_base64(tx_data.begin(), tx_data.end(), tx_data.begin());
        tx_data.erase(end, tx_data.end());
        good = true;
      }
    } else if (tx0 >= '0' && tx0 <= '2') {
      if (oxenmq::is_hex(tx_data)) {
        auto end = oxenmq::from_hex(tx_data.begin(), tx_data.end(), tx_data.begin());
        tx_data.erase(end, tx_data.end());
        good = true;
      }
    }

    if (!good)
      throw std::domain_error{"Invalid 'tx' value: expected hex, base64, or bytes"};
  }

  void parse_request(GET_BLOCK_HASH& bh, rpc_input in) {
    get_values(in, "heights", bh.request.heights);
    if (bh.request.heights.size() > bh.MAX_HEIGHTS)
      throw std::domain_error{"Error: too many block heights requested at once"};
  }

  void parse_request(GET_PEER_LIST& pl, rpc_input in) {
    get_values(in, "public_only", pl.request.public_only);
  }
}
