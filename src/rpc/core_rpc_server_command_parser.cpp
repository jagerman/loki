#include "core_rpc_server_command_parser.h"

#include <chrono>
#include <oxenmq/base64.h>
#include <oxenmq/hex.h>
#include <type_traits>

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

    // Consumes the next value from the dict consumer into `val`
    template <typename T>
    void load_value(oxenmq::bt_dict_consumer& d, T& val) {
      if constexpr (std::is_integral_v<T>)
        val = d.consume_integer<T>();
      else if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>)
        val = d.consume_string_view();
      else if constexpr (is_binary_parameter<T>)
        load_binary_parameter(d.consume_string_view(), true /*allow raw*/, val);
      else if constexpr (is_binary_vector<T>) {
        val.clear();
        auto lc = d.consume_list_consumer();
        while (!lc.is_finished())
          load_binary_parameter(lc.consume_string_view(), true /*allow raw*/, val.emplace_back());
      }
      else if constexpr (std::is_same_v<T, std::chrono::system_clock::time_point>)
        val = std::chrono::system_clock::time_point{std::chrono::seconds{d.consume_integer<int64_t>()}};
      else if constexpr (std::is_same_v<T, std::vector<std::string>> || std::is_same_v<T, std::vector<std::string_view>>) {
        val.clear();
        auto lc = d.consume_list_consumer();
        while (!lc.is_finished())
          val.emplace_back(lc.consume_string_view());
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
      } else if constexpr (is_binary_parameter<T> || is_binary_vector<T> ||
          std::is_same_v<T, std::vector<std::string>> || std::is_same_v<T, std::vector<std::string_view>>) {
        val = e.get<T>();
      } else if constexpr (std::is_same_v<T, std::chrono::system_clock::time_point>) {
        val = std::chrono::system_clock::time_point{std::chrono::seconds{e.get<int64_t>()}};
      } else {
        static_assert(std::is_same_v<T, void>, "Unsupported load type");
      }
      ++r.first;
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
  }
  void parse_request(STOP_MINING& stop_mining, rpc_input in) {
  }
  void parse_request(MINING_STATUS& mining_status, rpc_input in) {
  }
  void parse_request(GET_TRANSACTION_POOL_STATS& get_transaction_pool_stats, rpc_input in) {
  }
  void parse_request(GET_TRANSACTION_POOL_BACKLOG& get_transaction_pool_backlog, rpc_input in) {
  }
  void parse_request(GET_TRANSACTION_POOL_HASHES& get_transaction_pool_hashes, rpc_input in) {
  }
  void parse_request(GETBLOCKCOUNT& getblockcount, rpc_input in) {
  }
  void parse_request(STOP_DAEMON& stop_daemon, rpc_input in) {
  }
  void parse_request(SAVE_BC& save_bc, rpc_input in) {
  }
  void parse_request(GET_OUTPUTS& get_outputs, rpc_input in) {
  }

}
