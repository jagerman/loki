#include "core_rpc_server_command_parser.h"

#include <chrono>
#include <oxenmq/base64.h>
#include <oxenmq/hex.h>
#include <type_traits>

namespace cryptonote::rpc {

  // Binary types that we support as input parameters.  For json, these must be specified as hex or
  // base64; for bt-encoded requests these can be accepted as binary, hex, or base64.
  template <typename T>
  inline constexpr bool is_binary_parameter = false;
  template <>
  inline constexpr bool is_binary_parameter<crypto::hash> = true;

  // Loads a binary value from a string_view which may contain hex, base64, and (optionally) raw
  // bytes.
  template <typename T, typename = std::enable_if_t<is_binary_parameter<T>>>
  void load_binary_parameter(std::string_view bytes, bool allow_raw, T& val) {
    constexpr size_t raw_size = sizeof(T);
    constexpr size_t hex_size = raw_size * 2;
    constexpr size_t b64_padded = (raw_size + 2) / 3 * 4;
    constexpr size_t b64_padding = raw_size % 3 == 1 ? 2 : raw_size % 3 == 2 ? 1 : 0;
    constexpr size_t b64_unpadded = b64_padded - b64_padding;
    constexpr std::string_view b64_padding_string = b64_padding == 2 ? "=="sv : b64_padding == 1 ? "="sv : ""sv;
    if (allow_raw && bytes.size() == raw_size) {
      std::memcpy(&val, bytes.data(), bytes.size());
      return;
    } else if (bytes.size() == hex_size) {
      if (oxenmq::is_hex(bytes))
        return oxenmq::from_hex(bytes.begin(), bytes.end(), reinterpret_cast<uint8_t*>(&val));
    } else if (bytes.size() == b64_unpadded ||
        (b64_padding > 0 && bytes.size() == b64_padded && bytes.substr(b64_unpadded) == b64_padding_string)) {
      if (oxenmq::is_base64(bytes))
        return oxenmq::from_base64(bytes.begin(), bytes.end(), reinterpret_cast<uint8_t*>(&val));
    }

    throw std::runtime_error{"Invalid binary value: unexpected size and/or encoding"};
  }

}

// Specializations of binary types for deserialization; when receiving these from json we expect
// them encoded in hex or base64.  These may *not* be used for serialization, and will throw if so
// invoked; for serialization you need to use RPC_COMMAND::response_binary instead.
namespace nlohmann {
  template <typename T>
  struct adl_serializer<T, std::enable_if_t<cryptonote::rpc::is_binary_parameter<T>>> {
    static_assert(std::is_trivially_copyable_v<T> && std::has_unique_object_representations_v<T>);

    static void to_json(json& j, const T&) {
      throw std::logic_error{"Internal error: binary types are not directly serialization"};
    }
    static void from_json(const json& j, T& val) {
      load_binary_parameter(j.get<std::string_view>(), false /*no raw*/, val);
    }
  };
}


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
      else if constexpr (std::is_same_v<T, std::chrono::system_clock::time_point>)
        val = std::chrono::system_clock::time_point{std::chrono::seconds{d.consume_integer<int64_t>()}};
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
      } else if constexpr (is_binary_parameter<T>) {
        load_binary_parameter(e.get<std::string_view>(), false /*no raw bytes*/, val);
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

}
