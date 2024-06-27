
#include <cstdint>
#include <string>
#include <unordered_map>

namespace oxen::sent::devnet {

using namespace std::literals;

const std::unordered_map<std::string, std::string> addresses{

        {"dV1kUSiHZ9wfAtGaFzno3ygWUD519SuBphrAbe2tiV34T7PvHLqWGuD8uHJJ6Az8SQLkxGGkUbDkiMhVma3zQihr328CfmumW"s,
         "0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s},
        {"dV1noVdqm5pRnHEQx42zunebYsLUp7hXePLLfC7C4PoZRTZJDdooxfeeWLbCSjV69kJTWgcVXZpUW2uu7S7QSD4r27gCXztoD"s,
         "0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s},
        {"dV1xmAE3kud3u5ajhUiXQYLb6ditA4vRwgw8pQEuksCTC79oG138HR6cAKw8cf9VZjUatfu4VzvHHVXvAF6DFA5M15C7UwQDj"s,
         "0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s},
        {"dV3g5cg7mN1Jgtithg6f2yBCPx7gye7dgVAjE7rJgh5uSWYj8JTVU8CTNwjFPPMV6dBFRPtqsFaNEWAVEuDPnLc91pZpiJCs7"s,
         "0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s},

};

const std::pair<std::uint8_t, std::uint8_t> conv_ratio{2, 3};

const std::unordered_map<std::string, std::uint64_t> transition_bonus{

        {"0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s, 292553191489},
        {"0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s, 388297872340},
        {"0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s, 319148936170},

};  // Actual bonus total: 999.999999999 of target 1000.000000000

}  // namespace oxen::sent::devnet
