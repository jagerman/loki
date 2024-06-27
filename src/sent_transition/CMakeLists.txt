
add_library(sent_transition
  sent_transition.cpp
  mainnet.cpp
  testnet.cpp
  devnet.cpp)

target_link_libraries(sent_transition
    PUBLIC
    cryptonote_core)
