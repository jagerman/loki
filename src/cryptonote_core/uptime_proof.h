#pragma once

#include <oxenc/bt_serialize.h>
#include <oxenc/bt_value.h>

#include "cryptonote_protocol/cryptonote_protocol_defs.h"

namespace service_nodes {

struct service_node_keys;

}

namespace uptime_proof {

class Proof {

  public:
    std::array<uint16_t, 3> version{};
    std::array<uint16_t, 3> storage_server_version{};
    std::array<uint16_t, 3> lokinet_version{};

    uint64_t timestamp{};
    crypto::public_key pubkey{};
    crypto::signature sig{};
    crypto::ed25519_public_key pubkey_ed25519{};
    crypto::ed25519_signature sig_ed25519{};
    uint32_t public_ip{};
    uint16_t storage_https_port{};
    uint16_t storage_omq_port{};
    uint16_t qnet_port{};

    Proof() = default;
    Proof(uint32_t sn_public_ip,
          uint16_t sn_storage_https_port,
          uint16_t sn_storage_omq_port,
          std::array<uint16_t, 3> ss_version,
          uint16_t quorumnet_port,
          std::array<uint16_t, 3> lokinet_version,
          const service_nodes::service_node_keys& keys);

    Proof(const std::string& serialized_proof);
    oxenc::bt_dict bt_encode_uptime_proof() const;

    crypto::hash hash_uptime_proof() const;

    cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request generate_request() const;
};

bool operator==(const Proof& lhs, const Proof& rhs);
bool operator!=(const Proof& lhs, const Proof& rhs);

}  // namespace uptime_proof
