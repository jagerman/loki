#include "uptime_proof.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "uptime_proof"


uptime_proof::Proof::Proof(uint32_t public_ip, uint16_t storage_port, uint16_t storage_lmq_port, std::array<uint16_t, 3> ss_version, uint16_t quorumnet_port, std::array<uint16_t, 3> lokinet_version)
{
  assert(m_service_node_keys);
  const auto& keys = *m_service_node_keys;

  snode_version = OXEN_VERSION;
  timestamp = time(nullptr);
  pubkey = keys.pub;
  public_ip = public_ip;
  storage_port = storage_port;
  storage_lmq_port = storage_lmq_port;
  qnet_port = quorumnet_port;
  pubkey_ed25519 = keys.pub_ed25519;
  storage_version = ss_version;
  lokinet_version = lokinet_version;
  hash = uptime_proof::hash_uptime_proof(&this);

  crypto::generate_signature(hash, keys.pub, keys.key, sig);
  crypto_sign_detached(sig_ed25519.data, NULL, reinterpret_cast<unsigned char *>(hash.data), sizeof(hash.data), keys.key_ed25519.data);
}

uptime_proof::Proof::Proof(const std::string &serialized_proof)
{
  try {
    lokimq::bt_dict wrapped_bt_proof = lokimq::bt_deserialize<lokimq::bt_dict>(serialized_proof);
  } catch (const std::exception& e) {
    std::cerr << "deserialization failed: " << e.what();
  }
}

crypto::hash string uptime_proof::hash_uptime_proof(const uptime_proof::Proof& proof)
{
  crypto::hash result;

  std::string serialized_proof = lokimq::bt_serialize(uptime_proof::btencode_uptime_proof(proof));
  size_t buf_size = serialized_proof.size();
  crypto::cn_fast_hash(serialized_proof.data(), buf_size, result);
  return result;
}

lokimq::bt_dict uptime_proof::bt_encode_uptime_proof(const uptime_proof::Proof& proof)
{
  return lokimq::bt_dict {
    {"version", lokimq::bt_list{{proof.snode_version[0], proof.snode_version[1], proof.snode_version[2]}}},
    {"pubkey",  (proof.pubkey == proof.pubkey_ed25519) ? "" : tools::view_guts(proof.pubkey)},
    {"timestamp",proof.timestamp},
    {"public_ip",proof.public_ip},
    {"storage_port",proof.storage_port},
    {"pubkey_ed25519",tools::view_guts(proof.pubkey_ed25519)},
    {"qnet_port",proof.qnet_port},
    {"storage_lmq_port",proof.storage_lmq_port},
    {"storage_version", lokimq::bt_list{{proof.storage_version[0], proof.storage_version[1], proof.storage_version[2]}}},
    {"lokinet_version", lokimq::bt_list{{proof.lokinet_version[0], proof.lokinet_version[1], proof.lokinet_version[2]}}},
  };
}

std::string uptime_proof::serialize_uptime_proof(const uptime_proof::Proof& proof)
{
}

cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request uptime_proof::generate_request(const Proof& proof)
{
  return NOTIFY_BTENCODED_UPTIME_PROOF{
    {"proof", uptime_proof::btencode_uptime_proof(proof)},
    {"sig", tools::view_guts(proof.sig)},
    {"ed_sig", tools::view_guts(proof.sig_ed25519)}
  };
}


