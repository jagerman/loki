#include "uptime_proof.h"
#include "common/string_util.h"
#include "version.h"

extern "C"
{
#include <sodium/crypto_sign.h>
}

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "uptime_proof"

//Default constructor for the uptime proof, will take the service node keys as a param and sign 
uptime_proof::Proof::Proof(uint32_t public_ip, uint16_t storage_port, uint16_t storage_lmq_port, const std::array<uint16_t, 3> ss_version, uint16_t quorumnet_port, const std::array<uint16_t, 3> lokinet_version, const service_nodes::service_node_keys& keys)
{
  snode_version = OXEN_VERSION;
  pubkey = keys.pub;
  timestamp = time(nullptr);
  public_ip = public_ip;
  storage_port = storage_port;
  pubkey_ed25519 = keys.pub_ed25519;
  qnet_port = quorumnet_port;
  storage_lmq_port = storage_lmq_port;
  storage_version = ss_version;
  this->lokinet_version = lokinet_version;
  crypto::hash hash = uptime_proof::hash_uptime_proof(*this);

  crypto::generate_signature(hash, keys.pub, keys.key, sig);
  crypto_sign_detached(sig_ed25519.data, NULL, reinterpret_cast<unsigned char *>(hash.data), sizeof(hash.data), keys.key_ed25519.data);
}

//Deserialize from a btencoded string into our Proof instance
uptime_proof::Proof::Proof(const std::string& serialized_proof)
{
  try {
    lokimq::bt_dict bt_proof = lokimq::bt_deserialize<lokimq::bt_dict>(serialized_proof);
    //snode_version <X,X,X>
    lokimq::bt_list& bt_version = var::get<lokimq::bt_list>(bt_proof["version"]);
    int k = 0;
    for (lokimq::bt_value const &i: bt_version){
      snode_version[k++] = static_cast<uint16_t>(lokimq::get_int<unsigned>(i));
    }
    //timestamp
    timestamp = lokimq::get_int<unsigned>(bt_proof["timestamp"]);
    //public_ip
    public_ip = lokimq::get_int<unsigned>(bt_proof["public_ip"]);
    //storage_port
    storage_port = static_cast<uint16_t>(lokimq::get_int<unsigned>(bt_proof["storage_port"]));
    //pubkey_ed25519
    pubkey_ed25519 = tools::make_from_guts<crypto::ed25519_public_key>(var::get<std::string>(bt_proof["pubkey_ed25519"]));
    //pubkey
    std::string pubkey_str = var::get<std::string>(bt_proof["pubkey_ed25519"]);
    pubkey = (!pubkey_str.empty()) ? tools::make_from_guts<crypto::public_key>(pubkey_str) :tools::make_from_guts<crypto::public_key>(var::get<std::string>(bt_proof["pubkey_ed25519"]));
    //qnet_port
    qnet_port = lokimq::get_int<unsigned>(bt_proof["qnet_port"]);
    //storage_lmq_port
    storage_lmq_port = lokimq::get_int<unsigned>(bt_proof["storage_lmq_port"]);
    //storage_version
    lokimq::bt_list& bt_storage_version = var::get<lokimq::bt_list>(bt_proof["storage_version"]);
    k = 0;
    for (lokimq::bt_value const &i: bt_storage_version){
      storage_version[k++] = static_cast<uint16_t>(lokimq::get_int<unsigned>(i));
    }
    //lokinet_version
    lokimq::bt_list& bt_lokinet_version = var::get<lokimq::bt_list>(bt_proof["lokinet_version"]);
    k = 0;
    for (lokimq::bt_value const &i: bt_lokinet_version){
      lokinet_version[k++] = static_cast<uint16_t>(lokimq::get_int<unsigned>(i));
    }
  } catch (const std::exception& e) {
    std::cerr << "deserialization failed: " << e.what();
  }
}

crypto::hash uptime_proof::hash_uptime_proof(const uptime_proof::Proof& proof)
{
  crypto::hash result;

  std::string serialized_proof = lokimq::bt_serialize(uptime_proof::bt_encode_uptime_proof(proof));
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

cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request uptime_proof::generate_request(const Proof& proof)
{
  cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request request;
  request.proof = lokimq::bt_serialize(uptime_proof::bt_encode_uptime_proof(proof));
  request.sig = tools::view_guts(proof.sig);
  request.ed_sig = tools::view_guts(proof.sig_ed25519);

  return request;
}


