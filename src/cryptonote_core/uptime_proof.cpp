#include "uptime_proof.h"
#include "common/string_util.h"
#include "version.h"

extern "C"
{
#include <sodium/crypto_sign.h>
}

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "uptime_proof"

namespace uptime_proof
{

//Constructor for the uptime proof, will take the service node keys as a param and sign 
Proof::Proof(uint32_t sn_public_ip, uint16_t sn_storage_port, uint16_t sn_storage_lmq_port, const std::array<uint16_t, 3> ss_version, uint16_t quorumnet_port, const std::array<uint16_t, 3> lokinet_version, const service_nodes::service_node_keys& keys) : version{OXEN_VERSION}, pubkey{keys.pub}, timestamp{static_cast<uint64_t>(time(nullptr))}, public_ip{sn_public_ip}, storage_port{sn_storage_port}, pubkey_ed25519{keys.pub_ed25519},qnet_port{quorumnet_port}, storage_lmq_port{sn_storage_lmq_port}, storage_server_version{ss_version}
{
  this->lokinet_version = lokinet_version;
  crypto::hash hash = this->hash_uptime_proof();

  crypto::generate_signature(hash, keys.pub, keys.key, sig);
  crypto_sign_detached(sig_ed25519.data, NULL, reinterpret_cast<unsigned char *>(hash.data), sizeof(hash.data), keys.key_ed25519.data);
}

//Deserialize from a btencoded string into our Proof instance
Proof::Proof(const std::string& serialized_proof)
{
  try {
    const lokimq::bt_dict bt_proof = lokimq::bt_deserialize<lokimq::bt_dict>(serialized_proof);
    //snode_version <X,X,X>
    const lokimq::bt_list& bt_version = var::get<lokimq::bt_list>(bt_proof.at("version"));
    int k = 0;
    for (lokimq::bt_value const &i: bt_version){
      version[k++] = static_cast<uint16_t>(lokimq::get_int<unsigned>(i));
    }
    //timestamp
    timestamp = lokimq::get_int<unsigned>(bt_proof.at("timestamp"));
    //public_ip
    bool succeeded = epee::string_tools::get_ip_int32_from_string(public_ip, var::get<std::string>(bt_proof.at("public_ip")));
    //storage_port
    storage_port = static_cast<uint16_t>(lokimq::get_int<unsigned>(bt_proof.at("storage_port")));
    //pubkey_ed25519
    pubkey_ed25519 = tools::make_from_guts<crypto::ed25519_public_key>(var::get<std::string>(bt_proof.at("pubkey_ed25519")));
    //pubkey
    if (auto it = bt_proof.find("pubkey"); it != bt_proof.end())
      pubkey = tools::make_from_guts<crypto::public_key>(var::get<std::string>(bt_proof.at("pubkey")));
    else
      std::memcpy(pubkey.data, pubkey_ed25519.data, 32);
    //qnet_port
    qnet_port = lokimq::get_int<unsigned>(bt_proof.at("qnet_port"));
    //storage_lmq_port
    storage_lmq_port = lokimq::get_int<unsigned>(bt_proof.at("storage_lmq_port"));
    //storage_version
    const lokimq::bt_list& bt_storage_version = var::get<lokimq::bt_list>(bt_proof.at("storage_version"));
    k = 0;
    for (lokimq::bt_value const &i: bt_storage_version){
      storage_server_version[k++] = static_cast<uint16_t>(lokimq::get_int<unsigned>(i));
    }
    //lokinet_version
    const lokimq::bt_list& bt_lokinet_version = var::get<lokimq::bt_list>(bt_proof.at("lokinet_version"));
    k = 0;
    for (lokimq::bt_value const &i: bt_lokinet_version){
      lokinet_version[k++] = static_cast<uint16_t>(lokimq::get_int<unsigned>(i));
    }
  } catch (const std::exception& e) {
    MWARNING("deserialization failed: " <<  e.what());
    throw;
  }
}

crypto::hash Proof::hash_uptime_proof() const
{
  crypto::hash result;

  std::string serialized_proof = lokimq::bt_serialize(bt_encode_uptime_proof());
  size_t buf_size = serialized_proof.size();
  crypto::cn_fast_hash(serialized_proof.data(), buf_size, result);
  return result;
}

lokimq::bt_dict Proof::bt_encode_uptime_proof() const
{
  lokimq::bt_dict encoded_proof{
    {"version", lokimq::bt_list{{version[0], version[1], version[2]}}},
    {"timestamp", timestamp},
    {"public_ip", epee::string_tools::get_ip_string_from_int32(public_ip)},
    {"storage_port", storage_port},
    {"pubkey_ed25519", tools::view_guts(pubkey_ed25519)},
    {"qnet_port", qnet_port},
    {"storage_lmq_port", storage_lmq_port},
    {"storage_version", lokimq::bt_list{{storage_server_version[0], storage_server_version[1], storage_server_version[2]}}},
    {"lokinet_version", lokimq::bt_list{{lokinet_version[0], lokinet_version[1], lokinet_version[2]}}},
  };

  if (pubkey == pubkey_ed25519) encoded_proof["pubkey"] = tools::view_guts(pubkey);

  return encoded_proof;
}

cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request Proof::generate_request() const
{
  cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request request;
  request.proof = lokimq::bt_serialize(this->bt_encode_uptime_proof());
  request.sig = tools::view_guts(this->sig);
  request.ed_sig = tools::view_guts(this->sig_ed25519);

  return request;
}

}


