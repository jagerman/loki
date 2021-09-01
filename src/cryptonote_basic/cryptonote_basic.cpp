#include "cryptonote_basic.h"
#include "cryptonote_basic/hardfork.h"

namespace cryptonote {

void transaction_prefix::set_null() {
  version = txversion::v1;
  unlock_time = 0;
  vin.clear();
  vout.clear();
  extra.clear();
  output_unlock_times.clear();
  type = txtype::standard;
}

std::pair<txversion, txversion> transaction_prefix::get_version_range(network_state net)
{
  return {
    // min:
    network_dependent_value(net,
        feature::TX_V4_TYPES, txversion::v4_tx_types,
        txversion::v2_ringct),
    // max:
    hack::test_suite_permissive_txes ? txversion::v4_tx_types :
    network_dependent_value(net,
        feature::TX_V4_TYPES, txversion::v4_tx_types,
        feature::SERVICE_NODES, txversion::v3_per_output_unlock_times,
        txversion::v2_ringct)
  };
}

txtype transaction_prefix::get_max_type(network_state net)
{
  return network_dependent_value(net,
      feature::ONS, txtype::oxen_name_system,
      feature::TXTYPE_STAKE, txtype::stake,
      feature::INFINITE_STAKING, txtype::key_image_unlock,
      feature::SERVICE_NODES, txtype::state_change,
      txtype::standard);
}

const char* transaction_prefix::version_to_string(txversion v)
{
  switch(v)
  {
    case txversion::v1:                         return "1";
    case txversion::v2_ringct:                  return "2_ringct";
    case txversion::v3_per_output_unlock_times: return "3_per_output_unlock_times";
    case txversion::v4_tx_types:                return "4_tx_types";
    default: assert(false);                     return "xx_unhandled_version";
  }
}

const char* transaction_prefix::type_to_string(txtype type)
{
  switch(type)
  {
    case txtype::standard:                return "standard";
    case txtype::state_change:            return "state_change";
    case txtype::key_image_unlock:        return "key_image_unlock";
    case txtype::stake:                   return "stake";
    case txtype::oxen_name_system:        return "oxen_name_system";
    default: assert(false);               return "xx_unhandled_type";
  }
}

std::ostream& operator<<(std::ostream& o, txtype t) {
  return o << transaction::type_to_string(t);
}
std::ostream& operator<<(std::ostream& o, txversion v) {
  return o << transaction::version_to_string(v);
}

std::ostream& operator<<(std::ostream& o, network_version v) {
  return o << +v.first << '.' << +v.second;
}

transaction::transaction(const transaction &t) :
  transaction_prefix(t),
  hash_valid(false),
  blob_size_valid(false),
  signatures(t.signatures),
  rct_signatures(t.rct_signatures),
  pruned(t.pruned),
  unprunable_size(t.unprunable_size.load()),
  prefix_size(t.prefix_size.load())
{
  if (t.is_hash_valid()) {
    hash = t.hash;
    set_hash_valid(true);
  }
  if (t.is_blob_size_valid()) {
    blob_size = t.blob_size;
    set_blob_size_valid(true);
  }
}

transaction& transaction::operator=(const transaction& t) {
  transaction_prefix::operator=(t);
  set_hash_valid(false);
  set_blob_size_valid(false);
  signatures = t.signatures;
  rct_signatures = t.rct_signatures;
  if (t.is_hash_valid()) {
    hash = t.hash;
    set_hash_valid(true);
  }
  if (t.is_blob_size_valid()) {
    blob_size = t.blob_size;
    set_blob_size_valid(true);
  }
  pruned = t.pruned;
  unprunable_size = t.unprunable_size.load();
  prefix_size = t.prefix_size.load();
  return *this;
}

void transaction::set_null()
{
  transaction_prefix::set_null();
  signatures.clear();
  rct_signatures = {};
  rct_signatures.type = rct::RCTType::Null;
  set_hash_valid(false);
  set_blob_size_valid(false);
  pruned = false;
  unprunable_size = 0;
  prefix_size = 0;
}

void transaction::invalidate_hashes()
{
  set_hash_valid(false);
  set_blob_size_valid(false);
}

size_t transaction::get_signature_size(const txin_v& tx_in)
{
  if (std::holds_alternative<txin_to_key>(tx_in))
    return var::get<txin_to_key>(tx_in).key_offsets.size();
  return 0;
}

block::block(const block& b) :
  block_header(b),
  miner_tx{b.miner_tx},
  tx_hashes{b.tx_hashes},
  signatures{b.signatures}
{
  copy_hash(b);
}

block::block(block&& b) :
  block_header(std::move(b)),
  miner_tx{std::move(b.miner_tx)},
  tx_hashes{std::move(b.tx_hashes)},
  signatures{std::move(b.signatures)}
{
  copy_hash(b);
}

block& block::operator=(const block& b)
{
  block_header::operator=(b);
  miner_tx = b.miner_tx;
  tx_hashes = b.tx_hashes;
  signatures = b.signatures;
  copy_hash(b);
  return *this;
}
block& block::operator=(block&& b)
{
  block_header::operator=(std::move(b));
  miner_tx = std::move(b.miner_tx);
  tx_hashes = std::move(b.tx_hashes);
  signatures = std::move(b.signatures);
  copy_hash(b);
  return *this;
}

bool block::is_hash_valid() const
{
  return hash_valid.load(std::memory_order_acquire);
}
void block::set_hash_valid(bool v) const
{
  hash_valid.store(v,std::memory_order_release);
}

}
