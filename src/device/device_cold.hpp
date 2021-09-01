// Copyright (c) 2017-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#ifndef MONERO_DEVICE_COLD_H
#define MONERO_DEVICE_COLD_H

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include <optional>
#include <functional>

namespace wallet {
struct transfer_details;
struct unsigned_tx_set;
struct signed_tx_set;
}

namespace hw {

  struct wallet_shim {
    std::function<crypto::public_key (const wallet::transfer_details &td)> get_tx_pub_key_from_received_outs;
  };

  class tx_aux_data {
  public:
    std::vector<std::string> tx_device_aux;  // device generated aux data
    std::vector<cryptonote::address_parse_info> tx_recipients;  // as entered by user
    std::optional<int> bp_version;  // BP version to use
    std::optional<unsigned> client_version;  // Signing client version to use (testing)
    std::optional<cryptonote::network_version> network_version;  // hard fork being used for the transaction
  };

  class device_cold {
  public:

    using exported_key_image = std::vector<std::pair<crypto::key_image, crypto::signature>>;

    class op_progress : public hw::device_progress {
    public:
      op_progress():m_progress(0), m_indeterminate(false) {};
      explicit op_progress(double progress, bool indeterminate=false): m_progress(progress), m_indeterminate(indeterminate){}

      double progress() const override { return m_progress; }
      bool indeterminate() const override { return m_indeterminate; }
    protected:
      double m_progress;
      bool m_indeterminate;
    };

    class tx_progress : public op_progress {
    public:
      tx_progress():
        m_cur_tx(0), m_max_tx(1),
        m_cur_step(0), m_max_step(1),
        m_cur_substep(0), m_max_substep(1){};

      tx_progress(size_t cur_tx, size_t max_tx, size_t cur_step, size_t max_step, size_t cur_substep, size_t max_substep):
        m_cur_tx(cur_tx), m_max_tx(max_tx),
        m_cur_step(cur_tx), m_max_step(max_tx),
        m_cur_substep(cur_tx), m_max_substep(max_tx){}

      double progress() const override {
        return std::max(1.0, (double)m_cur_tx / m_max_tx
          + (double)m_cur_step / (m_max_tx * m_max_step)
          + (double)m_cur_substep / (m_max_tx * m_max_step * m_max_substep));
      }
      bool indeterminate() const override { return false; }

    protected:
      size_t m_cur_tx;
      size_t m_max_tx;
      size_t m_cur_step;
      size_t m_max_step;
      size_t m_cur_substep;
      size_t m_max_substep;
    };

    typedef struct {
      std::string salt1;
      std::string salt2;
      std::string tx_enc_keys;
      std::string tx_prefix_hash;
    } tx_key_data_t;

    /**
     * Key image sync with the cold protocol.
     */
    virtual void ki_sync(wallet_shim * wallet,
                 const std::vector<wallet::transfer_details> & transfers,
                 exported_key_image & ski) =0;

    /**
     * Signs unsigned transaction with the cold protocol.
     */
    virtual void tx_sign(wallet_shim * wallet,
                 const wallet::unsigned_tx_set & unsigned_tx,
                 wallet::signed_tx_set & signed_tx,
                 tx_aux_data & aux_data) =0;

    /**
     * Get tx key support check.
     */
    virtual bool is_get_tx_key_supported() const { return false; }

    /**
     * Loads TX aux data required for tx key.
     */
    virtual void load_tx_key_data(tx_key_data_t & res, const std::string & tx_aux_data) =0;

    /**
     * Decrypts TX keys.
     */
    virtual void get_tx_key(
        std::vector<::crypto::secret_key> & tx_keys,
        const tx_key_data_t & tx_aux_data,
        const ::crypto::secret_key & view_key_priv) =0;

    /**
     * Live refresh support check
     */
    virtual bool is_live_refresh_supported() const { return false; };

    /**
     * Starts live refresh process with the device
     */
    virtual void live_refresh_start() =0;

    /**
     * One live refresh step
     */
    virtual void live_refresh(
        const ::crypto::secret_key & view_key_priv,
        const crypto::public_key& out_key,
        const crypto::key_derivation& recv_derivation,
        size_t real_output_index,
        const cryptonote::subaddress_index& received_index,
        cryptonote::keypair& in_ephemeral,
        crypto::key_image& ki
    ) =0;

    /**
     * Live refresh process termination
     */
    virtual void live_refresh_finish() =0;
  };
}

#endif //MONERO_DEVICE_COLD_H
