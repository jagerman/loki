// Copyright (c) 2016-2019, The Monero Project
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

#pragma once

#include <boost/thread/thread.hpp>
#include <lokimq/lokimq.h>
#include <string>
#include <memory>

#include "common/command_line.h"

#include "rpc_handler.h"

namespace cryptonote
{

namespace rpc
{

static constexpr int DEFAULT_NUM_ZMQ_THREADS = 1;
static constexpr int DEFAULT_RPC_RECV_TIMEOUT_MS = 1000;

class ZmqServer
{
  public:

    ZmqServer(RpcHandler& h);

    ~ZmqServer();

    static void init_options(boost::program_options::options_description& desc);

    void serve();

    bool addIPCSocket(std::string address, std::string port);
    bool addTCPSocket(std::string address, std::string port);

    void run();
    void stop();

  private:
    RpcHandler& handler;

    volatile bool stop_signal;
    volatile bool running;

    zmq::context_t context;

    boost::thread run_thread;

    std::unique_ptr<zmq::socket_t> rep_socket;
};


}  // namespace cryptonote

}  // namespace rpc
