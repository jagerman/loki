// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 




#ifndef __WINH_OBJ_H__
#define __WINH_OBJ_H__

#include <condition_variable>
#include <mutex>

namespace epee
{

  struct simple_event
  {
    simple_event() : m_rised(false)
    {
    }

    void raise()
    {
      std::unique_lock<std::mutex> lock(m_mx);
      m_rised = true;
      m_cond_var.notify_one();
    }

    void wait()
    {
      std::unique_lock<std::mutex> lock(m_mx);
      while (!m_rised) 
        m_cond_var.wait(lock);
      m_rised = false;
    }

  private:
    std::mutex m_mx;
    std::condition_variable m_cond_var;
    bool m_rised;
  };

  class critical_region;

#define  CRITICAL_REGION_LOCAL(mutex) std::lock_guard<decltype(mutex)> critical_region_var{mutex}
#define  CRITICAL_REGION_BEGIN(mutex) { CRITICAL_REGION_LOCAL(mutex)
#define  CRITICAL_REGION_LOCAL1(mutex) std::lock_guard<decltype(mutex)> critical_region_var1{mutex}
#define  CRITICAL_REGION_BEGIN1(mutex) { CRITICAL_REGION_LOCAL1(mutex)
#define  CRITICAL_REGION_END() }

}

#endif
