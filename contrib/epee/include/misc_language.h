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



#pragma once

#include <limits>
#include <thread>
namespace epee
{

namespace misc_utils
{

	inline
	void sleep_no_w(long ms)
	{
        std::this_thread::sleep_for(std::chrono::milliseconds(std::max<long>(ms, 0)));
	}

  // Warning: partially sorts the given vector!
  template<class T>
  T median(std::vector<T> &v)
  {
    if(v.empty())
      return T{};

    const size_t mid = v.size() / 2;
    std::nth_element(v.begin(), v.begin() + mid, v.end());
    if (v.size() % 2) // odd size: mid is the median
      return v[mid];

    return (*std::max_element(v.begin(), v.begin() + mid) + v[mid]) / 2;
  }

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

  template<class UnaryFunction>
  struct scope_leave_handler
  {
    UnaryFunction f;
    scope_leave_handler(UnaryFunction f) : f{std::move(f)} {}
    ~scope_leave_handler() { try { f(); } catch (...) { /* ignore */ } }
  };

  template<class UnaryFunction>
  auto create_scope_leave_handler(UnaryFunction f) { return scope_leave_handler<UnaryFunction>(std::move(f)); }

  // Same, but returned in a unique_ptr to allow manual control:
  template<class UnaryFunction>
  auto create_scope_leave_handler_unique_ptr(UnaryFunction f) { return std::make_unique<scope_leave_handler<UnaryFunction>>(std::move(f)); }


  // FIXME: DELETE!
  template<typename T> struct struct_init: T
  {
    struct_init(): T{} {}
  };

}
}
