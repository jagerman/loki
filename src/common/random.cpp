// Copyright (c) 2019, The Loki Project
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

#include "random.h"
#include <cassert>

namespace tools {

thread_local std::mt19937_64 rng{std::random_device{}()};

uint64_t uniform_distribution_portable(std::mt19937_64& rng, const uint64_t n)
{
  // We can't change anything here that would result in a change of any generated values, so
  // potential improvements are left as comments in case anyone wants to copy this at some point.
  //
  // First, ideally we should be taking `n` as max-wanted instead of one-plus-max-wanted, so that
  // this *could* be used in a context that needs (at runtime) to be able to select from the full
  // range of `rng`.  Currently it cannot (since you can't pass 2^64 in order to get [0, 2^64-1]
  // values).
  //
  // Second we should have taken min,max values, to be more directly comparable to
  // std::uniform_int_distribution (and probably should use the struct-based
  // std::uniform_int_distribution interface).

  assert(n > 0);

  // This is slightly wasteful when rng.max() is one less than an integer multiple of `n`: we reject
  // the last `n` values unnecessarily.  (E.g. if `max()==255` and we give `n=64` then the below
  // generates values from [0, 191] and rejects values in [192, 255], even though it doesn't have
  // to.
  const uint64_t secureMax = rng.max() - rng.max() % n;
  uint64_t x;
  do x = rng(); while (x >= secureMax);

  // This double-integer-division is pointless (and slow) compared to `return x % n`, but we can't
  // change it because it would result in different (but still uniform) random values.
  return  x / (secureMax / n);
}

}
