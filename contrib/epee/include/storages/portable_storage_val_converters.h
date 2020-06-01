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

#include <time.h>
#include <boost/lexical_cast.hpp>
#include <regex>

#include "misc_language.h"
#include "portable_storage_base.h"
#include "parserse_base_utils.h"
#include "warnings.h"

namespace epee
{
  namespace serialization
  {
#define ASSERT_AND_THROW_WRONG_CONVERSION() ASSERT_MES_AND_THROW("WRONG DATA CONVERSION @ " << __FILE__ << ":" << __LINE__ << ": " << typeid(from).name() << " to " << typeid(to).name())

    template <typename from_type, typename to_type, std::enable_if_t<std::is_signed<from_type>::value && std::is_unsigned<to_type>::value, int> = 0>
    void convert_int(const from_type& from, to_type& to)
    {
PUSH_WARNINGS
DISABLE_VS_WARNINGS(4018)
      CHECK_AND_ASSERT_THROW_MES(from >=0, "unexpected int value with signed storage value less than 0, and unsigned receiver value");
DISABLE_GCC_AND_CLANG_WARNING(sign-compare)
      CHECK_AND_ASSERT_THROW_MES(from <= std::numeric_limits<to_type>::max(), "int value overhead: try to set value " << from << " to type " << typeid(to_type).name() << " with max possible value = " << std::numeric_limits<to_type>::max());
      to = static_cast<to_type>(from);
POP_WARNINGS
    }
    template <typename from_type, typename to_type, std::enable_if_t<std::is_signed<from_type>::value && std::is_signed<to_type>::value, int> = 0>
    void convert_int(const from_type& from, to_type& to)
    {
      CHECK_AND_ASSERT_THROW_MES(from >= boost::numeric::bounds<to_type>::lowest(), "int value overhead: try to set value " << from << " to type " << typeid(to_type).name() << " with lowest possible value = " << boost::numeric::bounds<to_type>::lowest());
PUSH_WARNINGS
DISABLE_CLANG_WARNING(tautological-constant-out-of-range-compare)
      CHECK_AND_ASSERT_THROW_MES(from <= std::numeric_limits<to_type>::max(), "int value overhead: try to set value " << from << " to type " << typeid(to_type).name() << " with max possible value = " << std::numeric_limits<to_type>::max());
POP_WARNINGS
      to = static_cast<to_type>(from);
    }
    template<typename from_type, typename to_type, std::enable_if_t<std::is_unsigned<from_type>::value, int> = 0>
    void convert_int(const from_type& from, to_type& to)
    {
PUSH_WARNINGS
DISABLE_VS_WARNINGS(4018)
DISABLE_CLANG_WARNING(tautological-constant-out-of-range-compare)
        CHECK_AND_ASSERT_THROW_MES(from <= std::numeric_limits<to_type>::max(), "uint value overhead: try to set value " << from << " to type " << typeid(to_type).name() << " with max possible value = " << std::numeric_limits<to_type>::max());
      to = static_cast<to_type>(from);
POP_WARNINGS
    }

    template<typename from_type, typename to_type, typename SFINAE = void>
    struct converter
    {
      void operator()(const from_type& from, to_type& to)
      {
        ASSERT_AND_THROW_WRONG_CONVERSION();
      }
    };

    template<typename from_type, typename to_type>
    struct converter<from_type, to_type, std::enable_if_t<!std::is_same<to_type, from_type>::value &&
        std::is_integral<to_type>::value && std::is_integral<from_type>::value &&
        !std::is_same<from_type, bool>::value && !std::is_same<to_type, bool>::value>>
    {
      void operator()(const from_type& from, to_type& to)
      {
        convert_int(from, to);
      }
    };

    // For MyMonero/OpenMonero backend compatibility
    // MyMonero backend sends amount, fees and timestamp values as strings.
    // Until MM backend is updated, this is needed for compatibility between OpenMonero and MyMonero. 
    template<>
    struct converter<std::string, uint64_t>
    {
      // MyMonero ISO 8061 timestamp (2017-05-06T16:27:06Z)
      inline static std::regex mymonero_iso8061_timestamp{R"(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\dZ)"};

      void operator()(const std::string& from, uint64_t& to)
      {
        MTRACE("Converting std::string to uint64_t. Source: " << from);
        // String only contains digits
        if(std::all_of(from.begin(), from.end(), epee::misc_utils::parse::isdigit))
          to = boost::lexical_cast<uint64_t>(from);
        else if (std::regex_match(from, mymonero_iso8061_timestamp))
        {
          // Convert to unix timestamp
#ifdef HAVE_STRPTIME
          struct tm tm;
          if (strptime(from.c_str(), "%Y-%m-%dT%H:%M:%S", &tm))
#else
          std::tm tm = {};
          std::istringstream ss(from);
          if (ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S"))
#endif
            to = std::mktime(&tm);
        } else
          ASSERT_AND_THROW_WRONG_CONVERSION();
      }
    };

    template<typename from_type, typename to_type>
    struct converter<from_type, to_type, std::enable_if_t<std::is_same<to_type, from_type>::value>>
    {
      void operator()(const from_type& from, to_type& to)
      {
        to = from;
      }
    };


    template<class from_type, class to_type>
    void convert_t(const from_type& from, to_type& to)
    {
      converter<from_type, to_type>{}(from, to);
    }
  }
}
