// Copyright (c) 2016-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
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

#include <chrono>
#include <vector>
#include "perf_timer.h"

using namespace std::literals;

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "perf"

#define PERF_LOG_ALWAYS(level, cat, x) \
  el::base::Writer(level, __FILE__, __LINE__, ELPP_FUNC, el::base::DispatchAction::FileOnlyLog).construct(cat) << x

namespace tools
{

el::Level performance_timer_log_level = el::Level::Info;

static thread_local std::vector<LoggingPerformanceTimer*>* performance_timers = nullptr;

void set_performance_timer_log_level(el::Level level)
{
  if (level != el::Level::Debug && level != el::Level::Trace && level != el::Level::Info
   && level != el::Level::Warning && level != el::Level::Error && level != el::Level::Fatal)
  {
    MERROR("Wrong log level: " << el::LevelHelper::convertToString(level) << ", using Info");
    level = el::Level::Info;
  }
  performance_timer_log_level = level;
}

PerformanceTimer::PerformanceTimer(bool paused): started(true)
{
  if (!paused)
    since = std::chrono::steady_clock::now();
}

LoggingPerformanceTimer::LoggingPerformanceTimer(const std::string &s, const std::string &cat, uint64_t unit, el::Level l): PerformanceTimer(), name(s), cat(cat), unit(unit), level(l)
{
  const bool log = ELPP->vRegistry()->allowed(level, cat.c_str());
  if (!performance_timers)
  {
    if (log)
      PERF_LOG_ALWAYS(level, cat.c_str(), "PERF             ----------");
    performance_timers = new std::vector<LoggingPerformanceTimer*>();
    performance_timers->reserve(16); // how deep before realloc
  }
  else
  {
    LoggingPerformanceTimer* pt = performance_timers->back();
    if (!pt->started && pt->since)
    {
      if (log)
      {
        size_t size = 0; for (const auto *tmp: *performance_timers) if (tmp->since) ++size;
        PERF_LOG_ALWAYS(pt->level, cat.c_str(), "PERF           " << std::string((size-1) * 2, ' ') << "  " << pt->name);
      }
      pt->started = true;
    }
  }
  performance_timers->push_back(this);
}

LoggingPerformanceTimer::~LoggingPerformanceTimer()
{
  pause();
  performance_timers->pop_back();
  const bool log = ELPP->vRegistry()->allowed(level, cat.c_str());
  if (log)
  {
    char s[12];
    snprintf(s, sizeof(s), "%8llu  ", static_cast<unsigned long long>(elapsed.count() / (1000000000 / unit)));
    size_t size = 0; for (const auto *tmp: *performance_timers) if (tmp->since || tmp==this) ++size;
    PERF_LOG_ALWAYS(level, cat.c_str(), "PERF " << s << std::string(size * 2, ' ') << "  " << name);
  }
  if (performance_timers->empty())
  {
    delete performance_timers;
    performance_timers = nullptr;
  }
}

void PerformanceTimer::pause()
{
  if (!since)
    return;
  auto now = std::chrono::steady_clock::now();
  elapsed += now - *since;
  since.reset();
}

void PerformanceTimer::resume()
{
  if (!since)
    since = std::chrono::steady_clock::now();
}

void PerformanceTimer::reset()
{
  elapsed = 0ns;
  if (since)
    since = std::chrono::steady_clock::now();
}

std::chrono::nanoseconds PerformanceTimer::value() const
{
  auto ret = elapsed;
  if (since)
    ret += std::chrono::steady_clock::now() - *since;
  return ret;
}

} // namespace tools
