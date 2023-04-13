#pragma once

#include "fs.h"

#ifndef USE_GHC_FILESYSTEM
#include <fmt/std.h>
#else
#include <fmt/core.h>

namespace fmt {
template <>
struct formatter<ghc::filesystem::path> : formatter<std::string> {
    template <typename FormatContext>
    auto format(const ghc::filesystem::path& val, FormatContext& ctx) const {
        return formatter<std::string>::format(val.u8string(), ctx);
    }
};
}  // namespace fmt
#endif
