#pragma once
#include <string_view>

namespace mcp_runtime {
    inline bool origin_allowed(std::string_view origin) {
        if (origin.empty()) return true; // Native MCP clients generally send no Origin.
        if (origin.starts_with("http://")) origin.remove_prefix(7);
        else if (origin.starts_with("https://")) origin.remove_prefix(8);
        else return false;
        const auto colon = origin.find(':');
        const auto host = origin.substr(0, colon);
        if (host != "localhost" && host != "127.0.0.1") return false;
        if (colon == std::string_view::npos) return true;
        const auto port = origin.substr(colon + 1);
        if (port.empty() || port.size() > 5) return false;
        unsigned value = 0;
        for (auto digit : port) {
            if (digit < '0' || digit > '9') return false;
            value = value * 10 + static_cast<unsigned>(digit - '0');
        }
        return value > 0 && value <= 65535;
    }

    inline bool host_allowed(std::string_view host) {
        return host == "localhost:8888" || host == "127.0.0.1:8888";
    }

    inline bool token_matches(std::string_view authorization, std::string_view token) {
        constexpr std::string_view prefix = "Bearer ";
        if (token.empty() || !authorization.starts_with(prefix)) return false;
        authorization.remove_prefix(prefix.size());
        if (authorization.size() != token.size()) return false;
        unsigned difference = 0;
        for (std::size_t index = 0; index < token.size(); ++index)
            difference |= static_cast<unsigned char>(authorization[index]) ^ static_cast<unsigned char>(token[index]);
        return difference == 0;
    }
}
