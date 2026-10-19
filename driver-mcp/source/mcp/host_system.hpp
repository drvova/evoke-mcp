#pragma once
#include <array>
#include <cstdint>
#include <string_view>
#include "common.hpp"

namespace mcp_runtime {
    struct host_snapshot {
        std::uint64_t filetime_100ns = 0, performance_counter = 0, performance_frequency = 0, tick_count_ms = 0;
        std::array<std::uint8_t, 48> system_info{};
        std::array<std::uint8_t, 64> memory_status{};
        json describe() const;
    };
    class host_system_provider {
    public:
        virtual ~host_system_provider() = default;
        virtual bool available() const = 0;
        virtual std::string_view name() const = 0;
        virtual host_snapshot capture() = 0;
    };
    host_system_provider& native_host_system();
}
