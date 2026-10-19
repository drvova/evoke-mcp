#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace mcp_runtime {
    struct target_identity {
        std::uint32_t pid;
        std::uint64_t creation_time;
        std::uint64_t base;
        bool operator==(const target_identity&) const = default;
    };

    // Implementations return false on failed or incomplete transfers.
    class memory_backend {
    public:
        virtual ~memory_backend() = default;
        virtual std::optional<target_identity> identity() = 0;
        virtual bool read(std::uint64_t address, void* out, std::size_t size) = 0;
        virtual bool write(std::uint64_t address, const void* data, std::size_t size) = 0;
    };
}
