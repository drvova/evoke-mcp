#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace mcp_runtime {
    struct target_identity {
        std::uint32_t pid;
        std::uint64_t creation_time;
        std::uint64_t base;
        bool operator==(const target_identity&) const = default;
    };

    enum class driver_operation { connect, attach, detach, query_process, allocate, protect, unload };

    enum class page_protection { no_access, read_only, read_write, execute, execute_read, execute_read_write };

    struct process_information {
        std::uint64_t peb = 0;
        std::uint64_t dtb = 0;
    };

    // Driver adapters implement their own ABI. Unsupported management operations
    // default to false and are never dispatched unless supports() advertises them.
    // Read/write return false on failed or incomplete transfers.
    class memory_backend {
    public:
        virtual ~memory_backend() = default;
        virtual std::string_view name() const { return "custom"; }
        virtual bool supports(driver_operation) const { return false; }
        virtual bool connected() { return identity().has_value(); }
        virtual bool connect() { return false; }
        virtual bool attach(std::uint32_t) { return false; }
        virtual bool detach() { return false; }
        virtual bool query_process(process_information&) { return false; }
        virtual bool allocate(std::uint64_t&, std::uint64_t&, page_protection) { return false; }
        virtual bool protect(std::uint64_t&, std::uint64_t&, page_protection, std::uint32_t&) { return false; }
        virtual bool unload() { return false; }
        virtual std::optional<target_identity> identity() = 0;
        virtual bool read(std::uint64_t address, void* out, std::size_t size) = 0;
        virtual bool write(std::uint64_t address, const void* data, std::size_t size) = 0;
    };
}
