#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <unicorn/unicorn.h>
#include "host_system.hpp"

namespace mcp_runtime {
    enum class api_kind { copy, move, fill_c, fill_nt, zero, compare, allocate_legacy, allocate2,
        free_pool, free_tagged, time_write, kernel_counter, counter_write, frequency_write, ticks,
        system_info, memory_status };
    struct api_model {
        const char* name;
        const char* modules;
        const char* parameters;
        const char* result;
        const char* limitations;
        api_kind kind;
        unsigned arguments;
        bool host_backed;
    };
    std::span<const api_model> api_models();
    const api_model* find_api_model(std::string_view module, std::string_view name);
    json describe_api_models(host_system_provider& host, const json& args);

    struct api_binding { std::string module, name; std::uint64_t address; const api_model* model; };
    class api_machine {
    public:
        static constexpr std::uint64_t pool_base = 0x50000000, pool_size = 0x100000;
        api_machine(uc_engine* engine, host_system_provider& host) : engine_(engine), host_(host) {}
        // Runs outside Unicorn callbacks. Returns an event; on failure the guest PC
        // is left at the bound import and the main loop stops with this diagnostic.
        json invoke(const api_binding& binding);
        json allocations() const;
        json snapshot_description() const;
    private:
        struct allocation { std::uint64_t address, requested, mapped; std::uint32_t tag; };
        void require_access(std::uint64_t address, std::size_t size, unsigned permission);
        std::vector<std::uint8_t> read(std::uint64_t address, std::size_t size);
        void write(std::uint64_t address, const void* data, std::size_t size);
        std::uint64_t allocate(std::uint64_t size, std::uint32_t tag, bool executable);
        void release(std::uint64_t address, std::optional<std::uint32_t> tag);
        const host_snapshot& snapshot();
        uc_engine* engine_;
        host_system_provider& host_;
        std::optional<host_snapshot> snapshot_;
        std::array<bool, 256> pages_{};
        std::vector<allocation> allocations_;
    };
}
