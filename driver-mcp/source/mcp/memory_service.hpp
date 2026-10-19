#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "common.hpp"
#include "memory_backend.hpp"

namespace mcp_runtime {
    class memory_service {
    public:
        using clock = std::chrono::steady_clock;
        using now_function = std::function<clock::time_point()>;
        using id_function = std::function<std::string()>;
        using audit_function = std::function<void(const json&)>;

        memory_service(memory_backend& backend, id_function next_id,
                       audit_function audit = {}, now_function now = clock::now,
                       std::chrono::seconds ttl = std::chrono::seconds(60),
                       std::size_t capacity = 128);
        json get_base(const json& args);
        json read(const json& args);
        json prepare(const json& args);
        json apply(const json& args);

    private:
        struct patch {
            target_identity target;
            std::uint64_t address;
            std::string type;
            std::vector<std::uint8_t> before;
            std::vector<std::uint8_t> after;
            clock::time_point expires;
        };
        memory_backend& backend_;
        id_function next_id_;
        audit_function audit_;
        now_function now_;
        std::chrono::seconds ttl_;
        std::size_t capacity_;
        std::mutex mutex_;
        std::unordered_map<std::string, patch> patches_;
    };
}
