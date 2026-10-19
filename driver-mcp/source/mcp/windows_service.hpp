#pragma once
#include "common.hpp"
#include <filesystem>
#include <mutex>
namespace mcp_runtime {
    class windows_service {
    public:
        windows_service();
        explicit windows_service(std::filesystem::path worker) : worker_(std::move(worker)) {}
        json info(const json& args);
        json catalog(const json& args);
        json run(const json& args);
        json image(const json& args);
        json discover_contract(const json& args);
    private:
        json invoke(const char* action, const json& args);
        std::filesystem::path worker_;
        std::mutex mutex_;
    };
}
