#pragma once
#include <mutex>
#include "common.hpp"
#include "host_system.hpp"

namespace mcp_runtime {
    // A fresh Unicorn machine per request. This service never receives a driver
    // backend, so guest memory cannot read or write the live target.
    class emulation_service {
    public:
        explicit emulation_service(host_system_provider& host = native_host_system()) : host_(host) {}
        json api_catalog(const json& args);
        json system_snapshot(const json& args);
        json info(const json& args);
        json run(const json& args);
    private:
        host_system_provider& host_;
        std::mutex mutex_;
    };
}
