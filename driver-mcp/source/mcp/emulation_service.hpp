#pragma once
#include <mutex>
#include "common.hpp"

namespace mcp_runtime {
    // A fresh Unicorn machine per request. This service never receives a driver
    // backend, so guest memory cannot read or write the live target.
    class emulation_service {
    public:
        json info(const json& args);
        json run(const json& args);
    private:
        std::mutex mutex_;
    };
}
