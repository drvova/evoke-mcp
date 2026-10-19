#pragma once

#include <optional>
#include <unordered_map>
#include <vector>
#include "common.hpp"
#include "memory_service.hpp"

namespace mcp_runtime {
    class mcp_server {
    public:
        explicit mcp_server(memory_service& memory);
        std::optional<json> handle(const json& message);

    private:
        std::vector<tool_definition> tools_;
        std::unordered_map<std::string, tool_function> handlers_;
    };
}
