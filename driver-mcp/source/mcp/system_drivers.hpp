#pragma once
#include "common.hpp"
namespace mcp_runtime {
json list_system_drivers(const json& args);
// Read-only service configuration; throws when the image path cannot be resolved.
json resolve_system_driver(const std::string& service_name);
}
