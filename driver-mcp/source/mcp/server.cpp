#include "server.hpp"
#include <stdexcept>

namespace mcp_runtime {
    namespace {
        json result(const json& id, const json& value) {
            return {{"jsonrpc", "2.0"}, {"id", id}, {"result", value}};
        }
        json error(const json& id, int code, const char* message) {
            return {{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", message}}}};
        }
    }

    json make_tool_result(const std::string& text, const json& structured_content, bool is_error) {
        json value = {{"content", json::array({{{"type", "text"},
            {"text", structured_content.empty() ? text : text + "\n" + structured_content.dump()}}})},
            {"isError", is_error}};
        if (!structured_content.is_null() && !structured_content.empty())
            value["structuredContent"] = structured_content;
        return value;
    }

    mcp_server::mcp_server(memory_service& memory) {
        const json type = {{"type", "string"}, {"enum", json::array({
            "byte", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "float", "double"})}};
        const json addr = {{"type", "integer"}, {"minimum", 65536}, {"maximum", 140737488355327LL},
            {"description", "Target user virtual address. Transfers must fit below the user address boundary."}};
        const json size = {{"type", "integer"}, {"minimum", 1}, {"maximum", 140737488289792LL}};
        const json protection = {{"type", "string"}, {"enum", json::array({
            "no_access", "read_only", "read_write", "execute", "execute_read", "execute_read_write"})}};
        auto schema = [](json properties, json required) {
            return json{{"type", "object"}, {"properties", properties},
                        {"required", required}, {"additionalProperties", false}};
        };
        tools_ = {
            {"get_driver_status", "Report adapter capabilities, driver availability, target identity, and pending previews. Capabilities are declarations, not a runtime ABI probe.",
                schema(json::object(), json::array()), true,
                [&memory](const json& args) { return memory.driver_status(args); }},
            {"connect_driver", "Open the configured driver's device connection. Invalidates pending previews; does not install or load a driver.",
                schema(json::object(), json::array()), false,
                [&memory](const json& args) { return memory.connect_driver(args); }},
            {"attach_process", "Attach the driver to an explicit PID and retain its process identity. Invalidates pending previews.",
                schema({{"pid", {{"type", "integer"}, {"minimum", 1}, {"maximum", 4294967295ULL}}}}, {"pid"}), false,
                [&memory](const json& args) { return memory.attach_process(args); }},
            {"detach_process", "Detach from the current process. Invalidates pending previews.",
                schema(json::object(), json::array()), false,
                [&memory](const json& args) { return memory.detach_process(args); }},
            {"get_process_info", "Read the attached process identity, PEB, and DTB. Full-width PEB/DTB are returned as decimal strings.",
                schema(json::object(), json::array()), true,
                [&memory](const json& args) { return memory.process_info(args); }},
            {"allocate_memory", "Reserve and commit private memory in the attached process. Returns the driver's address and rounded size. Invalidates previews; does not execute code. Evoke defines no free operation.",
                schema({{"size", size}, {"protection", protection}}, {"size", "protection"}), false,
                [&memory](const json& args) { return memory.allocate_memory(args); }},
            {"protect_memory", "Change memory protection in the attached process. Returns the driver's actual range and previous native protection. Invalidates previews; does not execute code.",
                schema({{"addr", addr}, {"size", size}, {"protection", protection}}, {"addr", "size", "protection"}), false,
                [&memory](const json& args) { return memory.protect_memory(args); }},
            {"unload_driver", "Request driver unload, close the device on success, and invalidate pending previews. Reconnecting requires the driver to be loaded externally.",
                schema(json::object(), json::array()), false,
                [&memory](const json& args) { return memory.unload_driver(args); }},
            {"get_base_address", "Get the live attached process identity and image base.",
                schema(json::object(), json::array()), true,
                [&memory](const json& args) { return memory.get_base(args); }},
            {"read_memory", "Read a primitive value; driver failures are reported as errors.",
                schema({{"addr", addr}, {"type", type}}, {"addr", "type"}), true,
                [&memory](const json& args) { return memory.read(args); }},
            {"prepare_memory_patch", "Preview a typed memory patch without writing. Inspect the preview before applying its single-use ID; expires after 60 seconds.",
                schema({{"addr", addr}, {"type", type}, {"value", {{"type", "number"}}},
                        {"expected", {{"type", "number"}, {"description", "Optional required current value; compared as exact encoded bytes."}}}},
                       {"addr", "type", "value"}), true,
                [&memory](const json& args) { return memory.prepare(args); }},
            {"apply_memory_patch", "Apply a prepared patch only if the live process and original bytes still match, then read back to verify. Not atomic against the target process.",
                schema({{"patch_id", {{"type", "string"}, {"minLength", 1}}}}, {"patch_id"}), false,
                [&memory](const json& args) { return memory.apply(args); }}
        };
        for (const auto& tool : tools_) handlers_.emplace(tool.name, tool.function);
    }

    std::optional<json> mcp_server::handle(const json& message) {
        if (!message.is_object()) return error(nullptr, -32600, "invalid_request");
        const bool has_id = message.contains("id");
        const auto id = has_id ? message.at("id") : json(nullptr);
        if ((has_id && !id.is_string() && !id.is_number_integer() && !id.is_null()) ||
            !message.contains("jsonrpc") || message.at("jsonrpc") != "2.0" ||
            !message.contains("method") || !message.at("method").is_string())
            return error(nullptr, -32600, "invalid_request");
        if (message.contains("params") && !message.at("params").is_object()) {
            if (!has_id) return std::nullopt;
            return error(id, -32602, "params_must_be_object");
        }
        // Notifications never execute a tool or produce a response.
        if (!has_id) return std::nullopt;
        const auto method = message.at("method").get<std::string>();
        const auto params = message.value("params", json::object());
        if (method == "ping") return result(id, json::object());
        if (method == "initialize") {
            if (!params.contains("protocolVersion") || !params.at("protocolVersion").is_string())
                return error(id, -32602, "protocol_version_required");
            return result(id, {{"protocolVersion", "2025-03-26"},
                {"capabilities", {{"tools", json::object()}}},
                {"serverInfo", {{"name", "evoke-mcp"}, {"version", "2.1.0"}}}});
        }
        if (method == "tools/list") {
            auto list = json::array();
            for (const auto& tool : tools_)
                list.push_back({{"name", tool.name}, {"description", tool.description},
                    {"inputSchema", tool.input_schema}, {"annotations", {
                        {"readOnlyHint", tool.read_only_hint}, {"destructiveHint", !tool.read_only_hint},
                        {"openWorldHint", false}}}});
            return result(id, {{"tools", list}});
        }
        if (method == "tools/call") {
            if (!params.contains("name") || !params.at("name").is_string())
                return error(id, -32602, "tool_name_required");
            const auto handler = handlers_.find(params.at("name").get<std::string>());
            if (handler == handlers_.end()) return error(id, -32602, "unknown_tool");
            const auto args = params.value("arguments", json::object());
            if (!args.is_object()) return error(id, -32602, "arguments_must_be_object");
            try { return result(id, handler->second(args)); }
            catch (const std::exception& exception) {
                return result(id, make_tool_result(exception.what(), {{"status", exception.what()}}, true));
            }
        }
        return error(id, -32601, "method_not_found");
    }
}
