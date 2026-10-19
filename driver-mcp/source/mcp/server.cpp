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
        auto schema = [](json properties, json required) {
            return json{{"type", "object"}, {"properties", properties},
                        {"required", required}, {"additionalProperties", false}};
        };
        tools_ = {
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
                {"serverInfo", {{"name", "evoke-mcp"}, {"version", "2.0.0"}}}});
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
