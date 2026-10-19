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
        const json emulation_integer = {{"oneOf", json::array({
            {{"type", "integer"}, {"minimum", 0}},
            {{"type", "string"}, {"pattern", "^(0x[0-9a-fA-F]+|[0-9]+)$"}}
        })}};
        const json emulation_registers = {{"type", "object"}, {"additionalProperties", false}, {"properties", json::object()}};
        auto register_schema = emulation_registers;
        for (auto name : {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags", "fs_base", "gs_base"})
            register_schema["properties"][name] = emulation_integer;
        const auto buffer_ref = schema({{"buffer", {{"type", "string"}, {"minLength", 1}, {"maxLength", 64}}},
            {"offset", emulation_integer}}, {"buffer"});
        const json operation_argument = {{"oneOf", json::array({emulation_integer, buffer_ref,
            schema({{"result", {{"type", "integer"}, {"minimum", 0}, {"maximum", 63}}}}, {"result"}),
            schema({{"read_u64", buffer_ref}}, {"read_u64"})})}};
        tools_ = {
            {"get_windows_emulation_info", "Report the bundled KernEmul Windows handler runtime, bounds, invocation mode and limitations. No live system or driver operations.",
                schema(json::object(), json::array()), true,
                [this](const json& args) { return windows_.info(args); }},
            {"list_windows_operations", "Enumerate actual registered KernEmul implementations across kernel modules, including Nt/Zw syscall handlers. Returns argument counts, provenance, exact runtime counts and pagination. Does not imply complete native fidelity.",
                schema({{"module", {{"type", "string"}}}, {"name", {{"type", "string"}}},
                    {"syscalls_only", {{"type", "boolean"}}}, {"offset", {{"type", "integer"}, {"minimum", 0}}},
                    {"limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 200}, {"default", 100}}}}, json::array()), true,
                [this](const json& args) { return windows_.catalog(args); }},
            {"emulate_windows_operations", "Execute named original KernEmul handlers in a fresh Windows guest model, preserving guest state across up to 64 operations. Supports buffers, prior results and guest handle references; returns effects, raw return values and upstream diagnostics. Nt/Zw calls use their names, without numeric syscall dispatch or PE execution. Guest state only; no live-driver access.",
                schema({{"context", {{"type", "string"}, {"enum", json::array({"kernel", "user"})}, {"default", "kernel"}}},
                    {"timeout_ms", {{"type", "integer"}, {"minimum", 100}, {"maximum", 10000}, {"default", 3000}}},
                    {"buffers", {{"type", "array"}, {"maxItems", 32}, {"items", schema({
                        {"id", {{"type", "string"}, {"minLength", 1}, {"maxLength", 64}}},
                        {"bytes_hex", {{"type", "string"}, {"maxLength", 32768}, {"pattern", "^([0-9a-fA-F]{2})*$"}}},
                        {"size", {{"type", "integer"}, {"minimum", 1}, {"maximum", 16384}}}
                    }, {"id"})}}},
                    {"operations", {{"type", "array"}, {"minItems", 1}, {"maxItems", 64}, {"items", schema({
                        {"module", {{"type", "string"}, {"default", "ntoskrnl.exe"}}}, {"name", {{"type", "string"}}},
                        {"arguments", {{"type", "array"}, {"maxItems", 16}, {"items", operation_argument}}}
                    }, {"name", "arguments"})}}},
                    {"patches", {{"type", "array"}, {"maxItems", 64}, {"items", schema({
                        {"buffer", {{"type", "string"}}}, {"offset", emulation_integer}, {"value", operation_argument}
                    }, {"buffer", "offset", "value"})}}},
                    {"reads", {{"type", "array"}, {"maxItems", 16}, {"items", schema({
                        {"address", operation_argument}, {"size", {{"type", "integer"}, {"minimum", 1}, {"maximum", 16384}}}
                    }, {"address", "size"})}}}
                }, {"operations"}), true,
                [this](const json& args) { return windows_.run(args); }},
            {"list_api_models", "List named emulated APIs and Windows host-snapshot bridges, with signatures, supported modules, availability, provenance, and fidelity limits. This is an explicit subset, not all Windows APIs.",
                schema({{"module", {{"type", "string"}}}, {"name", {{"type", "string"}}}}, json::array()), true,
                [this](const json& args) { return emulation_.api_catalog(args); }},
            {"get_system_snapshot", "Read actual host Windows time, performance counters, uptime, system information, and memory status through supported Win32 APIs. Read-only; returns explicit unavailability on other hosts.",
                schema(json::object(), json::array()), true,
                [this](const json& args) { return emulation_.system_snapshot(args); }},
            {"get_emulation_info", "Report the built-in Unicorn x86-64 emulator, limits, default stack, and availability of explicit API models and host-snapshot bridges. Available without a connected driver.",
                schema(json::object(), json::array()), true,
                [this](const json& args) { return emulation_.info(args); }},
            {"emulate_region", "Emulate supplied x86-64 bytes with optional registers and guest memory. Return registers, instruction/memory traces, changed guest bytes, and a precise stop reason. Bind named APIs to guest models or read-only Windows snapshots using imports. Unsupported APIs, missing memory and external instructions stop execution; no live-driver access. Fresh state per call.",
                schema({
                    {"code_hex", {{"type", "string"}, {"minLength", 2}, {"maxLength", 32768}, {"pattern", "^([0-9a-fA-F]{2})+$"}}},
                    {"address", emulation_integer}, {"entry_offset", emulation_integer}, {"registers", register_schema},
                    {"imports", {{"type", "array"}, {"maxItems", 32}, {"items", schema({
                        {"module", {{"type", "string"}, {"minLength", 1}, {"maxLength", 128}}},
                        {"name", {{"type", "string"}, {"minLength", 1}, {"maxLength", 128}}},
                        {"address", emulation_integer},
                        {"backend", {{"type", "string"}, {"enum", json::array({"model", "host_snapshot"})}}}
                    }, {"module", "name", "address"})}}},
                    {"instruction_limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 100000}, {"default", 10000}}},
                    {"timeout_ms", {{"type", "integer"}, {"minimum", 1}, {"maximum", 500}, {"default", 100}}},
                    {"trace_limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 512}, {"default", 128}}},
                    {"memory", {{"type", "array"}, {"maxItems", 8}, {"items", schema({
                        {"address", emulation_integer},
                        {"bytes_hex", {{"type", "string"}, {"minLength", 2}, {"maxLength", 8192}, {"pattern", "^([0-9a-fA-F]{2})+$"}}},
                        {"permissions", {{"type", "string"}, {"enum", json::array({"r", "rw", "rx", "rwx"})}, {"default", "rw"}}}
                    }, {"address", "bytes_hex"})}}}
                }, {"code_hex"}), true,
                [this](const json& args) { return emulation_.run(args); }},
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
                {"serverInfo", {{"name", "evoke-mcp"}, {"version", "2.4.0"}}}});
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
