#include "../httplib/httplib.h"
#include <bcrypt.h>
#include <array>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../driver/memory_backend.hpp"
#include "../mcp/http_security.hpp"
#include "../mcp/server.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace {
    std::string patch_id() {
        std::array<unsigned char, 16> random{};
        if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            throw std::runtime_error("patch_id_generation_failed");
        constexpr char digits[] = "0123456789abcdef";
        std::string out;
        for (auto value : random) {
            out += digits[value >> 4];
            out += digits[value & 15];
        }
        return out;
    }
}

int main() {
    const auto* configured_token = std::getenv("EVOKE_MCP_TOKEN");
    const std::string token = configured_token ? configured_token : "";
    if (token.size() < 32 || token.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) {
        std::cerr << "Set EVOKE_MCP_TOKEN to a random token of at least 32 URL-safe characters.\n";
        return 1;
    }
    driver::km->init();
    driver::km->attach(L"FortniteClient-Win64-Shipping.exe");
    driver::windows_memory_backend backend(*driver::km);
    if (!backend.identity()) {
        std::cerr << "Driver or target unavailable; cannot start memory service.\n";
        return 1;
    }
    std::ofstream audit("evoke-mcp-audit.jsonl", std::ios::app);
    if (!audit) {
        std::cerr << "Cannot open evoke-mcp-audit.jsonl.\n";
        return 1;
    }
    mcp_runtime::memory_service memory(backend, patch_id, [&](const mcp_runtime::json& record) {
        audit << record.dump() << '\n';
        audit.flush();
        if (!audit) throw std::runtime_error("audit_sink_failed");
    });
    mcp_runtime::mcp_server server_core(memory);
    httplib::Server http_server;
    http_server.set_payload_max_length(16 * 1024);

    const auto authorize = [&](const httplib::Request& request, httplib::Response& response, bool preflight = false) {
        const auto origin = request.get_header_value("Origin");
        if (request.get_header_value_count("Host") != 1 || request.get_header_value_count("Origin") > 1 ||
            !mcp_runtime::host_allowed(request.get_header_value("Host")) || !mcp_runtime::origin_allowed(origin)) {
            response.status = 403;
            return false;
        }
        if (!origin.empty()) {
            response.set_header("Access-Control-Allow-Origin", origin);
            response.set_header("Vary", "Origin");
        }
        if (!preflight && (request.get_header_value_count("Authorization") != 1 ||
            !mcp_runtime::token_matches(request.get_header_value("Authorization"), token))) {
            response.status = 401;
            response.set_header("WWW-Authenticate", "Bearer");
            return false;
        }
        return true;
    };
    http_server.Get("/mcp", [&](const httplib::Request& request, httplib::Response& response) {
        if (authorize(request, response)) response.status = 405; // No SSE stream is offered.
    });
    http_server.Options("/mcp", [&](const httplib::Request& request, httplib::Response& response) {
        if (!authorize(request, response, true)) return;
        response.set_header("Access-Control-Allow-Headers", "content-type, authorization, mcp-protocol-version");
        response.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
        response.status = 204;
    });
    http_server.Get("/health", [&](const httplib::Request& request, httplib::Response& response) {
        if (!authorize(request, response)) return;
        response.status = backend.identity() ? 200 : 503;
        response.set_content(response.status == 200 ? "ok" : "target_unavailable", "text/plain");
    });
    http_server.Post("/mcp", [&](const httplib::Request& request, httplib::Response& response) {
        if (!authorize(request, response)) return;
        const auto content_type = request.get_header_value("Content-Type");
        if (content_type.substr(0, content_type.find(';')) != "application/json") {
            response.status = 415;
            return;
        }
        try {
            const auto output = server_core.handle(mcp_runtime::json::parse(request.body));
            if (output) response.set_content(output->dump(), "application/json");
            else response.status = 202;
        } catch (const mcp_runtime::json::parse_error&) {
            response.status = 400;
            response.set_content(R"({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse_error"}})", "application/json");
        } catch (const std::exception&) {
            response.status = 500;
            response.set_content(R"({"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal_error"}})", "application/json");
        }
    });
    std::cout << "Listening on http://127.0.0.1:8888/mcp\n";
    if (!http_server.listen("127.0.0.1", 8888)) {
        std::cerr << "Cannot bind port 8888.\n";
        return 1;
    }
    return 0;
}
