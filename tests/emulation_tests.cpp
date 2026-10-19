#include "emulation_service.hpp"

#include <chrono>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

using namespace mcp_runtime;
namespace {
    int assertions = 0;
    void check(bool value, const char* message) {
        ++assertions;
        if (!value) throw std::runtime_error(message);
    }
    template<class Function> void rejects(Function function, const char* message) {
        bool rejected = false;
        try { function(); } catch(const std::exception&) { rejected = true; }
        check(rejected, message);
    }
    json result(const json& value) { return value.at("structuredContent"); }
    void status(const json& value, const char* expected) {
        if (result(value).at("status") != expected) std::cerr << value.dump() << '\n';
        check(result(value).at("status") == expected, expected);
        check(value.at("isError") == (std::string(expected) != "completed"), "partial runs are tool errors");
        check(result(value).at("live_memory_modified") == false, "no live writes");
    }
    void arithmetic_and_stack() {
        emulation_service service;
        check(result(service.info(json::object())).at("built_in") == true, "Unicorn built in");
        const auto value = service.run({{"code_hex", "4889c84801d0c3"}, {"registers", {{"rcx", 7}, {"rdx", 35}}}});
        status(value, "completed");
        const auto out = result(value);
        check(out.at("registers").at("rax") == "0x2a", "arithmetic result");
        check(out.at("rip") == "0x100007", "return reaches synthetic exit");
        check(out.at("instructions_observed") == 3, "instruction trace includes ret");
        check(out.at("instruction_trace").at(0).at("bytes_hex") == "4889c8", "instruction bytes captured");
        check(out.at("registers").at("rsp") == "0x7000ffe0", "Windows x64 stack has return address");
        const auto next = result(service.run({{"code_hex", "c3"}}));
        check(next.at("registers").at("rax") == "0x0", "fresh registers every run");
        check(next.at("instructions_observed") == 1, "fresh trace every run");
        status(service.run({{"code_hex", "b82a000000c3"}, {"address", "0xfffff80000001000"}}), "completed");
        const auto offset = service.run({{"code_hex", "0f0bb82a000000c3"}, {"entry_offset", 2}});
        status(offset, "completed");
        check(result(offset).at("registers").at("rax") == "0x2a", "entry offset skips prefix");
    }
    void guest_memory() {
        emulation_service service;
        json args = {{"code_hex", "c7012a0000008b01c3"}, {"registers", {{"rcx", "0x200000"}}},
            {"memory", json::array({{{"address", "0x200000"}, {"bytes_hex", "00000000"}}})}};
        const auto value = service.run(args);
        status(value, "completed");
        const auto out = result(value);
        check(out.at("memory").at(0).at("before_hex") == "00000000", "memory before recorded");
        check(out.at("memory").at(0).at("after_hex") == "2a000000", "guest writes captured");
        check(out.at("registers").at("rax") == "0x2a", "guest read result");
        bool saw_write = false;
        for (const auto& event : out.at("memory_trace"))
            if (event.at("access") == "write" && event.at("address") == "0x200000") saw_write = true;
        check(saw_write, "memory write trace");
        args["memory"][0]["permissions"] = "r";
        const auto fault = service.run(args);
        status(fault, "memory_fault");
        check(result(fault).at("fault").at("access") == "write_protected", "write protection diagnosed");
        check(result(fault).at("memory").at(0).at("after_hex") == "00000000", "failed write did not affect guest bytes");
        const auto helper = service.run({{"code_hex", "48b80000200000000000ffd0c3"},
            {"memory", json::array({{{"address", "0x200000"}, {"bytes_hex", "b82a000000c3"}, {"permissions", "rx"}}})}});
        status(helper, "completed");
        check(result(helper).at("registers").at("rax") == "0x2a", "explicitly mapped helper emulated");
    }
    void incomplete_runs() {
        emulation_service service;
        const auto loop = service.run({{"code_hex", "ebfe"}, {"instruction_limit", 10}, {"trace_limit", 2}});
        status(loop, "instruction_limit");
        check(result(loop).at("instruction_trace").size() == 2, "bounded trace size");
        check(result(loop).at("trace_truncated") == true, "truncation reported");
        check(result(loop).at("instructions_observed") == 10, "instruction budget honored");
        const auto fault = service.run({{"code_hex", "488b01"}});
        status(fault, "memory_fault");
        check(result(fault).at("fault").at("address") == "0x0", "missing dependency address reported");
        const auto call = service.run({{"code_hex", "48b80000300000000000ffd0"}});
        status(call, "memory_fault");
        check(result(call).at("fault").at("access") == "fetch_unmapped", "missing routine diagnosed");
        for (auto code : {"0f05", "0f34", "ec", "ee"})
            status(service.run({{"code_hex", code}}), "external_instruction");
        const auto input = service.run({{"code_hex", "f3ec"}, {"registers", {{"rax", 42}}}});
        status(input, "external_instruction");
        check(result(input).at("registers").at("rax") == "0x2a", "unmodeled port input preserves register state");
        check(result(input).at("rip") == "0x100000", "external instruction is not executed");
        status(service.run({{"code_hex", "cc"}}), "interrupt");
        status(service.run({{"code_hex", "f4"}}), "halted");
        status(service.run({{"code_hex", "f3f4"}}), "halted");
        const auto invalid = result(service.run({{"code_hex", "0f0b"}}));
        check(invalid.at("completed") == false, "invalid instruction never reported complete");
        check(invalid.at("status") == "unsupported_instruction" || invalid.at("status") == "interrupt", "invalid instruction diagnosed");
        const auto start = std::chrono::steady_clock::now();
        const auto timeout = result(service.run({{"code_hex", "ebfe"}, {"instruction_limit", 100000}, {"timeout_ms", 1}, {"trace_limit", 1}}));
        check(timeout.at("status") == "timeout" || timeout.at("status") == "instruction_limit", "bounded looping execution");
        check(std::chrono::steady_clock::now() - start < std::chrono::seconds(5), "run terminates promptly");
    }
    void validation() {
        emulation_service service;
        for (auto code : {json(""), json("0"), json("zz"), json("90 90"), json(true), json(std::string(32770, '9'))})
            rejects([&] { service.run({{"code_hex", code}}); }, "invalid code rejected");
        for (auto address : {json(-1), json(true), json(1.5), json("0x"), json("-1"), json("18446744073709551616"), json("0x10000000000000000")})
            rejects([&] { service.run({{"code_hex", "c3"}, {"address", address}}); }, "invalid address rejected");
        rejects([&] { service.run({{"code_hex", "c3"}, {"address", std::numeric_limits<std::uint64_t>::max()}}); }, "address overflow rejected");
        rejects([&] { service.run({{"code_hex", "c3"}, {"address", "0x70000000"}}); }, "stack collision rejected");
        rejects([&] { service.run({{"code_hex", "c3"}, {"entry_offset", 1}}); }, "invalid entry offset rejected");
        rejects([&] { service.run({{"code_hex", "c3"}, {"registers", {{"rip", 0}}}}); }, "unknown register rejected");
        rejects([&] { service.run({{"code_hex", "c3"}, {"registers", json::array()}}); }, "register array rejected");
        for (auto key : {"instruction_limit", "trace_limit", "timeout_ms"}) {
            rejects([&] { service.run({{"code_hex", "c3"}, {key, 0}}); }, "zero budget rejected");
            rejects([&] { service.run({{"code_hex", "c3"}, {key, 100001}}); }, "excessive budget rejected");
        }
        rejects([&] { service.run({{"code_hex", "c3"}, {"memory", json::array({{{"address", "0x100001"}, {"bytes_hex", "00"}}})}}); }, "same-page overlap rejected");
        rejects([&] { service.run({{"code_hex", "c3"}, {"memory", json::array({{{"address", "0x200000"}, {"bytes_hex", "00"}, {"permissions", "unknown"}}})}}); }, "invalid permissions rejected");
        rejects([&] { service.run({{"code_hex", "c3"}, {"memory", json::array({{{"address", "0x200000"}, {"bytes_hex", std::string(8194, '0')}}})}}); }, "oversized data region rejected");
        rejects([&] { service.run({{"code_hex", "c3"}, {"unexpected", true}}); }, "unknown argument rejected");
        rejects([&] { service.info({{"unexpected", true}}); }, "info validates arguments");
    }
}
int main() {
    try {
        arithmetic_and_stack(); guest_memory(); incomplete_runs(); validation();
        std::cout << assertions << " emulation assertions passed\n";
        return 0;
    } catch(const std::exception& exception) {
        std::cerr << "FAIL after " << assertions << " assertions: " << exception.what() << '\n';
        return 1;
    }
}
