#include "emulation_service.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace mcp_runtime {
    namespace {
        constexpr std::uint64_t page_size = 4096;
        constexpr std::uint64_t stack_base = 0x70000000, stack_size = 0x10000;
        constexpr std::uint64_t default_rsp = stack_base + stack_size - 0x28;
        struct register_definition { const char* name; int id; };
        constexpr register_definition registers[] = {
            {"rax", UC_X86_REG_RAX}, {"rbx", UC_X86_REG_RBX}, {"rcx", UC_X86_REG_RCX},
            {"rdx", UC_X86_REG_RDX}, {"rsi", UC_X86_REG_RSI}, {"rdi", UC_X86_REG_RDI},
            {"rbp", UC_X86_REG_RBP}, {"rsp", UC_X86_REG_RSP}, {"r8", UC_X86_REG_R8},
            {"r9", UC_X86_REG_R9}, {"r10", UC_X86_REG_R10}, {"r11", UC_X86_REG_R11},
            {"r12", UC_X86_REG_R12}, {"r13", UC_X86_REG_R13}, {"r14", UC_X86_REG_R14},
            {"r15", UC_X86_REG_R15}, {"rflags", UC_X86_REG_RFLAGS},
            {"fs_base", UC_X86_REG_FS_BASE}, {"gs_base", UC_X86_REG_GS_BASE}
        };
        void check(uc_err result) {
            if (result != UC_ERR_OK) throw std::runtime_error(std::string("unicorn: ") + uc_strerror(result));
        }
        void fields(const json& args, std::initializer_list<const char*> required,
                    std::initializer_list<const char*> optional = {}) {
            if (!args.is_object()) throw std::invalid_argument("arguments_must_be_object");
            for (auto key : required)
                if (!args.contains(key)) throw std::invalid_argument(std::string("missing_") + key);
            for (const auto& item : args.items()) {
                bool known = false;
                for (auto key : required) known |= item.key() == key;
                for (auto key : optional) known |= item.key() == key;
                if (!known) throw std::invalid_argument("unexpected_emulation_argument");
            }
        }
        std::uint64_t number(const json& value) {
            if (value.is_number_integer()) {
                if (!value.is_number_unsigned() && value.get<std::int64_t>() < 0)
                    throw std::invalid_argument("negative_emulation_integer");
                return value.get<std::uint64_t>();
            }
            if (value.is_string()) {
                auto text = value.get<std::string>();
                std::string_view view(text);
                int base = 10;
                if (view.starts_with("0x")) { base = 16; view.remove_prefix(2); }
                std::uint64_t out = 0;
                const auto parsed = std::from_chars(view.data(), view.data() + view.size(), out, base);
                if (!view.empty() && parsed.ec == std::errc() && parsed.ptr == view.data() + view.size()) return out;
            }
            throw std::invalid_argument("unsigned_integer_or_hex_string_required");
        }
        std::size_t limit(const json& args, const char* name, std::size_t fallback, std::size_t maximum) {
            if (args.contains(name) && !args.at(name).is_number_integer())
            throw std::invalid_argument(std::string("integer_required_for_") + name);
        const auto value = args.contains(name) ? number(args.at(name)) : fallback;
            if (!value || value > maximum) throw std::invalid_argument(std::string("invalid_") + name);
            return static_cast<std::size_t>(value);
        }
        std::string hex_number(std::uint64_t value) {
            std::ostringstream out;
            out << "0x" << std::hex << value;
            return out.str();
        }
        std::string hex_bytes(const std::uint8_t* bytes, std::size_t size) {
            std::ostringstream out;
            out << std::hex << std::setfill('0');
            for (std::size_t index = 0; index < size; ++index) out << std::setw(2) << static_cast<unsigned>(bytes[index]);
            return out.str();
        }
        std::vector<std::uint8_t> decode(const json& value, std::size_t maximum) {
            const auto text = value.get<std::string>();
            if (text.empty() || text.size() % 2 || text.size() > maximum * 2)
                throw std::invalid_argument("invalid_hex_byte_length");
            auto nibble = [](char c) -> unsigned {
                if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
                if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
                if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
                throw std::invalid_argument("invalid_hex_byte");
            };
            std::vector<std::uint8_t> out;
            out.reserve(text.size() / 2);
            for (std::size_t index = 0; index < text.size(); index += 2)
                out.push_back(static_cast<std::uint8_t>((nibble(text[index]) << 4) | nibble(text[index + 1])));
            return out;
        }
        struct region {
            std::uint64_t address, mapped_address, mapped_size;
            std::vector<std::uint8_t> data;
            unsigned permissions;
        };
        region make_region(std::uint64_t addr, std::vector<std::uint8_t> data, unsigned permissions) {
            constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
            if (addr > maximum - data.size() || addr + data.size() > maximum - (page_size - 1))
                throw std::invalid_argument("emulation_address_overflow");
            const auto first = addr & ~(page_size - 1);
            const auto last = (addr + data.size() + page_size - 1) & ~(page_size - 1);
            return {addr, first, last - first, std::move(data), permissions};
        }
        void disjoint(const region& a, const region& b) {
            if (a.mapped_address < b.mapped_address + b.mapped_size && b.mapped_address < a.mapped_address + a.mapped_size)
                throw std::invalid_argument("overlapping_emulation_pages");
        }
        unsigned permissions(const json& value) {
            const auto text = value.get<std::string>();
            if (text == "r") return UC_PROT_READ;
            if (text == "rw") return UC_PROT_READ | UC_PROT_WRITE;
            if (text == "rx") return UC_PROT_READ | UC_PROT_EXEC;
            if (text == "rwx") return UC_PROT_ALL;
            throw std::invalid_argument("invalid_emulation_permissions");
        }
        const char* access_name(uc_mem_type type) {
            switch (type) {
                case UC_MEM_READ: return "read";
                case UC_MEM_WRITE: return "write";
                case UC_MEM_READ_UNMAPPED: return "read_unmapped";
                case UC_MEM_WRITE_UNMAPPED: return "write_unmapped";
                case UC_MEM_FETCH_UNMAPPED: return "fetch_unmapped";
                case UC_MEM_READ_PROT: return "read_protected";
                case UC_MEM_WRITE_PROT: return "write_protected";
                case UC_MEM_FETCH_PROT: return "fetch_protected";
                default: return "other";
            }
        }
        struct instruction_event { std::uint64_t address; std::uint32_t size; std::array<std::uint8_t, 15> bytes{}; };
        struct memory_event { uc_mem_type access; std::uint64_t address; int size; std::uint64_t value; };
        struct trace_state {
            std::size_t maximum, observed = 0, memory_observed = 0;
            std::vector<instruction_event> instructions;
            std::vector<memory_event> memory;
            const char* stop = nullptr;
            bool has_fault = false;
            memory_event fault{};
            std::uint32_t interrupt = 0;
        };
        // Hook buffers are reserved and events contain no allocating fields. Never
        // allocate JSON or propagate C++ exceptions through Unicorn's C callbacks.
        void on_code(uc_engine* engine, std::uint64_t addr, std::uint32_t size, void* context) {
            auto& state = *static_cast<trace_state*>(context);
            ++state.observed;
            instruction_event event{addr, size, {}};
            const auto bytes = std::min<std::size_t>(size, event.bytes.size());
            if (bytes) uc_mem_read(engine, addr, event.bytes.data(), bytes);
            if (state.instructions.size() < state.maximum) state.instructions.push_back(event);
            std::size_t opcode = 0;
            while (opcode < bytes) {
                const auto prefix = event.bytes[opcode];
                if ((prefix >= 0x40 && prefix <= 0x4f) || prefix == 0x66 || prefix == 0x67 ||
                    prefix == 0xf0 || prefix == 0xf2 || prefix == 0xf3 || prefix == 0x2e ||
                    prefix == 0x36 || prefix == 0x3e || prefix == 0x26 || prefix == 0x64 || prefix == 0x65) ++opcode;
                else break;
            }
            if (opcode < bytes) {
                const auto op = event.bytes[opcode];
                const bool port_io = (op >= 0xe4 && op <= 0xe7) || (op >= 0xec && op <= 0xef) ||
                                     (op >= 0x6c && op <= 0x6f);
                const bool system_call = op == 0x0f && opcode + 1 < bytes &&
                    (event.bytes[opcode + 1] == 0x05 || event.bytes[opcode + 1] == 0x34);
                if (port_io || system_call) state.stop = "external_instruction";
                else if (op == 0xf4) state.stop = "halted";
                // Stop before execution, preserving registers instead of supplying
                // a fabricated port-read result or a syscall return value.
                if (state.stop) uc_emu_stop(engine);
            }
        }
        void on_memory(uc_engine*, uc_mem_type access, std::uint64_t addr, int size, std::int64_t value, void* context) {
            auto& state = *static_cast<trace_state*>(context);
            ++state.memory_observed;
            if (state.memory.size() < state.maximum)
                state.memory.push_back({access, addr, size, static_cast<std::uint64_t>(value)});
        }
        bool on_fault(uc_engine*, uc_mem_type access, std::uint64_t addr, int size, std::int64_t value, void* context) {
            auto& state = *static_cast<trace_state*>(context);
            state.has_fault = true;
            state.fault = {access, addr, size, static_cast<std::uint64_t>(value)};
            return false;
        }
        void on_interrupt(uc_engine* engine, std::uint32_t interrupt, void* context) {
            auto& state = *static_cast<trace_state*>(context);
            state.stop = "interrupt";
            state.interrupt = interrupt;
            uc_emu_stop(engine);
        }
        bool on_invalid(uc_engine*, void* context) {
            static_cast<trace_state*>(context)->stop = "unsupported_instruction";
            return false;
        }
    }

    json emulation_service::info(const json& args) {
        fields(args, {});
        unsigned major = 0, minor = 0;
        uc_version(&major, &minor);
        return make_tool_result("emulation_available", {{"engine", "unicorn"}, {"built_in", true},
            {"api_major", major}, {"api_minor", minor}, {"architecture", "x86_64"},
            {"kernel_api_model", false}, {"live_driver_access", false},
            {"maximum_code_bytes", 16384}, {"maximum_memory_regions", 8}, {"maximum_region_bytes", 4096},
            {"maximum_instructions", 100000}, {"maximum_timeout_ms", 500}, {"maximum_trace_events", 512},
            {"stack_address", hex_number(stack_base)}, {"stack_size", stack_size}, {"default_rsp", hex_number(default_rsp)}});
    }

    json emulation_service::run(const json& args) {
        fields(args, {"code_hex"}, {"address", "entry_offset", "registers", "memory", "instruction_limit", "timeout_ms", "trace_limit"});
        const auto code_address = args.contains("address") ? number(args.at("address")) : 0x100000;
        auto code = make_region(code_address, decode(args.at("code_hex"), 16384), UC_PROT_READ | UC_PROT_EXEC);
        const auto offset = args.contains("entry_offset") ? number(args.at("entry_offset")) : 0;
        if (offset >= code.data.size()) throw std::invalid_argument("entry_offset_outside_code");
        const auto instruction_limit = limit(args, "instruction_limit", 10000, 100000);
        const auto timeout_ms = limit(args, "timeout_ms", 100, 500);
        const auto trace_limit = limit(args, "trace_limit", 128, 512);
        std::vector<region> regions;
        regions.push_back(std::move(code));
        regions.push_back(make_region(stack_base, std::vector<std::uint8_t>(stack_size), UC_PROT_READ | UC_PROT_WRITE));
        disjoint(regions[0], regions[1]);
        if (args.contains("memory")) {
            const auto& input = args.at("memory");
            if (!input.is_array() || input.size() > 8) throw std::invalid_argument("invalid_emulation_memory_regions");
            for (const auto& item : input) {
                fields(item, {"address", "bytes_hex"}, {"permissions"});
                auto region = make_region(number(item.at("address")), decode(item.at("bytes_hex"), 4096),
                    item.contains("permissions") ? permissions(item.at("permissions")) : UC_PROT_READ | UC_PROT_WRITE);
                for (const auto& previous : regions) disjoint(region, previous);
                regions.push_back(std::move(region));
            }
        }
        std::vector<std::pair<int, std::uint64_t>> initial;
        if (args.contains("registers")) {
            if (!args.at("registers").is_object()) throw std::invalid_argument("registers_must_be_object");
            for (const auto& item : args.at("registers").items()) {
                const auto definition = std::find_if(std::begin(registers), std::end(registers),
                    [&](const auto& reg) { return item.key() == reg.name; });
                if (definition == std::end(registers)) throw std::invalid_argument("unknown_emulation_register");
                initial.emplace_back(definition->id, number(item.value()));
            }
        }
        std::unique_lock lock(mutex_, std::try_to_lock);
        if (!lock.owns_lock()) return make_tool_result("emulation_busy", {{"status", "emulation_busy"}}, true);
        uc_engine* raw = nullptr;
        check(uc_open(UC_ARCH_X86, UC_MODE_64, &raw));
        const std::unique_ptr<uc_engine, decltype(&uc_close)> engine(raw, uc_close);
        check(uc_ctl_set_tcg_buffer_size(raw, static_cast<std::uint32_t>(16 * 1024 * 1024)));
        // Guest virtual addresses are supplied directly; no physical page tables or
        // live address translation are used, including for high kernel addresses.
        check(uc_ctl_tlb_mode(raw, UC_TLB_VIRTUAL));
        for (const auto& region : regions) {
            check(uc_mem_map(raw, region.mapped_address, static_cast<std::size_t>(region.mapped_size), region.permissions));
            check(uc_mem_write(raw, region.address, region.data.data(), region.data.size()));
        }
        const auto until = code_address + regions[0].data.size();
        check(uc_mem_write(raw, default_rsp, &until, sizeof(until)));
        check(uc_reg_write(raw, UC_X86_REG_RSP, &default_rsp));
        for (const auto& [id, value] : initial) check(uc_reg_write(raw, id, &value));
        trace_state state{trace_limit, 0, 0, {}, {}, nullptr, false, {}, 0};
        state.instructions.reserve(trace_limit);
        state.memory.reserve(trace_limit);
        uc_hook hook{};
        check(uc_hook_add(raw, &hook, UC_HOOK_CODE, reinterpret_cast<void*>(on_code), &state, 1, 0));
        check(uc_hook_add(raw, &hook, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(on_memory), &state, 1, 0));
        check(uc_hook_add(raw, &hook, UC_HOOK_MEM_INVALID, reinterpret_cast<void*>(on_fault), &state, 1, 0));
        check(uc_hook_add(raw, &hook, UC_HOOK_INTR, reinterpret_cast<void*>(on_interrupt), &state, 1, 0));
        check(uc_hook_add(raw, &hook, UC_HOOK_INSN_INVALID, reinterpret_cast<void*>(on_invalid), &state, 1, 0));
        const auto error = uc_emu_start(raw, code_address + offset, until, timeout_ms * 1000, instruction_limit);
        std::uint64_t rip = 0;
        check(uc_reg_read(raw, UC_X86_REG_RIP, &rip));
        std::size_t timed_out = 0;
        check(uc_query(raw, UC_QUERY_TIMEOUT, &timed_out));
        const char* status = state.stop ? state.stop : state.has_fault ? "memory_fault" :
            error != UC_ERR_OK ? "engine_error" : timed_out ? "timeout" :
            rip == until ? "completed" : state.observed >= instruction_limit ? "instruction_limit" : "stopped";
        json out = {{"status", status}, {"engine", "unicorn"}, {"architecture", "x86_64"},
            {"completed", std::string_view(status) == "completed"}, {"rip", hex_number(rip)},
            {"instructions_observed", state.observed}, {"instruction_limit", instruction_limit},
            {"timeout_ms", timeout_ms}, {"timed_out", timed_out != 0},
            {"trace_truncated", state.observed > trace_limit}, {"memory_trace_truncated", state.memory_observed > trace_limit},
            {"registers", json::object()}, {"instruction_trace", json::array()}, {"memory_trace", json::array()},
            {"memory", json::array()}, {"live_memory_modified", false}};
        if (error != UC_ERR_OK) out["engine_error"] = uc_strerror(error);
        if (state.has_fault) out["fault"] = {{"access", access_name(state.fault.access)},
            {"address", hex_number(state.fault.address)}, {"size", state.fault.size}};
        if (state.stop && std::string_view(state.stop) == "interrupt") out["interrupt"] = state.interrupt;
        for (const auto& reg : registers) {
            std::uint64_t value = 0;
            check(uc_reg_read(raw, reg.id, &value));
            out["registers"][reg.name] = hex_number(value);
        }
        for (const auto& event : state.instructions)
            out["instruction_trace"].push_back({{"address", hex_number(event.address)}, {"size", event.size},
                {"bytes_hex", hex_bytes(event.bytes.data(), std::min<std::size_t>(event.size, event.bytes.size()))}});
        for (const auto& event : state.memory) {
            json entry = {{"access", access_name(event.access)}, {"address", hex_number(event.address)}, {"size", event.size}};
            if (event.access == UC_MEM_WRITE && event.size <= 8) entry["value"] = hex_number(event.value);
            out["memory_trace"].push_back(entry);
        }
        for (std::size_t index = 2; index < regions.size(); ++index) {
            auto after = regions[index].data;
            check(uc_mem_read(raw, regions[index].address, after.data(), after.size()));
            out["memory"].push_back({{"address", hex_number(regions[index].address)},
                {"before_hex", hex_bytes(regions[index].data.data(), regions[index].data.size())},
                {"after_hex", hex_bytes(after.data(), after.size())}});
        }
        const bool incomplete = !out.at("completed").get<bool>();
        return make_tool_result(status, out, incomplete);
    }
}
