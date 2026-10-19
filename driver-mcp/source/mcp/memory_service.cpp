#include "memory_service.hpp"
#include "routines/type_dispatch.hpp"

#include <bit>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <type_traits>

namespace mcp_runtime {
    namespace {
        using bytes = std::vector<std::uint8_t>;
        static_assert(std::endian::native == std::endian::little, "Windows target memory is little endian");

        void fields(const json& args, std::initializer_list<const char*> required,
                    std::initializer_list<const char*> optional = {}) {
            if (!args.is_object()) throw std::invalid_argument("arguments_must_be_object");
            for (const auto* key : required)
                if (!args.contains(key)) throw std::invalid_argument(std::string("missing_") + key);
            for (const auto& item : args.items()) {
                bool known = false;
                for (const auto* key : required) known |= item.key() == key;
                for (const auto* key : optional) known |= item.key() == key;
                if (!known) throw std::invalid_argument("unexpected_argument");
            }
        }

        std::uint64_t unsigned_integer(const json& value) {
            if (!value.is_number_integer()) throw std::invalid_argument("integer_required");
            if (!value.is_number_unsigned() && value.get<std::int64_t>() < 0)
                throw std::invalid_argument("negative_unsigned_integer");
            return value.get<std::uint64_t>();
        }

        template<class T> bytes pack(T value) {
            bytes out(sizeof(T));
            std::memcpy(out.data(), &value, sizeof(T));
            return out;
        }
        template<class T> json unpack(const bytes& data) {
            T value{};
            std::memcpy(&value, data.data(), sizeof(T));
            if constexpr (std::is_floating_point_v<T>) {
                if (!std::isfinite(value)) throw std::invalid_argument("non_finite_memory_value");
            }
            return value;
        }
        template<class T> bytes encode(const json& value) {
            if constexpr (std::is_unsigned_v<T>) {
                const auto number = unsigned_integer(value);
                if (number > std::numeric_limits<T>::max()) throw std::invalid_argument("value_out_of_range");
                return pack(static_cast<T>(number));
            } else if constexpr (std::is_integral_v<T>) {
                if (!value.is_number_integer()) throw std::invalid_argument("integer_required");
                if (value.is_number_unsigned() && value.get<std::uint64_t>() > static_cast<std::uint64_t>(std::numeric_limits<T>::max()))
                    throw std::invalid_argument("value_out_of_range");
                const auto number = value.get<std::int64_t>();
                if (number < std::numeric_limits<T>::min() || number > std::numeric_limits<T>::max())
                    throw std::invalid_argument("value_out_of_range");
                return pack(static_cast<T>(number));
            } else {
                if (!value.is_number()) throw std::invalid_argument("number_required");
                const double number = value.get<double>();
                if (!std::isfinite(number) || std::abs(number) > std::numeric_limits<T>::max())
                    throw std::invalid_argument("value_out_of_range");
                const auto converted = static_cast<T>(number);
                if (number != 0 && converted == 0) throw std::invalid_argument("value_underflow");
                return pack(converted);
            }
        }

        template<class Function> auto dispatch(const std::string& name, Function function) {
            const auto type = parse_primitive_type(name);
            if (!type) throw std::invalid_argument("bad_type");
            switch (*type) {
                case primitive_type::byte:
                case primitive_type::u8: return function.template operator()<std::uint8_t>();
                case primitive_type::u16: return function.template operator()<std::uint16_t>();
                case primitive_type::u32: return function.template operator()<std::uint32_t>();
                case primitive_type::u64: return function.template operator()<std::uint64_t>();
                case primitive_type::i8: return function.template operator()<std::int8_t>();
                case primitive_type::i16: return function.template operator()<std::int16_t>();
                case primitive_type::i32: return function.template operator()<std::int32_t>();
                case primitive_type::i64: return function.template operator()<std::int64_t>();
                case primitive_type::f32: return function.template operator()<float>();
                case primitive_type::f64: return function.template operator()<double>();
            }
            throw std::invalid_argument("bad_type");
        }

        std::string type_name(const json& args) { return args.at("type").get<std::string>(); }
        std::size_t width(const std::string& type) {
            return dispatch(type, []<class T>() -> std::size_t { return sizeof(T); });
        }
        void validate_range(std::uint64_t addr, std::uint64_t size) {
            constexpr std::uint64_t maximum = 0x00007fffffffffffULL;
            if (!size || size > maximum || addr < 0x10000 || addr > maximum - (size - 1))
                throw std::invalid_argument("invalid_user_address_range");
        }
        std::uint64_t address(const json& args, std::size_t size) {
            const auto result = unsigned_integer(args.at("addr"));
            validate_range(result, size);
            return result;
        }
        page_protection parse_protection(const json& value) {
            const auto name = value.get<std::string>();
            for (const auto& [text, protection] : std::initializer_list<std::pair<const char*, page_protection>>{
                {"no_access", page_protection::no_access}, {"read_only", page_protection::read_only},
                {"read_write", page_protection::read_write}, {"execute", page_protection::execute},
                {"execute_read", page_protection::execute_read}, {"execute_read_write", page_protection::execute_read_write}})
                if (name == text) return protection;
            throw std::invalid_argument("invalid_page_protection");
        }
        std::string hex(const bytes& data) {
            std::ostringstream stream;
            stream << std::hex << std::setfill('0');
            for (auto value : data) stream << std::setw(2) << static_cast<unsigned>(value);
            return stream.str();
        }
        json target_json(const target_identity& target) {
            return {{"pid", target.pid}, {"creation_time", std::to_string(target.creation_time)},
                    {"base", target.base}};
        }
        target_identity require_target(memory_backend& backend) {
            auto target = backend.identity();
            if (!target) throw std::runtime_error("target_unavailable");
            return *target;
        }
        bytes read_bytes(memory_backend& backend, std::uint64_t addr, std::size_t size) {
            bytes out(size);
            if (!backend.read(addr, out.data(), size)) throw std::runtime_error("driver_read_failed");
            return out;
        }
    }

    memory_service::memory_service(memory_backend& backend, id_function next_id,
                                   audit_function audit, now_function now,
                                   std::chrono::seconds ttl, std::size_t capacity)
        : backend_(backend), next_id_(std::move(next_id)), audit_(std::move(audit)),
          now_(std::move(now)), ttl_(ttl), capacity_(capacity) {
        if (!next_id_ || !now_ || ttl_ <= std::chrono::seconds::zero() || capacity_ == 0)
            throw std::invalid_argument("invalid_service_configuration");
    }

    void memory_service::require_operation(driver_operation operation) {
        if (!backend_.supports(operation)) throw std::runtime_error("operation_not_supported_by_adapter");
    }

    json memory_service::control(const char* operation, json details, const std::function<json()>& action) {
        // Caller holds mutex_ across the audit sink, backend operation, and patch invalidation.
        details["operation"] = operation;
        details["operation_id"] = next_id_();
        details["operation_attempted"] = false;
        details["ok"] = false;
        auto timestamp = [&] {
            details["timestamp_unix_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        };
        details["status"] = "operation_started";
        timestamp();
        if (audit_) {
            try { audit_(details); }
            catch (...) { return make_tool_result("audit_unavailable_no_operation", {
                {"status", "audit_unavailable_no_operation"}, {"operation", operation},
                {"operation_id", details["operation_id"]}, {"operation_attempted", false}, {"ok", false}}, true); }
        }
        // A lifecycle or memory-map operation may invalidate an existing preview even
        // if its driver call fails. Never allow those previews to be reused.
        patches_.clear();
        details["operation_attempted"] = true;
        try { details.update(action()); }
        catch (const std::exception& exception) { details["status"] = exception.what(); }
        timestamp();
        bool audit_failed = false;
        if (audit_) {
            try { audit_(details); }
            catch (...) { details["audit_error"] = "audit_sink_failed"; audit_failed = true; }
        }
        return make_tool_result(details.at("status").get<std::string>(), details,
                                !details.at("ok").get<bool>() || audit_failed);
    }

    json memory_service::driver_status(const json& args) {
        fields(args, {});
        std::lock_guard lock(mutex_);
        std::erase_if(patches_, [&](const auto& item) { return item.second.expires <= now_(); });
        json operations = json::array({"get_driver_status", "read_memory", "prepare_memory_patch", "apply_memory_patch", "get_base_address"});
        for (const auto& [operation, name] : std::initializer_list<std::pair<driver_operation, const char*>>{
            {driver_operation::connect, "connect_driver"}, {driver_operation::attach, "attach_process"},
            {driver_operation::detach, "detach_process"}, {driver_operation::query_process, "get_process_info"},
            {driver_operation::allocate, "allocate_memory"}, {driver_operation::protect, "protect_memory"},
            {driver_operation::unload, "unload_driver"}})
            if (backend_.supports(operation)) operations.push_back(name);
        const auto target = backend_.identity();
        return make_tool_result("driver_status", {
            {"adapter", std::string(backend_.name())}, {"driver_available", backend_.connected()},
            {"target", target ? target_json(*target) : json(nullptr)}, {"supported_operations", operations},
            {"execution_exposed", false}, {"capabilities_source", "adapter_declarations_not_runtime_probe"},
            {"pending_patches", patches_.size()}
        });
    }

    json memory_service::connect_driver(const json& args) {
        fields(args, {});
        std::lock_guard lock(mutex_);
        require_operation(driver_operation::connect);
        return control("connect_driver", json::object(), [&] {
            if (!backend_.connect()) throw std::runtime_error("driver_connect_failed");
            return json{{"status", "driver_connected"}, {"ok", true}};
        });
    }

    json memory_service::attach_process(const json& args) {
        fields(args, {"pid"});
        const auto pid = unsigned_integer(args.at("pid"));
        if (pid == 0 || pid > std::numeric_limits<std::uint32_t>::max()) throw std::invalid_argument("invalid_pid");
        std::lock_guard lock(mutex_);
        require_operation(driver_operation::attach);
        return control("attach_process", {{"pid", pid}}, [&] {
            if (!backend_.attach(static_cast<std::uint32_t>(pid))) throw std::runtime_error("driver_attach_failed");
            const auto target = require_target(backend_);
            if (target.pid != pid) throw std::runtime_error("attached_pid_mismatch");
            return json{{"status", "process_attached"}, {"ok", true}, {"target", target_json(target)}};
        });
    }

    json memory_service::detach_process(const json& args) {
        fields(args, {});
        std::lock_guard lock(mutex_);
        require_operation(driver_operation::detach);
        return control("detach_process", json::object(), [&] {
            if (!backend_.detach()) throw std::runtime_error("driver_detach_failed");
            return json{{"status", "process_detached"}, {"ok", true}};
        });
    }

    json memory_service::process_info(const json& args) {
        fields(args, {});
        std::lock_guard lock(mutex_);
        require_operation(driver_operation::query_process);
        const auto target = require_target(backend_);
        process_information info;
        if (!backend_.query_process(info)) throw std::runtime_error("driver_query_failed");
        if (backend_.identity() != target) throw std::runtime_error("target_changed");
        // String encoding preserves full-width DTB and PEB values in JavaScript clients.
        return make_tool_result("process_info", {{"target", target_json(target)},
            {"peb", std::to_string(info.peb)}, {"dtb", std::to_string(info.dtb)}});
    }

    json memory_service::allocate_memory(const json& args) {
        fields(args, {"size", "protection"});
        const auto requested = unsigned_integer(args.at("size"));
        validate_range(0x10000, requested);
        const auto protection = parse_protection(args.at("protection"));
        std::lock_guard lock(mutex_);
        require_operation(driver_operation::allocate);
        const auto target = require_target(backend_);
        return control("allocate_memory", {{"target", target_json(target)}, {"requested_size", requested},
            {"protection", args.at("protection")}}, [&] {
            if (backend_.identity() != target) throw std::runtime_error("target_changed");
            std::uint64_t addr = 0, size = requested;
            if (!backend_.allocate(addr, size, protection)) throw std::runtime_error("driver_allocate_failed");
            // Preserve reported outputs even when validation detects a bad driver response.
            json out = {{"addr", addr}, {"size", size}, {"driver_reported_success", true}, {"ok", false}};
            if (backend_.identity() != target) { out["status"] = "target_changed_after_operation"; return out; }
            try { validate_range(addr, size); }
            catch (...) { out["status"] = "invalid_driver_allocation_range"; return out; }
            if (size < requested) { out["status"] = "driver_allocation_too_small"; return out; }
            out["status"] = "memory_allocated";
            out["ok"] = true;
            return out;
        });
    }

    json memory_service::protect_memory(const json& args) {
        fields(args, {"addr", "size", "protection"});
        const auto addr = unsigned_integer(args.at("addr"));
        const auto size = unsigned_integer(args.at("size"));
        validate_range(addr, size);
        const auto protection = parse_protection(args.at("protection"));
        std::lock_guard lock(mutex_);
        require_operation(driver_operation::protect);
        const auto target = require_target(backend_);
        return control("protect_memory", {{"target", target_json(target)}, {"requested_addr", addr},
            {"requested_size", size}, {"protection", args.at("protection")}}, [&] {
            if (backend_.identity() != target) throw std::runtime_error("target_changed");
            auto actual_addr = addr, actual_size = size;
            std::uint32_t previous = 0;
            if (!backend_.protect(actual_addr, actual_size, protection, previous)) throw std::runtime_error("driver_protect_failed");
            json out = {{"addr", actual_addr}, {"size", actual_size}, {"previous_native_protection", previous},
                {"driver_reported_success", true}, {"ok", false}};
            if (backend_.identity() != target) { out["status"] = "target_changed_after_operation"; return out; }
            try { validate_range(actual_addr, actual_size); }
            catch (...) { out["status"] = "invalid_driver_protection_range"; return out; }
            if (actual_addr > addr || actual_addr + actual_size < addr + size) {
                out["status"] = "driver_protection_range_mismatch";
                return out;
            }
            out["status"] = "memory_protection_changed";
            out["ok"] = true;
            return out;
        });
    }

    json memory_service::unload_driver(const json& args) {
        fields(args, {});
        std::lock_guard lock(mutex_);
        require_operation(driver_operation::unload);
        return control("unload_driver", json::object(), [&] {
            if (!backend_.unload()) throw std::runtime_error("driver_unload_failed");
            return json{{"status", "driver_unloaded"}, {"ok", true}};
        });
    }

    json memory_service::get_base(const json& args) {
        fields(args, {});
        std::lock_guard lock(mutex_);
        const auto target = require_target(backend_);
        return make_tool_result("target_ready", {{"base", target.base}, {"target", target_json(target)}});
    }

    json memory_service::read(const json& args) {
        fields(args, {"addr", "type"});
        const auto type = type_name(args);
        const auto addr = address(args, width(type));
        std::lock_guard lock(mutex_);
        const auto target = require_target(backend_);
        const auto data = read_bytes(backend_, addr, width(type));
        if (backend_.identity() != target) throw std::runtime_error("target_changed");
        const auto value = dispatch(type, [&]<class T>() { return unpack<T>(data); });
        return make_tool_result("read_success", {{"value", value}, {"bytes", hex(data)}, {"target", target_json(target)}});
    }

    json memory_service::prepare(const json& args) {
        fields(args, {"addr", "type", "value"}, {"expected"});
        const auto type = type_name(args);
        const auto addr = address(args, width(type));
        const auto after = dispatch(type, [&]<class T>() { return encode<T>(args.at("value")); });
        std::optional<bytes> expected;
        if (args.contains("expected"))
            expected = dispatch(type, [&]<class T>() { return encode<T>(args.at("expected")); });
        std::lock_guard lock(mutex_);
        const auto current_time = now_();
        std::erase_if(patches_, [&](const auto& item) { return item.second.expires <= current_time; });
        if (patches_.size() >= capacity_) throw std::runtime_error("too_many_pending_patches");
        const auto target = require_target(backend_);
        const auto before = read_bytes(backend_, addr, after.size());
        if (backend_.identity() != target) throw std::runtime_error("target_changed");
        if (expected && *expected != before) throw std::runtime_error("expected_value_mismatch");
        const auto before_value = dispatch(type, [&]<class T>() { return unpack<T>(before); });
        const auto after_value = dispatch(type, [&]<class T>() { return unpack<T>(after); });
        const auto id = next_id_();
        if (id.empty() || patches_.contains(id)) throw std::runtime_error("patch_id_generation_failed");
        // Start the TTL after the preview read completes, so slow reads cannot issue expired previews.
        patches_.emplace(id, patch{target, addr, type, before, after, now_() + ttl_});
        return make_tool_result("patch_prepared_no_write_performed", {
            {"patch_id", id}, {"expires_in_seconds", ttl_.count()}, {"target", target_json(target)},
            {"addr", addr}, {"type", type}, {"before", before_value}, {"after", after_value},
            {"before_bytes", hex(before)}, {"after_bytes", hex(after)}, {"write_attempted", false}
        });
    }

    json memory_service::apply(const json& args) {
        fields(args, {"patch_id"});
        const auto id = args.at("patch_id").get<std::string>();
        std::lock_guard lock(mutex_);
        const auto iterator = patches_.find(id);
        if (iterator == patches_.end()) throw std::runtime_error("unknown_or_consumed_patch");
        const auto plan = iterator->second;
        patches_.erase(iterator); // Every attempt consumes its ID, including failed attempts.
        json record = {
            {"patch_id", id}, {"target", target_json(plan.target)}, {"addr", plan.address},
            {"type", plan.type}, {"before_bytes", hex(plan.before)}, {"after_bytes", hex(plan.after)},
            {"write_attempted", false}, {"verified", false},
            {"timestamp_unix_ms", std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
        auto finish = [&](const char* status) {
            record["status"] = status;
            record["timestamp_unix_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            bool audit_failed = false;
            if (audit_) {
                try { audit_(record); }
                catch (...) { audit_failed = true; }
            }
            if (audit_failed) record["audit_error"] = "audit_sink_failed";
            return make_tool_result(status, record, !record.at("verified").get<bool>() || audit_failed);
        };
        if (now_() >= plan.expires) return finish("patch_expired");
        if (backend_.identity() != plan.target) return finish("target_changed");
        bytes current(plan.before.size());
        if (!backend_.read(plan.address, current.data(), current.size())) return finish("driver_read_failed");
        record["observed_bytes"] = hex(current);
        if (current != plan.before) return finish("memory_changed");
        // Recheck after the precondition read; this is not an atomic compare-and-swap.
        if (backend_.identity() != plan.target) return finish("target_changed");
        if (now_() >= plan.expires) return finish("patch_expired");
        if (audit_) {
            record["status"] = "apply_started";
            try { audit_(record); }
            catch (...) { return finish("audit_unavailable_no_write"); }
        }
        // Disk I/O in the audit sink may block long enough to expire a preview.
        if (now_() >= plan.expires) return finish("patch_expired");
        if (backend_.identity() != plan.target) return finish("target_changed");
        record["write_attempted"] = true;
        if (!backend_.write(plan.address, plan.after.data(), plan.after.size()))
            return finish("driver_write_failed"); // A failing driver may still have partially written.
        if (backend_.identity() != plan.target) return finish("target_changed_after_write");
        bytes observed(plan.after.size());
        if (!backend_.read(plan.address, observed.data(), observed.size())) return finish("verification_read_failed");
        record["observed_bytes"] = hex(observed);
        if (backend_.identity() != plan.target) return finish("target_changed_after_write");
        if (observed != plan.after) return finish("verification_failed");
        record["verified"] = true;
        return finish("verified");
    }
}
