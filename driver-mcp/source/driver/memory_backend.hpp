#pragma once

#include "driver.hpp"
#include "../mcp/memory_backend.hpp"

namespace driver {
    // Only this adapter knows the Evoke ABI. Retaining a process handle distinguishes
    // a specific process lifetime from another process that later reuses its PID.
    class windows_memory_backend final : public mcp_runtime::memory_backend {
    public:
        explicit windows_memory_backend(c_driver& driver) : driver_(driver), pid_(driver.m_pid) {
            static_assert(sizeof(void*) == 8, "evoke-mcp requires a Windows x64 build");
            if (pid_) process_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid_);
        }
        ~windows_memory_backend() override { if (process_) CloseHandle(process_); }
        windows_memory_backend(const windows_memory_backend&) = delete;
        windows_memory_backend& operator=(const windows_memory_backend&) = delete;
        std::string_view name() const override { return "evoke"; }
        bool supports(mcp_runtime::driver_operation operation) const override {
            using mcp_runtime::driver_operation;
            switch (operation) {
                case driver_operation::connect:
                case driver_operation::attach:
                case driver_operation::detach:
                case driver_operation::query_process:
                case driver_operation::allocate:
                case driver_operation::protect:
                case driver_operation::unload: return true;
            }
            return false;
        }
        bool connected() override {
            return driver_.m_kernel_available && driver_.m_handle != INVALID_HANDLE_VALUE;
        }
        bool connect() override {
            if (connected()) return true;
            clear_target();
            if (driver_.m_handle != INVALID_HANDLE_VALUE) CloseHandle(driver_.m_handle);
            driver_.m_handle = INVALID_HANDLE_VALUE;
            driver_.init();
            return connected();
        }
        bool attach(std::uint32_t pid) override {
            if (!connected()) return false;
            HANDLE candidate = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
            if (!candidate) return false;
            if (WaitForSingleObject(candidate, 0) != WAIT_TIMEOUT) {
                CloseHandle(candidate);
                return false;
            }
            clear_target();
            if (!driver_.attach_kernel(pid)) {
                CloseHandle(candidate);
                clear_target();
                return false;
            }
            process_ = candidate;
            pid_ = pid;
            if (!identity()) {
                clear_target();
                return false;
            }
            return true;
        }
        bool detach() override {
            if (!connected()) return false;
            const bool ok = driver_.detach_kernel();
            // On failure, retain the driver's PID for a detach retry but drop the
            // process handle so memory access stays disabled until another attach.
            clear_target(ok);
            return ok;
        }
        bool query_process(mcp_runtime::process_information& out) override {
            if (!identity()) return false;
            u64 peb = 0, dtb = 0;
            if (!driver_.get_peb(peb) || !driver_.get_dtb(dtb)) return false;
            out = {peb, dtb};
            return true;
        }
        bool allocate(std::uint64_t& addr, std::uint64_t& size, mcp_runtime::page_protection protection) override {
            if (!identity()) return false;
            u64 result_addr = addr, result_size = size;
            const bool ok = driver_.allocate_virtual(result_addr, result_size, MEM_COMMIT | MEM_RESERVE, native_protection(protection));
            addr = result_addr;
            size = result_size;
            return ok;
        }
        bool protect(std::uint64_t& addr, std::uint64_t& size, mcp_runtime::page_protection protection, std::uint32_t& old) override {
            if (!identity()) return false;
            u64 result_addr = addr, result_size = size;
            u32 previous = 0;
            const bool ok = driver_.protect_virtual(result_addr, result_size, native_protection(protection), previous);
            addr = result_addr;
            size = result_size;
            old = previous;
            return ok;
        }
        bool unload() override {
            if (!connected()) return false;
            const bool ok = driver_.unload();
            clear_target(ok);
            if (ok) {
                CloseHandle(driver_.m_handle);
                driver_.m_handle = INVALID_HANDLE_VALUE;
                driver_.m_kernel_available = false;
                driver_.m_nt_device_io_control_file = nullptr;
            }
            return ok;
        }
        std::optional<mcp_runtime::target_identity> identity() override {
            if (!process_ || !connected() || driver_.m_pid != pid_ ||
                !driver_.m_base_addr || WaitForSingleObject(process_, 0) != WAIT_TIMEOUT)
                return std::nullopt;
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!GetProcessTimes(process_, &created, &exited, &kernel, &user)) return std::nullopt;
            const auto creation = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
            return mcp_runtime::target_identity{pid_, creation, driver_.m_base_addr};
        }
        bool read(std::uint64_t addr, void* out, std::size_t size) override {
            return identity().has_value() && driver_.read(addr, out, size);
        }
        bool write(std::uint64_t addr, const void* data, std::size_t size) override {
            return identity().has_value() && driver_.write(addr, data, size);
        }
    private:
        static u32 native_protection(mcp_runtime::page_protection protection) {
            using mcp_runtime::page_protection;
            switch (protection) {
                case page_protection::no_access: return PAGE_NOACCESS;
                case page_protection::read_only: return PAGE_READONLY;
                case page_protection::read_write: return PAGE_READWRITE;
                case page_protection::execute: return PAGE_EXECUTE;
                case page_protection::execute_read: return PAGE_EXECUTE_READ;
                case page_protection::execute_read_write: return PAGE_EXECUTE_READWRITE;
            }
            return 0;
        }
        void clear_target(bool clear_driver = true) {
            if (process_) CloseHandle(process_);
            process_ = nullptr;
            pid_ = 0;
            if (clear_driver) {
                driver_.m_pid = 0;
                driver_.m_base_addr = 0;
                driver_.m_dtb = 0;
                driver_.m_peb = 0;
            }
        }
        c_driver& driver_;
        std::uint32_t pid_ = 0;
        HANDLE process_ = nullptr;
    };
}
