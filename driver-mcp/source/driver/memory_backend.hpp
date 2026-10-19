#pragma once

#include "driver.hpp"
#include "../mcp/memory_backend.hpp"

namespace driver {
    // The retained handle identifies a specific process lifetime, including after PID reuse.
    class windows_memory_backend final : public mcp_runtime::memory_backend {
    public:
        explicit windows_memory_backend(c_driver& driver) : driver_(driver), pid_(driver.m_pid) {
            static_assert(sizeof(void*) == 8, "evoke-mcp requires a Windows x64 build");
            if (pid_) process_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid_);
        }
        ~windows_memory_backend() override { if (process_) CloseHandle(process_); }
        windows_memory_backend(const windows_memory_backend&) = delete;
        windows_memory_backend& operator=(const windows_memory_backend&) = delete;

        std::optional<mcp_runtime::target_identity> identity() override {
            if (!process_ || !driver_.m_kernel_available || driver_.m_pid != pid_ ||
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
        c_driver& driver_;
        std::uint32_t pid_;
        HANDLE process_ = nullptr;
    };
}
