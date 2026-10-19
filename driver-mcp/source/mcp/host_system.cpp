#include "host_system.hpp"
#include <cstring>
#include <stdexcept>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace mcp_runtime {
    namespace {
        template<class T, std::size_t Size> T load(const std::array<std::uint8_t, Size>& bytes, std::size_t offset) {
            T value{};
            std::memcpy(&value, bytes.data() + offset, sizeof(value));
            return value;
        }
        class native_provider final : public host_system_provider {
        public:
            bool available() const override {
#ifdef _WIN32
                return true;
#else
                return false;
#endif
            }
            std::string_view name() const override { return available() ? "win32" : "unavailable_on_this_host"; }
            host_snapshot capture() override {
#ifdef _WIN32
                static_assert(sizeof(SYSTEM_INFO) == 48 && sizeof(MEMORYSTATUSEX) == 64,
                              "Host bridge requires Windows x64 structure layouts");
                FILETIME time{};
                GetSystemTimePreciseAsFileTime(&time);
                LARGE_INTEGER counter{}, frequency{};
                if (!QueryPerformanceCounter(&counter) || !QueryPerformanceFrequency(&frequency))
                    throw std::runtime_error("win32_performance_query_failed");
                SYSTEM_INFO info{};
                GetNativeSystemInfo(&info);
                MEMORYSTATUSEX memory{};
                memory.dwLength = sizeof(memory);
                if (!GlobalMemoryStatusEx(&memory)) throw std::runtime_error("win32_memory_query_failed");
                host_snapshot out;
                out.filetime_100ns = (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
                out.performance_counter = static_cast<std::uint64_t>(counter.QuadPart);
                out.performance_frequency = static_cast<std::uint64_t>(frequency.QuadPart);
                out.tick_count_ms = GetTickCount64();
                std::memcpy(out.system_info.data(), &info, sizeof(info));
                std::memcpy(out.memory_status.data(), &memory, sizeof(memory));
                return out;
#else
                throw std::runtime_error("host_windows_apis_unavailable");
#endif
            }
        };
    }
    host_system_provider& native_host_system() {
        static native_provider provider;
        return provider;
    }
    json host_snapshot::describe() const {
        return {{"filetime_100ns", std::to_string(filetime_100ns)},
            {"performance_counter", std::to_string(performance_counter)},
            {"performance_frequency", std::to_string(performance_frequency)},
            {"tick_count_ms", std::to_string(tick_count_ms)},
            {"system", {{"processor_architecture", load<std::uint16_t>(system_info, 0)},
                {"page_size", load<std::uint32_t>(system_info, 4)},
                {"processor_count", load<std::uint32_t>(system_info, 32)},
                {"allocation_granularity", load<std::uint32_t>(system_info, 40)}}},
            {"memory", {{"load_percent", load<std::uint32_t>(memory_status, 4)},
                {"total_physical_bytes", std::to_string(load<std::uint64_t>(memory_status, 8))},
                {"available_physical_bytes", std::to_string(load<std::uint64_t>(memory_status, 16))}}}};
    }
}
