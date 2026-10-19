#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
class vcpu;
struct execution_instruction {std::uint64_t address;std::uint32_t size;std::array<std::uint8_t,15> bytes{};};
struct execution_event {std::string status;std::uint64_t pc=0,fault_address=0;unsigned interrupt=0,instruction_size=0;};
// This bridge is the only new translation unit that sees Unicorn/Windows SDK
// headers. The worker's guest Windows structures must not see the host SDK types.
class execution_engine {
public:
    execution_engine(vcpu&,std::vector<std::uint64_t> imports,unsigned instruction_limit,unsigned trace_limit,unsigned timeout_ms);
    ~execution_engine();
    execution_event resume(std::uint64_t until);
    void invalidate_code();
    const std::vector<execution_instruction>& trace() const;
    std::size_t observed() const;
private:
    struct implementation;std::unique_ptr<implementation> impl_;
};
