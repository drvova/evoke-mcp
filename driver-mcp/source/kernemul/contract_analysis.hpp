#pragma once
#include "pe_image.hpp"
#include <nlohmann/json.hpp>
namespace evoke_contract {
struct dispatch_root {
    unsigned major;
    std::uint32_t rva;
    std::string evidence;
};
nlohmann::json analyze(const evoke_pe::image& image, std::span<const std::uint8_t> raw,
    const std::vector<dispatch_root>& observed, unsigned instruction_limit = 8192);
}
