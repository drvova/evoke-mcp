#include "pe_image.hpp"
#include "pe_fixture.hpp"
#include <iostream>
#include <random>
#include <stdexcept>
int main() {
    try {
        std::mt19937 random(0x45564f4b);auto base=pe_fixture::image({0xc3});
        for(std::size_t length=0;length<512;++length) {
            bool rejected=false;try{evoke_pe::image p(std::span<const std::uint8_t>(base.data(),length));}catch(const std::exception&){rejected=true;}
            if(!rejected)throw std::runtime_error("truncated PE accepted");
        }
        auto x86=pe_fixture::pe32(pe_fixture::stubs());auto arm64=pe_fixture::stubs();pe_fixture::put<std::uint16_t>(arm64,0x84,0xaa64);
        for(const auto& [raw,architecture]:{std::pair{x86,evoke_pe::architecture::x86},std::pair{arm64,evoke_pe::architecture::arm64}}) {
            const evoke_pe::image parsed(raw,false);
            if(parsed.arch!=architecture||parsed.exports().size()!=1||parsed.preferred_base!=(architecture==evoke_pe::architecture::x86?0x400000ULL:0x140000000ULL))
                throw std::logic_error("architecture header/export parsing failed");
            bool rejected=false;try{evoke_pe::image executable(raw);}catch(const std::invalid_argument&){rejected=true;}
            if(!rejected)throw std::logic_error("unsupported guest ABI accepted for execution");
            for(std::size_t length=0;length<512;++length) {
                rejected=false;try{evoke_pe::image truncated(std::span<const std::uint8_t>(raw.data(),length),false);}catch(const std::invalid_argument&){rejected=true;}
                if(!rejected)throw std::logic_error("truncated architecture header accepted");
            }
        }
        auto mismatch=x86;pe_fixture::put<std::uint16_t>(mismatch,0x84,0xaa64);bool mismatched=false;
        try{evoke_pe::image invalid(mismatch,false);}catch(const std::invalid_argument&){mismatched=true;}
        if(!mismatched)throw std::logic_error("PE machine and optional header mismatch accepted");
        std::vector<pe_fixture::bytes> seeds={base,pe_fixture::stubs(),x86,arm64};
        auto imported=base;pe_fixture::imported(imported,"ntoskrnl.exe","NtClose");seeds.push_back(imported);
        auto imported32=pe_fixture::pe32(imported);seeds.push_back(imported32);
        if(evoke_pe::image(imported32,false).imports()[0].slot!=0x21a0)throw std::logic_error("PE32 import thunk width failed");
        auto ordinal32=imported32;pe_fixture::put<std::uint32_t>(ordinal32,0x580,0x80000001);bool ordinal=false;
        try{evoke_pe::image(ordinal32,false).imports();}catch(const std::invalid_argument&){ordinal=true;}
        if(!ordinal)throw std::logic_error("PE32 ordinal import misparsed as RVA");
        auto large=seeds[1];large.resize(3*1024*1024);
        if(evoke_pe::image(large,false).exports().size()!=1)throw std::logic_error("large stub image rejected");
        large.resize(4*1024*1024+1);bool too_large=false;
        try{evoke_pe::image p(large,false);}catch(const std::invalid_argument&){too_large=true;}
        if(!too_large)throw std::logic_error("stub image size cap not enforced");
        for(unsigned iteration=0;iteration<4000;++iteration) {
            auto mutated=seeds[iteration%seeds.size()];
            for(unsigned n=0;n<1+iteration%8;++n)mutated[random()%mutated.size()]=static_cast<std::uint8_t>(random());
            try {
                evoke_pe::image parsed(mutated,false);
                if(parsed.bytes.size()>16*1024*1024)throw std::logic_error("image size invariant");
                for(const auto& i:parsed.imports())if(std::uint64_t(i.slot)+parsed.pointer_size>parsed.bytes.size())throw std::logic_error("import bounds invariant");
                for(const auto& e:parsed.exports())if(e.rva>=parsed.bytes.size())throw std::logic_error("export bounds invariant");
                parsed.relocate(parsed.preferred_base);
            }catch(const std::logic_error& error) {
                if(dynamic_cast<const std::invalid_argument*>(&error)==nullptr)throw;
            }catch(const std::runtime_error&){}
        }
        std::cout<<"1536 truncated images across x86/AMD64/ARM64 and 4000 deterministic PE mutations checked\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
