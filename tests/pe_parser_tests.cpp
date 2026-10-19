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
        std::vector<pe_fixture::bytes> seeds={base,pe_fixture::stubs()};
        auto imported=base;pe_fixture::imported(imported,"ntoskrnl.exe","NtClose");seeds.push_back(imported);
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
                for(const auto& i:parsed.imports())if(std::uint64_t(i.slot)+8>parsed.bytes.size())throw std::logic_error("import bounds invariant");
                for(const auto& e:parsed.exports())if(e.rva>=parsed.bytes.size())throw std::logic_error("export bounds invariant");
                parsed.relocate(parsed.preferred_base);
            }catch(const std::logic_error& error) {
                if(dynamic_cast<const std::invalid_argument*>(&error)==nullptr)throw;
            }catch(const std::runtime_error&){}
        }
        std::cout<<"512 truncated images and 4000 deterministic PE mutations checked\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
