#include "contract_analysis.hpp"
#include "contract_fixture.hpp"
#include <iostream>
namespace {
unsigned checks=0;
void check(bool value,const char* text){++checks;if(!value)throw std::runtime_error(text);}
auto analyze(const pe_fixture::bytes& raw,unsigned limit=8192) {
    return evoke_contract::analyze(evoke_pe::image(raw,false),raw,{},limit);
}
}
int main(){try {
    auto raw=contract_fixture::driver();auto out=analyze(raw);
    check(out.at("dispatch_routines").size()==1,"static registration discovered from driver object dataflow");
    check(out.at("ioctl_candidates").size()==1,"reachable dispatch comparison discovered without executing entry");
    check(out.at("ioctl_candidates")[0].at("code")==0x222004,"correct control code");
    check(out.at("buffer_accesses")[0].at("offset")==8,"buffer pointer provenance tracked");
    check(out.at("buffer_accesses")[1].at("write")==true,"buffer write identified");
    raw[0x24b]=0xb0;raw[0x24c]=0xff; // replace CMP with a partial AL write, then CMP eax,IOCTL
    const pe_fixture::bytes after={0xb0,0xff,0x3d,4,0x20,0x22,0,0xc3};std::copy(after.begin(),after.end(),raw.begin()+0x24b);
    check(analyze(raw).at("ioctl_candidates").empty(),"partial register writes invalidate provenance");
    raw=contract_fixture::driver();const pe_fixture::bytes sub={0x2d,4,0x20,0x22,0,0x74,0,0xc3};std::copy(sub.begin(),sub.end(),raw.begin()+0x24b);
    check(analyze(raw).at("ioctl_candidates")[0].at("code")==0x222004,"subtraction followed by equality branch reconstructs IOCTL");
    raw[0x250]=0x90;check(analyze(raw).at("ioctl_candidates").empty(),"arithmetic alone does not claim an equality candidate");
    raw=contract_fixture::driver();raw[0x240]=0xc3;
    check(analyze(raw).at("ioctl_candidates").empty(),"unreachable immediate bytes are not scanned as instructions");
    raw=contract_fixture::driver();raw[0x200]=0xc3;
    check(analyze(raw).at("dispatch_routines").empty(),"unreachable registration is ignored");
    raw=contract_fixture::driver(true);check(analyze(raw).at("dispatch_routines").empty(),"unresolved indexed store is not invented statically");
    const evoke_pe::image image(raw,false);
    out=evoke_contract::analyze(image,raw,{{14,0x1040,"guest_driver_object"}});
    check(out.at("ioctl_candidates").size()==1,"observed registration supplies static analysis root");
    check(analyze(raw,1).at("analysis_truncated")==true,"bounded analysis reports truncation");
    for(const auto& binary:{contract_fixture::x86_driver(),contract_fixture::arm64_driver()}) {
        const evoke_pe::image parsed(binary,false);out=analyze(binary);
        check(out.at("architecture")==evoke_pe::architecture_name(parsed.arch),"target architecture detected from PE machine");
        check(out.at("dispatch_routines")[0].at("rva")==0x1040,"architecture-specific dispatch registration recovered");
        check(out.at("ioctl_candidates").size()==1&&out.at("ioctl_candidates")[0].at("code")==0x222004,"architecture-specific IRP and IO_STACK_LOCATION dataflow");
        check(out.at("length_comparisons")[0].at("compared_value")==16,"architecture-specific length comparisons recovered");
        check(out.at("buffer_accesses").size()==2&&out.at("buffer_accesses")[1].at("write")==true,"architecture-specific buffer accesses recovered");
    }
    raw=contract_fixture::arm64_driver();
    pe_fixture::put<std::uint32_t>(raw,0x200,0x90000008); // ADRP x8, current page
    pe_fixture::put<std::uint32_t>(raw,0x204,0x91010108); // ADD x8,x8,#0x40
    pe_fixture::put<std::uint32_t>(raw,0x208,0xf9007008); // STR x8,[x0,#0xe0]
    check(analyze(raw).at("dispatch_routines")[0].at("rva")==0x1040,"ARM64 ADRP plus ADD registration");
    raw=contract_fixture::arm64_driver();
    pe_fixture::put<std::uint32_t>(raw,0x248,0x1800000b|(((0x2000-0x1048)/4)<<5)); // LDR w11,literal
    pe_fixture::put<std::uint32_t>(raw,0x24c,0xd503201f);pe_fixture::put<std::uint32_t>(raw,0x400,0x222004);
    check(analyze(raw).at("ioctl_candidates")[0].at("code")==0x222004,"ARM64 literal-loaded comparison constant");
    raw=contract_fixture::x86_driver();raw[0x248]=0xb8;
    check(analyze(raw).at("ioctl_candidates").empty(),"x86 never applies x64 IRP offsets");
    raw=contract_fixture::x86_driver();pe_fixture::put<std::uint32_t>(raw,0xb4,0xf0000000);pe_fixture::put<std::uint32_t>(raw,0x209,0xf0001040);
    check(analyze(raw).at("dispatch_routines")[0].at("rva")==0x1040,"x86 high image bases retain 32-bit address semantics");
    std::uint32_t state=0x73614291;auto random=[&](){state^=state<<13;state^=state>>17;state^=state<<5;return state;};
    for(unsigned iteration=0;iteration<1000;++iteration) {
        raw=iteration%3==0?contract_fixture::driver():iteration%3==1?contract_fixture::x86_driver():contract_fixture::arm64_driver();
        for(unsigned n=0;n<1+iteration%16;++n)raw[0x200+random()%512]=static_cast<std::uint8_t>(random());
        out=analyze(raw,256);
        if(out.at("analysis_instructions").get<unsigned>()>256||out.at("ioctl_candidates").size()>128||out.at("buffer_accesses").size()>128)
            throw std::logic_error("analysis bounds escaped");
    }
    std::cout<<checks<<" static contract assertions and 1000 instruction mutations passed\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL after "<<checks<<": "<<e.what()<<'\n';return 1;}}
