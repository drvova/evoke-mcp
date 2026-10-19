#include "windows_service.hpp"
#include "system_drivers.hpp"
#include "contract_fixture.hpp"
#include <fstream>
#include <iostream>
using namespace mcp_runtime;
namespace {
unsigned checks=0;
void check(bool value,const char* text){++checks;if(!value)throw std::runtime_error(text);}
json discover(windows_service& service,const pe_fixture::bytes& image,json options=json::object()) {
    options["image_hex"]=pe_fixture::hex(image);options["timeout_ms"]=10000;
    const auto result=service.discover_contract(options);const auto out=result.at("structuredContent");
    if(result.at("isError")!=false)throw std::runtime_error(out.dump());return out;
}
}
int main(){try {
    windows_service service;auto b=contract_fixture::driver();auto out=discover(service,b);
    const auto info=service.info(json::object()).at("structuredContent");
    check(info.at("contract_target_architectures")==json::array({"x86","amd64","arm64"}),"agents can discover all contract target architectures");
    check(info.at("windows_guest_execution_architectures")==json::array({"amd64"}),"agents can distinguish guest execution support");
    check(out.at("initialization_succeeded")==true,"actual driver initialization succeeds");
    check(out.at("source_sha256").get<std::string>().size()==64,"contract bound to exact binary");
    check(out.at("observations").at("dispatch_routines")[0].at("rva")==0x1040,"actual DRIVER_OBJECT dispatch registration captured");
    check(out.at("ioctl_candidates").size()==1,"only IO_STACK_LOCATION-derived IOCTL comparison included");
    const auto& code=out.at("ioctl_candidates")[0];
    check(code.at("code")==0x222004&&code.at("method")=="buffered"&&code.at("function")==0x801,"CTL_CODE fields decoded");
    check(code.at("accepted")==false&&code.at("evidence")=="io_stack_location_dataflow","candidate provenance preserved");
    check(out.at("length_comparisons")[0].at("compared_value")==16,"buffer length comparison discovered");
    check(out.at("buffer_accesses").size()==2,"read and write buffer offsets discovered");
    check(out.at("device_path_hints").size()==2,"ASCII and UTF16 namespace hints extracted");
    check(out.at("live_adapter_ready")==false&&out.at("buffer_layout_complete")==false,"inferred evidence never claims a complete live ABI");
    check(out.at("live_system_modified")==false,"discovery has guest-only effects");
    for(const auto& binary:{contract_fixture::x86_driver(),contract_fixture::arm64_driver()}) {
        out=discover(service,binary);
        check(out.at("ioctl_candidates")[0].at("code")==0x222004,"x86 and ARM64 contract discovery reachable through worker");
        check(out.at("analysis_available")==true&&out.at("guest_execution_available")==false,"analysis capability distinct from Windows ABI execution");
        check(out.at("initialization").at("status")=="unsupported_execution_architecture"&&out.at("initialization_succeeded")==false,"other architectures never run through the AMD64 guest");
        const auto execution=service.image({{"image_hex",pe_fixture::hex(binary)},{"timeout_ms",10000}});
        check(execution.at("isError")==true&&execution.at("structuredContent").at("error").get<std::string>().starts_with("pe_execution_architecture_unsupported:"),"PE execution rejects ABI mismatch explicitly");
    }
    out=discover(service,contract_fixture::driver(true));
    check(out.at("ioctl_candidates")[0].at("code")==0x222004,"emulated registration enables discovery beyond static registration patterns");
    auto failed=b;failed[0x20e]=0xb8;pe_fixture::put<std::uint32_t>(failed,0x20f,0xc0000001);failed[0x213]=0xc3;
    out=discover(service,failed);check(out.at("initialization_succeeded")==false,"failing NTSTATUS is not reported as initialization success");
    check(!out.at("observations").at("dispatch_routines").empty(),"registration evidence survives failing entry return");
    pe_fixture::imported(b,"missing.sys","UnknownApi");out=discover(service,b);
    check(out.at("initialization").at("status")=="unresolved_import","unsupported initialization is explicit");
    check(out.at("ioctl_candidates")[0].at("code")==0x222004,"static fallback works when imports block execution");
    check(out.at("imports")[0].at("modeled")==false,"unmodeled import reported");
    out=discover(service,contract_fixture::symbolic_link());
    check(out.at("initialization_succeeded")==true,"driver calls original namespace API");
    check(out.at("observations").at("namespace_events")[0].at("names")[0]=="\\DosDevices\\ContractFixture","observed namespace call distinguished from hint");
    out=discover(service,contract_fixture::driver(),{{"analysis_instruction_limit",1}});
    check(out.at("analysis_truncated")==true&&out.at("analysis_instructions")==1,"analysis budget enforced independently of guest execution");
    auto changed=contract_fixture::driver();changed.back()^=1;
    check(discover(service,changed).at("source_sha256")!=discover(service,contract_fixture::driver()).at("source_sha256"),"hash includes unexecuted file bytes");
    auto bad=service.discover_contract({{"image_hex","00"},{"timeout_ms",10000}});
    check(bad.at("isError")==true,"malformed binary rejected");
    bool ambiguous=false;try{service.discover_contract({{"image_path","driver.sys"},{"service_name","driver"}});}catch(const std::invalid_argument&){ambiguous=true;}
    check(ambiguous,"ambiguous service/file sources rejected");
    bool invalid_limit=false;try{list_system_drivers({{"limit",0}});}catch(const std::invalid_argument&){invalid_limit=true;}
    check(invalid_limit,"native catalog bounds checked on every host");
    const auto catalog=list_system_drivers({{"limit",10}});
#ifdef _WIN32
    check(catalog.at("isError")==false,"native SCM enumeration works on Windows");
    const auto& drivers=catalog.at("structuredContent").at("drivers");
    check(!drivers.empty(),"Windows driver services enumerated");
    bool resolved=false;for(const auto& driver:drivers)if(driver.contains("image_path")) {
        const auto found=resolve_system_driver(driver.at("service_name").get<std::string>());
        check(found.at("image_path")==driver.at("image_path"),"native service resolves consistent configured image");resolved=true;break;
    }
    check(resolved,"at least one real driver image path resolved");
#else
    check(catalog.at("isError")==true,"native driver service enumeration explicitly unavailable on Linux");
    check(service.discover_contract({{"service_name","fixture"}}).at("structuredContent").at("status")=="driver_service_resolution_failed","native service resolution fails explicitly on non-Windows");
#endif
    std::cout<<checks<<" contract discovery assertions passed\n";return 0;
}catch(const std::exception& error){std::cerr<<"FAIL after "<<checks<<": "<<error.what()<<'\n';return 1;}}
