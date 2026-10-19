#include "windows_service.hpp"
#include "pe_fixture.hpp"
#include <iostream>
#include <stdexcept>
using namespace mcp_runtime;
namespace {
int assertions=0;
void check(bool yes,const char* name){++assertions;if(!yes)throw std::runtime_error(name);}
json request(const pe_fixture::bytes& b,const char* kind="application"){return {{"image_hex",pe_fixture::hex(b)},{"kind",kind},{"timeout_ms",10000}};}
json run(windows_service& service,const json& args,const char* expected="completed") {
    auto result=service.image(args);const auto out=result.at("structuredContent");
    if(out.value("status",std::string())!=expected)std::cerr<<out.dump()<<'\n';
    check(out.at("status")==expected,expected);check(result.at("isError")== (std::string(expected)!="completed"),"status error flag");return out;
}
void loading(windows_service& s) {
    auto b=pe_fixture::image({0xb8,42,0,0,0,0xc3});auto out=run(s,request(b));
    check(out.at("entry_return_value")=="0x2a","actual PE machine instructions execute");
    check(out.at("instructions_observed")==2,"instruction trace includes PE code");
    out=run(s,request(pe_fixture::image({0x0f,0xb7,0x01,0xc3}),"driver"));
    check(out.at("entry_return_value")=="0x4","DriverEntry gets initialized driver object");
    std::copy_n(std::initializer_list<std::uint8_t>{0xb8,99,0,0,0,0xc3}.begin(),6,b.begin()+0x220);
    auto args=request(b);args["entry_rva"]=0x1020;out=run(s,args);
    check(out.at("entry_return_value")=="0x63","selected image routine entry executes");
    b.resize(100000);out=run(s,request(b));check(out.at("entry_return_value")=="0x2a","PE requests larger than legacy 128 KiB cap work");
}
void imports(windows_service& s) {
    auto b=pe_fixture::image({0xff,0x15,0x9a,0x11,0,0,0x48,0x89,0x05,0xf3,0x0f,0,0,0xc3});
    pe_fixture::imported(b,"NTOSKRNL.EXE","PsGetCurrentProcessId");auto args=request(b,"driver");args["watch"]=json::array({{{"rva",8192},{"size",8}}});
    auto out=run(s,args);check(out.at("api_trace")[0].at("name")=="PsGetCurrentProcessId","PE IAT reaches original handler");
    check(out.at("watch")[0].at("after_hex")!="0000000000000000","guest code receives handler return and writes data");
    check(out.at("imports")[0].at("iat_rva")==0x21a0,"PE import resolution reported");
    b=pe_fixture::image({0x48,0x8d,0x0d,0xf9,0x0f,0,0,0xff,0x15,0x93,0x11,0,0,0xc3});
    pe_fixture::imported(b,"ntdll.dll","NtQuerySystemTime");args=request(b);args["watch"]=json::array({{{"rva",8192},{"size",8}}});out=run(s,args);
    check(out.at("watch")[0].at("after_hex")!="0000000000000000","ntdll import bridges to kernel model");
    pe_fixture::imported(b,"ntoskrnl.exe","UnknownRoutine");out=run(s,request(b),"unresolved_import");
    check(out.at("name")=="UnknownRoutine","missing import named before execution");
}
void syscalls(windows_service& s) {
    auto args=request(pe_fixture::syscall());args["syscalls"]=json::array({{{"id",119},{"name","NtQuerySystemTime"}}});
    args["watch"]=json::array({{{"rva",8192},{"size",8}}});auto out=run(s,args);
    const auto& call=out.at("api_trace")[0];check(call.at("kind")=="syscall"&&call.at("syscall_id")==119,"real syscall instruction dispatched by EAX");
    check(call.at("arguments")[0]=="0x140002000","syscall first argument comes from R10");
    check(out.at("watch")[0].at("after_hex")!="0000000000000000","syscall writes guest output");
    check(out.at("registers").at("rcx")=="0x140001011","syscall RCX architectural clobber");
    args.erase("syscalls");args["syscall_stubs_hex"]=pe_fixture::hex(pe_fixture::stubs());out=run(s,args);
    check(out.at("syscall_mapping")[0].at("source")=="supplied_stub_image","numeric mapping decoded from supplied PE exports");
    args["image_hex"]=pe_fixture::hex(pe_fixture::syscall(120));out=run(s,args,"unsupported_syscall");
    check(out.at("api_trace")[0].at("syscall_id")==120,"unknown syscall number explicit");
    auto b=pe_fixture::image({0x4c,0x8b,0xd1,0xb8,0x77,0,0,0,0x0f,0x05,0xc3});pe_fixture::put<std::uint64_t>(b,0x408,4096);
    args=request(b);args["arguments"]=json::array({"0xffffffffffffffff",{{"image_rva",8192}},0,{{"image_rva",8200}},12288,4});
    args["syscalls"]=json::array({{{"id",119},{"name","NtAllocateVirtualMemory"}}});args["watch"]=json::array({{{"rva",8192},{"size",8}}});out=run(s,args);
    check(out.at("entry_return_value")=="0x0"&&out.at("watch")[0].at("after_hex")!="0000000000000000","six-argument syscall reads Windows shadow-space stack arguments");
}
void relocation_and_limits(windows_service& s) {
    auto b=pe_fixture::image({0x48,0xa1,0x08,0x20,0x00,0x40,0x01,0,0,0,0xc3});pe_fixture::put<std::uint64_t>(b,0x408,0x1122334455667788ULL);
    pe_fixture::put<std::uint32_t>(b,0x130,0x2200);pe_fixture::put<std::uint32_t>(b,0x134,12);
    pe_fixture::put<std::uint32_t>(b,0x600,0x1000);pe_fixture::put<std::uint32_t>(b,0x604,12);pe_fixture::put<std::uint16_t>(b,0x608,0xa002);
    auto args=request(b);args["base_address"]="0x150000000";auto out=run(s,args);
    check(out.at("entry_return_value")=="0x1122334455667788","DIR64 relocation changes actual absolute operand");
    args=request(pe_fixture::image({0xeb,0xfe}));args["instruction_limit"]=20;out=run(s,args,"instruction_limit");
    check(out.at("instructions_observed")==20,"instruction count bounded across PE execution");
    args["instruction_limit"]=100000;args["execution_timeout_ms"]=1;run(s,args,"timeout");
    run(s,request(pe_fixture::image({0xf4})),"halted");
    run(s,request(pe_fixture::image({0xec,0xc3})),"external_instruction");
    run(s,request(pe_fixture::image({0x48,0xa1,0,0,0,0,0,0,0,0,0xc3})),"memory_fault");
    args=request(pe_fixture::image({0x48,0xb8,1,0,0,0,0,0,0,0,0x48,0xa3,0x00,0x10,0x00,0x40,0x01,0,0,0,0xc3}));
    args["watch"]=json::array({{{"rva",4096},{"size",1}}});out=run(s,args,"memory_fault");
    check(out.at("watch")[0].at("after_hex")=="48","PE text section write protection enforced");
}
void invalid_images(windows_service& s) {
    auto b=pe_fixture::image({0xc3});pe_fixture::put<std::uint32_t>(b,60,0xfffffff0);auto out=run(s,request(b),"worker_error");
    check(out.at("error")=="pe_truncated_structure","malformed header bounds checked");
    b=pe_fixture::image({0xc3});pe_fixture::put<std::uint32_t>(b,0x19c,0xfffffff0);run(s,request(b),"worker_error");
    b=pe_fixture::image({0xc3});pe_fixture::put<std::uint32_t>(b,0x150,0x2100);pe_fixture::put<std::uint32_t>(b,0x154,8);out=run(s,request(b),"worker_error");
    check(out.at("error")=="pe_tls_delay_imports_or_clr_unsupported","TLS unsupported explicitly");
    auto args=request(pe_fixture::syscall());args["syscalls"]=json::array({{{"id",119},{"name","NtQuerySystemTime"}},{{"id",119},{"name","NtClose"}}});
    out=run(s,args,"worker_error");check(out.at("error")=="conflicting_syscall_mapping","conflicting build-specific syscall maps rejected");
}
}
int main(){try{windows_service service;loading(service);imports(service);syscalls(service);relocation_and_limits(service);invalid_images(service);std::cout<<assertions<<" PE and syscall assertions passed\n";return 0;}catch(const std::exception& e){std::cerr<<"FAIL after "<<assertions<<": "<<e.what()<<'\n';return 1;}}
