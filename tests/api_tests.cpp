#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "emulation_service.hpp"
#include "api_models.hpp"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace mcp_runtime;
namespace {
    int assertions=0;
    void check(bool value,const char* message) {++assertions;if(!value)throw std::runtime_error(message);}
    template<class F> void rejects(F function,const char* message) {bool rejected=false;try{function();}catch(const std::exception&){rejected=true;}check(rejected,message);}
    json content(const json& result) {return result.at("structuredContent");}
    void status(const json& value,const char* expected) {
        const auto actual=content(value).at("status");
        if(actual!=expected) std::cerr<<value.dump()<<'\n';
        check(actual==expected,expected);
        check(value.at("isError")== (std::string(expected)!="completed"),"error flag matches completion");
    }
    struct fake_host : host_system_provider {
        bool enabled=true,fail=false;
        int captures=0;
        bool available() const override {return enabled;}
        std::string_view name() const override {return "test_fixture";}
        host_snapshot capture() override {
            ++captures;if(fail)throw std::runtime_error("host_capture_failed");
            host_snapshot value;value.filetime_100ns=42;value.performance_counter=1234;value.performance_frequency=10000000;value.tick_count_ms=5678;
            const std::uint32_t page=4096,processors=8,length=64; const std::uint64_t physical=0x100000000;
            std::memcpy(value.system_info.data()+4,&page,4);std::memcpy(value.system_info.data()+32,&processors,4);
            std::memcpy(value.memory_status.data(),&length,4);std::memcpy(value.memory_status.data()+8,&physical,8);
            return value;
        }
    };
    json bind(const char* name,const char* module="ntoskrnl.exe",const char* address="0x300000") {
        return {{"module",module},{"name",name},{"address",address}};
    }
    json call(const char* name,json registers,json memory=json::array(),const char* module="ntoskrnl.exe") {
        return {{"code_hex","48b80000300000000000ffd0c3"},{"registers",registers},
            {"memory",memory},{"imports",json::array({bind(name,module)})}};
    }
    json region(const char* addr,const char* bytes,const char* perms="rw") {return {{"address",addr},{"bytes_hex",bytes},{"permissions",perms}};}
    void catalog_and_host() {
        fake_host host;emulation_service service(host);
        const auto catalog=content(service.api_catalog(json::object()));
        check(catalog.at("apis").size()==22,"catalog covers explicit models");
        check(catalog.at("complete_windows_api_coverage")==false,"coverage limitations explicit");
        check(content(service.api_catalog({{"module","KERNEL32.DLL"},{"name","GetTickCount64"}})).at("apis").size()==1,"module matching case insensitive");
        check(content(service.api_catalog({{"name","Unknown"}})).at("apis").empty(),"unknown API not advertised");
        host.enabled=false;
        check(content(service.api_catalog({{"name","GetTickCount64"}})).at("apis")[0].at("available")==false,"host availability exposed");
        check(service.system_snapshot(json::object()).at("isError")==true,"unavailable host snapshot explicit");
        host.enabled=true;
        const auto snapshot=content(service.system_snapshot(json::object()));
        check(snapshot.at("provider")=="test_fixture"&&snapshot.at("source")=="host_snapshot","snapshot provenance");
        check(snapshot.at("system").at("processor_count")==8,"system information decoded");
        check(snapshot.at("memory").at("total_physical_bytes")=="4294967296","full width system numbers preserved");
        rejects([&]{service.api_catalog({{"bad",true}});},"catalog rejects unknown field");
        rejects([&]{service.system_snapshot({{"bad",true}});},"snapshot rejects unknown field");
#ifdef _WIN32
        emulation_service native;
        const auto actual=content(native.system_snapshot(json::object()));
        check(actual.at("provider")=="win32","native Win32 provider");
        check(actual.at("system").at("page_size").get<unsigned>()>0,"native Windows page size");
        check(actual.at("system").at("processor_count").get<unsigned>()>0,"native Windows processors");
        check(std::stoull(actual.at("performance_frequency").get<std::string>())>0,"native performance frequency");
        const auto native_call=native.run(call("GetTickCount64",json::object(),json::array(),"kernel32.dll"));
        status(native_call,"completed");
        check(content(native_call).at("api_trace")[0].at("provider")=="win32","real host data reaches guest bridge");
        check(content(native_call).at("registers").at("rax")!="0x0","native guest uptime is populated");
#else
        emulation_service native;
        check(native.system_snapshot(json::object()).at("isError")==true,"native Windows APIs unavailable on Linux");
#endif
    }
    void memory_models() {
        fake_host host;emulation_service service(host);
        const auto memory=json::array({region("0x200000","0102030400000000")});
        auto value=service.run(call("memcpy",{{"rcx","0x200004"},{"rdx","0x200000"},{"r8",4}},memory));
        status(value,"completed");
        auto out=content(value);
        check(out.at("memory")[0].at("after_hex")=="0102030401020304","memcpy changes guest bytes");
        check(out.at("registers").at("rax")=="0x200004","memcpy returns destination");
        check(out.at("api_trace")[0].at("backend")=="model"&&out.at("host_mutation")==false,"model provenance");
        check(host.captures==0,"memory model never queries host");
        value=service.run(call("memmove",{{"rcx","0x200001"},{"rdx","0x200000"},{"r8",3}},memory));status(value,"completed");
        check(content(value).at("memory")[0].at("after_hex")=="0101020300000000","overlapping memmove");
        value=service.run(call("memcpy",{{"rcx","0x200001"},{"rdx","0x200000"},{"r8",3}},memory));status(value,"api_model_error");
        value=service.run(call("RtlZeroMemory",{{"rcx","0x200000"},{"rdx",4}},memory));status(value,"completed");
        check(content(value).at("memory")[0].at("after_hex")=="0000000000000000","zero memory");
        value=service.run(call("memset",{{"rcx","0x200000"},{"rdx",255},{"r8",4}},memory));status(value,"completed");
        check(content(value).at("memory")[0].at("after_hex")=="ffffffff00000000","memset argument order");
        value=service.run(call("RtlFillMemory",{{"rcx","0x200000"},{"rdx",4},{"r8",170}},memory));status(value,"completed");
        check(content(value).at("memory")[0].at("after_hex")=="aaaaaaaa00000000","RtlFillMemory argument order");
        value=service.run(call("RtlCompareMemory",{{"rcx","0x200000"},{"rdx","0x200000"},{"r8",4}},memory));status(value,"completed");
        check(content(value).at("registers").at("rax")=="0x4","compare matching bytes");
        value=service.run(call("memcpy",{{"rcx",0},{"rdx",0},{"r8",0}}));status(value,"completed");
        value=service.run(call("memset",{{"rcx","0x200000"},{"rdx",1},{"r8",4}},json::array({region("0x200000","00000000","r")})));status(value,"api_model_error");
        check(content(value).at("memory")[0].at("after_hex")=="00000000","API respects guest permissions");
        value=service.run(call("memset",{{"rcx",0},{"rdx",1},{"r8",65537}}));status(value,"api_model_error");
        value=service.run(call("memcpy",{{"rcx","0x200004"},{"rdx","0x900000"},{"r8",4}},memory));status(value,"api_model_error");
        check(content(value).at("api_trace")[0].at("error")=="api_guest_memory_unmapped_or_protected","named dependency diagnostic");
    }
    void host_bridges() {
        fake_host host;emulation_service service(host);
        auto value=service.run(call("KeQuerySystemTime",{{"rcx","0x200000"}},json::array({region("0x200000","0000000000000000")})));status(value,"completed");
        auto out=content(value);
        check(out.at("memory")[0].at("after_hex")=="2a00000000000000","host time copied into guest memory");
        check(out.at("api_trace")[0].at("backend")=="host_snapshot"&&out.at("api_trace")[0].at("provider")=="test_fixture","host call provenance");
        check(out.at("host_snapshot").at("filetime_100ns")=="42","snapshot captured as data");
        value=service.run(call("QueryPerformanceCounter",{{"rcx","0x200000"}},json::array({region("0x200000","0000000000000000")}),"kernel32.dll"));status(value,"completed");
        check(content(value).at("memory")[0].at("after_hex")=="d204000000000000","performance counter bridge");
        value=service.run(call("KeQueryPerformanceCounter",{{"rcx",0}}));status(value,"completed");
        check(content(value).at("registers").at("rax")=="0x4d2","kernel counter returns large integer");
        value=service.run(call("QueryPerformanceFrequency",{{"rcx","0x200000"}},json::array({region("0x200000","0000000000000000")}),"kernelbase.dll"));status(value,"completed");
        check(content(value).at("memory")[0].at("after_hex")=="8096980000000000","performance frequency bridge");
        auto args=call("GetTickCount64",json::object(),json::array(),"kernel32.dll");
        args["code_hex"]="48b80000300000000000ffd048b80000300000000000ffd0c3";
        const auto before=host.captures;value=service.run(args);status(value,"completed");
        check(host.captures==before+1&&content(value).at("api_trace").size()==2,"single frozen snapshot per run");
        check(content(value).at("registers").at("rax")=="0x162e","uptime bridge");
        value=service.run(call("GetNativeSystemInfo",{{"rcx","0x200000"}},json::array({region("0x200000",std::string(96,'0').c_str())}),"kernel32.dll"));status(value,"completed");
        check(content(value).at("memory")[0].at("after_hex").get<std::string>().substr(8,8)=="00100000","guest x64 SYSTEM_INFO layout");
        value=service.run(call("GlobalMemoryStatusEx",{{"rcx","0x200000"}},json::array({region("0x200000",("40000000"+std::string(120,'0')).c_str())}),"kernel32.dll"));status(value,"completed");
        check(content(value).at("registers").at("rax")=="0x1","memory status success");
        value=service.run(call("GlobalMemoryStatusEx",{{"rcx","0x200000"}},json::array({region("0x200000",std::string(128,'0').c_str())}),"kernel32.dll"));status(value,"api_model_error");
        host.enabled=false;value=service.run(args);status(value,"api_model_error");
        check(content(value).at("api_trace")[0].at("error")=="host_windows_apis_unavailable","host unavailable not fake success");
        host.enabled=true;host.fail=true;value=service.run(args);status(value,"api_model_error");
        check(content(value).at("api_trace")[0].at("error")=="host_capture_failed","host errors preserved");
    }
    void pool_resource_limits() {
        fake_host host;emulation_service service(host);
        auto args=call("ExAllocatePool2",{{"rbx",17}});
        args["code_hex"]="b940000000ba0000010041b80100000048b80000300000000000ffd048ffcb75dfc3";
        args["timeout_ms"]=500;
        const auto value=service.run(args);status(value,"completed");
        const auto out=content(value);
        check(out.at("guest_pool_allocations").size()==16,"guest pool bounded to one MiB");
        check(out.at("registers").at("rax")=="0x0","exhausted pool returns NULL");
        check(out.at("api_trace").back().at("allocation_failure")=="guest_pool_exhausted","pool exhaustion explained");
        check(host.captures==0,"pool allocations never allocate host kernel memory");
    }
    void pool_and_binding() {
        fake_host host;emulation_service service(host);
        auto value=service.run(call("ExAllocatePool2",{{"rcx",64},{"rdx",16},{"r8",1}}));status(value,"completed");
        auto out=content(value);
        check(out.at("registers").at("rax")=="0x50000000"&&out.at("guest_pool_allocations").size()==1,"guest pool allocation");
        auto args=call("ExAllocatePool2",{{"rcx",64},{"rdx",16},{"r8",1}});
        args["code_hex"]="48b80000300000000000ffd04889c1ba0100000048b80100300000000000ffd0c3";
        args["imports"].push_back(bind("ExFreePoolWithTag","ntoskrnl.exe","0x300001"));
        value=service.run(args);status(value,"completed");
        check(content(value).at("guest_pool_allocations").empty(),"guest pool freed");
        check(content(value).at("api_trace").size()==2,"same-page imports dispatched independently");
        value=service.run(call("ExFreePool",{{"rcx","0x50000000"}}));status(value,"api_model_error");
        check(content(value).at("api_trace")[0].at("error")=="invalid_guest_pool_free","invalid free diagnostic");
        value=service.run(call("ExAllocatePool2",{{"rcx",1},{"rdx",16},{"r8",1}}));status(value,"api_model_error");
        value=service.run(call("ExAllocatePoolWithTag",{{"rcx",512},{"rdx",16},{"r8",1}}));status(value,"completed");
        value=service.run(call("ExAllocatePoolWithTag",{{"rcx",513},{"rdx",16},{"r8",1}}));status(value,"api_model_error");
        value=service.run(call("ExAllocatePoolWithTag",{{"rcx",512},{"rdx",16},{"r8",0}}));status(value,"api_model_error");
        args=call("ExAllocatePool2",{{"rcx",64},{"rdx",16},{"r8",1}});
        args["code_hex"]="48b80000300000000000ffd04889c1ba0200000048b80100300000000000ffd0c3";
        args["imports"].push_back(bind("ExFreePoolWithTag","ntoskrnl.exe","0x300001"));
        value=service.run(args);status(value,"api_model_error");
        check(content(value).at("api_trace")[1].at("error")=="guest_pool_tag_mismatch","pool tag mismatch diagnosed");
        check(content(value).at("guest_pool_allocations").size()==1,"failed tagged free preserves allocation");
        value=service.run(call("UnknownKernelApi",json::object()));status(value,"unsupported_api");
        check(content(value).at("api_trace")[0].at("name")=="UnknownKernelApi","unknown API named in trace");
        args=call("memcpy",json::object());args["imports"][0]["backend"]="host_snapshot";
        rejects([&]{service.run(args);},"backend mismatch rejected");
        args=call("memcpy",json::object());args["imports"].push_back(args["imports"][0]);
        rejects([&]{service.run(args);},"duplicate import address rejected");
        args=call("memcpy",json::object());args["imports"][0]["address"]="0x100000";
        rejects([&]{service.run(args);},"import cannot overwrite code");
        args=call("ExAllocatePool2",{{"rcx",64},{"rdx",16},{"r8",1}});args["memory"].push_back(region("0x50000000","00"));
        rejects([&]{service.run(args);},"pool range collision rejected");
        args=call("GetTickCount64",json::object(),json::array(),"kernel32.dll");args["instruction_limit"]=2;
        value=service.run(args);status(value,"instruction_limit");
        check(content(value).at("api_trace").empty(),"instruction budget stops before API entry");
    }
}
int main() {
    try {catalog_and_host();memory_models();host_bridges();pool_and_binding();pool_resource_limits();std::cout<<assertions<<" API assertions passed\n";return 0;}
    catch(const std::exception& error){std::cerr<<"FAIL after "<<assertions<<" assertions: "<<error.what()<<'\n';return 1;}
}
