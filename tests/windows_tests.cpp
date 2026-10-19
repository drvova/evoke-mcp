#include "windows_service.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <string>
using namespace mcp_runtime;
namespace {
int assertions=0;
void check(bool yes,const char* what){++assertions;if(!yes)throw std::runtime_error(what);}
json body(const json& result) {return result.at("structuredContent");}
json run(windows_service& service,json args) {
    args["timeout_ms"]=10000;auto value=service.run(args);
    if(value.at("isError")==true){const auto out=body(value);std::cerr<<out.value("status",std::string())<<" "<<out.value("error",std::string())<<" "<<out.value("operation_trace",json::array()).dump()<<'\n';}
    check(value.at("isError")==false,"real handler execution completes");return body(value);
}
json op(const char* name,json arguments){return {{"name",name},{"arguments",arguments}};}
json ptr(const char* name,unsigned offset=0){return {{"buffer",name},{"offset",offset}};}
json ret(unsigned index){return {{"result",index}};}
json handle(const char* name){return {{"read_u64",ptr(name)}};}
std::string encode(const std::string& bytes){constexpr char h[]="0123456789abcdef";std::string s;for(unsigned char c:bytes){s+=h[c>>4];s+=h[c&15];}return s;}
json buffer(const char* id,unsigned size,const std::string& hex=""){return {{"id",id},{"size",size},{"bytes_hex",hex}};}
std::string after(const json& out,const char* id) {for(const auto& b:out.at("buffers"))if(b.at("id")==id)return b.at("after_hex");throw std::runtime_error("missing_buffer");}
std::uint64_t value(const json& out,unsigned index) {return std::stoull(out.at("operation_trace")[index].at("return_value").get<std::string>(),nullptr,16);}
void success(const json& out,unsigned index){check(value(out,index)==0,"NTSTATUS success from real upstream handler");}
void unicode(json& args,const std::string& id,const std::string& text) {
    std::string wide;for(char c:text){wide+=c;wide+='\0';}const auto len=static_cast<unsigned>(wide.size());wide+='\0';wide+='\0';
    std::string descriptor(16,'\0');descriptor[0]=static_cast<char>(len&255);descriptor[1]=static_cast<char>(len>>8);
    descriptor[2]=static_cast<char>((len+2)&255);descriptor[3]=static_cast<char>((len+2)>>8);
    args["buffers"].push_back(buffer((id+"_text").c_str(),len+2,encode(wide)));
    args["buffers"].push_back(buffer(id.c_str(),16,encode(descriptor)));
    args["patches"].push_back({{"buffer",id},{"offset",8},{"value",ptr((id+"_text").c_str())}});
}
void attributes(json& args,const std::string& path) {
    unicode(args,"path",path);args["buffers"].push_back(buffer("oa",48,"30000000"));
    args["patches"].push_back({{"buffer","oa"},{"offset",16},{"value",ptr("path")}});
}
void discovery(windows_service& service) {
    check(body(service.info(json::object())).at("bundled_worker_available")==true,"worker bundled");
    auto response=service.catalog({{"limit",200}});
    if(response.at("isError")==true)std::cerr<<response.dump()<<'\n';
    check(response.at("isError")==false,"real runtime catalog available");
    const auto catalog=body(response);
    check(catalog.at("total_registered").get<unsigned>()>=460,"upstream runtime registers hundreds of handlers");
    check(catalog.at("nt_handlers").get<unsigned>()>=155,"upstream Nt syscall handler coverage");
    check(catalog.at("next_offset")==200,"catalog pagination");
    const auto one=body(service.catalog({{"module","NTOSKRNL.EXE"},{"name","NtCreateFile"}}));
    check(one.at("filtered_total")==1,"case insensitive module filter");
    check(one.at("operations")[0].at("argument_count")==11,"actual function traits exposed");
    check(one.at("operations")[0].at("syscall_handler")==true,"syscall provenance");
    check(body(service.catalog({{"name","UnknownFunction"}})).at("filtered_total")==0,"unknown handlers not advertised");
    std::cout<<catalog.at("total_registered")<<" registered handlers; "<<catalog.at("nt_handlers")<<" Nt handlers; "<<catalog.at("zw_aliases")<<" Zw aliases\n";
}
void memory_process_threads(windows_service& service) {
    auto out=run(service,{{"buffers",json::array({buffer("process",8),buffer("thread",8),buffer("source",16,std::string(32,'a')),buffer("copied",8)})},
        {"operations",json::array({op("ExAllocatePool2",{64,16,1}),op("MmCopyMemory",{ret(0),ptr("source"),16,2,ptr("copied")}),
            op("PsGetCurrentProcessId",json::array()),op("PsLookupProcessByProcessId",{ret(2),ptr("process")}),
            op("PsGetCurrentProcess",json::array()),op("PsGetCurrentThreadId",json::array()),
            op("PsLookupThreadByThreadId",{ret(5),ptr("thread")}),op("PsGetCurrentThreadId",json::array())})},
        {"reads",json::array({{{"address",ret(0)},{"size",16}}})}});
    check(out.at("reads")[0].at("bytes_hex")==std::string(32,'a'),"pool fill visible through guest memory");
    success(out,3);success(out,6);check(value(out,2)>0&&value(out,5)>0,"guest process and thread IDs populated");
    check(value(out,4)>0&&value(out,7)==value(out,5),"guest process/thread objects populated");
    check(after(out,"process")!="0000000000000000"&&after(out,"thread")!="0000000000000000","lookup APIs write guest pointers");
    out=run(service,{{"operations",json::array({op("ExAllocatePool2",{64,16,1}),op("ExFreePool",{ret(0)})})}});
    check(out.at("operation_trace")[1].at("return_value").is_null(),"void returns do not fabricate values");
}
void synchronization(windows_service& service) {
    const auto out=run(service,{{"buffers",json::array({buffer("event",64)})},
        {"operations",json::array({op("KeInitializeEvent",{ptr("event"),0,0}),op("KeSetEvent",{ptr("event"),0,0}),
            op("KeReadStateMutant",{ptr("event")}),op("KeResetEvent",{ptr("event")}),op("KeReadStateMutant",{ptr("event")})})}});
    check(value(out,1)==0&&value(out,2)==1&&value(out,3)==1&&value(out,4)==0,"event state shared across handlers");
}
void registry(windows_service& service) {
    json args={{"buffers",json::array({buffer("key",8),buffer("disposition",4),buffer("data",4,"78563412"),buffer("output",32),buffer("length",4)})},
        {"patches",json::array()}};
    attributes(args,"\\Registry\\Machine\\Software\\EvokeMcpGuestTest");unicode(args,"value","Answer");
    args["operations"]=json::array({op("NtCreateKey",{ptr("key"),0xf003f,ptr("oa"),0,0,0,ptr("disposition")}),
        op("NtSetValueKey",{handle("key"),ptr("value"),0,4,ptr("data"),4}),
        op("ZwQueryValueKey",{handle("key"),ptr("value"),2,ptr("output"),32,ptr("length")}),op("NtClose",{handle("key")})});
    const auto out=run(service,args);for(unsigned i=0;i<4;++i)success(out,i);
    check(after(out,"output").substr(24,8)=="78563412","registry value persists within guest request");
    args["operations"]=json::array({op("NtOpenKey",{ptr("key"),0xf003f,ptr("oa")})});
    const auto fresh=run(service,args);check(value(fresh,0)!=0,"guest registry reset between requests");
}
void files(windows_service& service) {
    json args={{"buffers",json::array({buffer("file",8),buffer("iosb",16),buffer("source",4,"01020304"),buffer("output",4),buffer("offset",8)})},{"patches",json::array()}};
    attributes(args,"\\??\\C:\\evoke-mcp-guest-only.bin");
    args["operations"]=json::array({op("NtCreateFile",{ptr("file"),"0xc0100000",ptr("oa"),ptr("iosb"),0,128,7,3,64,0,0}),
        op("NtWriteFile",{handle("file"),0,0,0,ptr("iosb"),ptr("source"),4,ptr("offset"),0}),
        op("NtReadFile",{handle("file"),0,0,0,ptr("iosb"),ptr("output"),4,ptr("offset"),0}),op("NtClose",{handle("file")})});
    const auto out=run(service,args);for(unsigned i=0;i<4;++i)success(out,i);
    check(after(out,"output")=="01020304","guest file write/read preserves data");
}
void devices(windows_service& service) {
    const auto out=run(service,{{"buffers",json::array({buffer("driver",512),buffer("device",8)})},
        {"operations",json::array({op("IoCreateDevice",{ptr("driver"),16,0,34,0,0,ptr("device")}),op("IoDeleteDevice",{handle("device")})})}});
    success(out,0);check(after(out,"device")!="0000000000000000","device model creates guest object");
}
void virtual_memory(windows_service& service) {
    const auto out=run(service,{{"context","user"},{"buffers",json::array({buffer("base",8),buffer("size",8,"0010000000000000"),buffer("zero",8)})},
        {"operations",json::array({op("NtAllocateVirtualMemory",{"0xffffffffffffffff",ptr("base"),0,ptr("size"),12288,4}),
            op("NtFreeVirtualMemory",{"0xffffffffffffffff",ptr("base"),ptr("zero"),32768})})}});
    success(out,0);success(out,1);
}
void failures(windows_service& service,const char* executable) {
    auto result=service.run({{"operations",json::array({op("DoesNotExist",json::array())})},{"timeout_ms",10000}});
    check(result.at("isError")==true&&body(result).at("status")=="unsupported_operation","unknown operation stops with named status");
    result=service.run({{"operations",json::array({op("RtlCompareMemory",{0,0,4})})},{"timeout_ms",10000}});
    check(result.at("isError")==true&&body(result).at("status")=="handler_error","unmapped guest pointer does not succeed");
    result=service.run({{"operations",json::array({op("RtlCompareMemory",{1})})},{"timeout_ms",10000}});
    check(result.at("isError")==true&&body(result).at("status")=="worker_error","missing arguments rejected");
    result=service.run({{"buffers",json::array({buffer("event",64)})},
        {"operations",json::array({op("KeInitializeEvent",{ptr("event"),0,0}),
            op("KeWaitForSingleObject",{ptr("event"),0,0,0,0}),op("PsGetCurrentProcessId",json::array())})},{"timeout_ms",10000}});
    check(result.at("isError")==true&&body(result).at("status")=="guest_scheduling_required","pending waits require scheduler support");
    check(body(result).at("operation_trace").size()==2,"pending wait stops dependent operations");
    windows_service hanging(std::filesystem::absolute(executable));
    const auto started=std::chrono::steady_clock::now();
    const auto timeout=hanging.run({{"timeout_ms",100}});
    check(timeout.at("isError")==true&&body(timeout).at("status")=="timeout","worker deadline terminates child");
    check(std::chrono::steady_clock::now()-started<std::chrono::seconds(2),"timeout does not wait for sleeping child");
    windows_service missing(std::filesystem::path("/does-not-exist/evoke-kernemul"));
    check(missing.run(json::object()).at("isError")==true,"missing bundled worker explicit");
}
}
int main(int argc,char** argv){if(argc==3){std::this_thread::sleep_for(std::chrono::seconds(3));return 0;}try{windows_service service;discovery(service);memory_process_threads(service);synchronization(service);registry(service);files(service);devices(service);virtual_memory(service);failures(service,argv[0]);std::cout<<assertions<<" Windows runtime assertions passed\n";return 0;}catch(const std::exception& e){std::cerr<<"FAIL after "<<assertions<<": "<<e.what()<<'\n';return 1;}}
