// Runs the pinned upstream implementations in a fresh, image-free Windows model.
// Guest buffers, handles, registry and devices belong to this process only.
#include <nlohmann/json.hpp>
#include "kernel/win/x86_win.hpp"
#include "emu/x86/calling_conv.hpp"
#include "emu/guest_emu.hpp"
#include "pe_image.hpp"
#include "execution_engine.hpp"
#include "contract_analysis.hpp"
#include <spdlog/sinks/base_sink.h>
#include <algorithm>
#include <charconv>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <map>
#include <mutex>
#include <stdexcept>
#ifndef _WIN32
#include <sys/resource.h>
#endif

using json = nlohmann::json;
namespace {
std::string hex(std::uint64_t v) { return std::format("0x{:x}", v); }
std::uint64_t number(const json& value) {
    if (value.is_number_unsigned()) return value.get<std::uint64_t>();
    if (value.is_number_integer() && value.get<std::int64_t>() >= 0) return value.get<std::uint64_t>();
    if (value.is_string()) {
        auto text = value.get<std::string>(); std::string_view view(text);
        int base = 10; if (view.starts_with("0x")) { view.remove_prefix(2); base = 16; }
        std::uint64_t n{}; const auto p = std::from_chars(view.data(), view.data()+view.size(), n, base);
        if (!view.empty() && p.ec == std::errc() && p.ptr == view.data()+view.size()) return n;
    }
    throw std::invalid_argument("unsigned_integer_or_hex_string_required");
}
void fields(const json& j, std::initializer_list<const char*> allowed) {
    if (!j.is_object()) throw std::invalid_argument("object_required");
    for (const auto& x : j.items()) {
        bool found = false; for (auto a : allowed) found |= x.key()==a;
        if (!found) throw std::invalid_argument("unexpected_argument: "+x.key());
    }
}
std::vector<std::uint8_t> decode(const std::string& text,std::size_t maximum=16384) {
    if (text.size()%2 || text.size()/2>maximum) throw std::invalid_argument("invalid_buffer_hex");
    std::vector<std::uint8_t> data;
    auto nibble=[](char c)->unsigned {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;throw std::invalid_argument("invalid_buffer_hex");};
    for (std::size_t i=0;i<text.size();i+=2) data.push_back(static_cast<std::uint8_t>(nibble(text[i])*16+nibble(text[i+1])));
    return data;
}
std::vector<std::uint8_t> image_input(const json& args,const char* hex_key,const char* path_key,std::size_t maximum) {
    if(args.contains(hex_key)==args.contains(path_key))throw std::invalid_argument("provide_exactly_one_image_input");
    if(args.contains(hex_key))return decode(args.at(hex_key).get<std::string>(),maximum);
    const auto text=args.at(path_key).get<std::string>();
    if(text.empty()||text.size()>4096||text.find('\0')!=std::string::npos)throw std::invalid_argument("invalid_image_path");
    const auto path=std::filesystem::u8path(text);
    if(!std::filesystem::is_regular_file(path))throw std::invalid_argument("image_path_not_regular_file");
    const auto length=std::filesystem::file_size(path);if(length>maximum)throw std::invalid_argument("image_file_too_large");
    std::ifstream file(path,std::ios::binary);std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length));
    file.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
    if(!file||file.gcount()!=static_cast<std::streamsize>(bytes.size())||file.peek()!=std::char_traits<char>::eof())
        throw std::runtime_error("image_file_read_failed_or_changed");
    return bytes;
}
std::string encode(const std::vector<std::uint8_t>& data) {
    constexpr char digits[]="0123456789abcdef"; std::string out;out.reserve(data.size()*2);
    for (auto b:data) {out+=digits[b>>4];out+=digits[b&15];}return out;
}
std::string module_name(std::string text) {
    for(auto& c:text) if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');return text;
}
struct log_sink final : spdlog::sinks::base_sink<std::mutex> {
    json entries=json::array(); bool truncated=false;
    void sink_it_(const spdlog::details::log_msg& msg) override {
        if(entries.size()>=256){truncated=true;return;}
        entries.push_back({{"level",std::string(spdlog::level::to_string_view(msg.level).data(),spdlog::level::to_string_view(msg.level).size())},
            {"message",std::string(msg.payload.data(),std::min<std::size_t>(msg.payload.size(),1024))}});
    }
    void flush_() override {}
};
struct handler {redirect_fn fn;std::size_t arguments;bool returns_value;};
struct runtime {
    std::shared_ptr<x86::mmu> memory=std::make_shared<x86::mmu>();
    std::shared_ptr<x86_win_conv> conv=std::make_shared<x86_win_conv>();
    std::shared_ptr<emu> emulator=make_guest_emu(memory,conv);
    x86_win_emulator win{emulator,false};
    std::map<std::pair<std::string,std::string>,handler> handlers;
    std::vector<std::shared_ptr<proc_module>> modules;
    runtime() {
        auto& state=win.kernel();
        state.handler_observer=[this](proc_module& mod,std::string_view name,redirect_fn fn,std::size_t args,bool result) {
            const auto key=std::make_pair(mod.name,std::string(name));
            // Upstream's address map also keeps the last registration for aliases/overrides.
            handlers.insert_or_assign(key,handler{std::move(fn),args,result});
        };
        auto add=[&](const char* name,auto registrar) {
            auto mod=std::make_shared<proc_module>();mod->name=name;mod->lookup_name=name;
            modules.push_back(mod);registrar(state,*mod);
        };
        add("ntoskrnl.exe",modules::register_ntoskrnl);add("fltmgr.sys",modules::register_fltmgr);
        add("cng.sys",modules::register_cng);add("ci.dll",modules::register_ci);
        add("ndis.sys",modules::register_ndis);add("tbs.sys",modules::register_tbs);
        add("tdi.sys",modules::register_tdi);add("win32k.sys",modules::register_win32k);
        state.handler_observer={};
    }
    json catalog(const json& args) {
        fields(args,{"module","name","syscalls_only","offset","limit"});
        const auto mod=module_name(args.value("module",std::string())),name=args.value("name",std::string());
        const auto offset=args.contains("offset")?number(args.at("offset")):0;
        const auto limit=args.contains("limit")?number(args.at("limit")):100;
        if(!limit||limit>200)throw std::invalid_argument("invalid_catalog_limit");
        const bool only=args.value("syscalls_only",false);
        json entries=json::array();std::size_t filtered=0,nt=0,zw=0;
        for(const auto& [key,h]:handlers) {
            const auto& [module,api]=key;const bool syscall=api.starts_with("Nt")||api.starts_with("Zw");
            if(api.starts_with("Nt"))++nt;if(api.starts_with("Zw"))++zw;
            if((!mod.empty()&&module!=mod)||(!name.empty()&&api!=name)||(only&&!syscall))continue;
            if(filtered++<offset||entries.size()>=limit)continue;
            entries.push_back({{"module",module},{"name",api},{"argument_count",h.arguments},
                {"returns_value",h.returns_value},{"syscall_handler",syscall},{"source","kernemul"},
                {"calling_convention","windows_x64"},{"fidelity","upstream_reimplementation"}});
        }
        return {{"operations",entries},{"total_registered",handlers.size()},{"nt_handlers",nt},{"zw_aliases",zw},
            {"filtered_total",filtered},{"next_offset",offset+entries.size()<filtered?json(offset+entries.size()):json(nullptr)},
            {"numeric_syscall_dispatch",true},{"syscall_mapping_required",true},{"upstream_revision",EVOKE_KERNEMUL_REVISION}};
    }
#include "image_runtime.inc"
    json discover_contract(const json& args) {
        fields(args,{"image_hex","image_path","base_address","instruction_limit","trace_limit","execution_timeout_ms","timeout_ms","analysis_instruction_limit"});
        const auto raw=image_input(args,"image_hex","image_path",2*1024*1024);
        const evoke_pe::image image(raw,false);
        const auto analysis_limit=args.contains("analysis_instruction_limit")?number(args.at("analysis_instruction_limit")):8192;
        if(!analysis_limit||analysis_limit>32768)throw std::invalid_argument("invalid_analysis_instruction_limit");
        json observations={{"dispatch_routines",json::array()},{"namespace_events",json::array()}};
        json execution_args=args;execution_args.erase("analysis_instruction_limit");execution_args["kind"]="driver";
        // Snapshot once: discovery and emulation must refer to the exact same source bytes.
        execution_args.erase("image_path");execution_args["image_hex"]=encode(raw);
        json initialization;
        try {initialization=execute_image(execution_args,&observations);}
        catch(const std::exception& error){initialization={{"status","initialization_unavailable"},{"error",error.what()}};}
        std::vector<evoke_contract::dispatch_root> roots;
        for(const auto& r:observations["dispatch_routines"])if(r.contains("rva"))
            roots.push_back({r.at("major").get<unsigned>(),r.at("rva").get<std::uint32_t>(),"guest_driver_object"});
        auto report=evoke_contract::analyze(image,raw,roots,static_cast<unsigned>(analysis_limit));
        json imports=json::array();
        try {for(const auto& imp:image.imports()) {
            auto module=module_name(imp.module);if(module=="ntkrnlmp.exe")module="ntoskrnl.exe";
            imports.push_back({{"module",imp.module},{"name",imp.name},{"iat_rva",imp.slot},
                {"modeled",handlers.contains({module=="ntdll.dll"?"ntoskrnl.exe":module,imp.name})}});
        }}catch(const std::exception& error){report["import_analysis_error"]=error.what();}
        report["imports"]=std::move(imports);report["status"]="completed";report["tool"]="discover_driver_contract";
        report["source"]="kernemul_and_capstone";report["source_input"]=args.contains("image_path")?"host_file":"supplied_hex";
        report["observations"]=std::move(observations);
        const bool returned=initialization.value("status",std::string())=="completed";
        report["initialization_succeeded"]=returned&&static_cast<std::int32_t>(number(initialization.at("entry_return_value")))>=0;
        report["initialization"]=std::move(initialization);report["live_system_modified"]=false;
        report["contract_version"]=1;report["upstream_revision"]=EVOKE_KERNEMUL_REVISION;
        return report;
    }
    struct buffer {std::uint64_t addr;std::vector<std::uint8_t> bytes;};
    json run(const json& args) {
        fields(args,{"context","buffers","operations","patches","reads","timeout_ms"});
        const auto context=args.value("context",std::string("kernel"));
        if(context!="kernel"&&context!="user")throw std::invalid_argument("invalid_context");
        const auto& calls=args.at("operations");
        if(!calls.is_array()||calls.empty()||calls.size()>64)throw std::invalid_argument("invalid_operations");
        auto& state=win.kernel();state.initialize_headless();win.create_vcpus(1);
        auto cpu=win.cpus().front();state.init_per_cpu(*cpu);set_log_cpu(cpu.get());
        auto proc=context=="user"?std::dynamic_pointer_cast<windows_process>(state.create_process("evoke.exe")):
            std::static_pointer_cast<windows_process>(state.sys_proc);
        proc->set_scheduler(&win.scheduler());
        auto t=proc->create_suspended_thread(*cpu,0);cpu->set_thread(t);t->restore(*cpu);
        auto space=proc->addr_space();memory->switch_to(*cpu,space);
        std::map<std::string,buffer> buffers;std::size_t total_bytes=0;
        if(args.contains("buffers")) {
            const auto& entries=args.at("buffers");if(!entries.is_array()||entries.size()>32)throw std::invalid_argument("invalid_buffers");
            for(const auto& entry:entries) {
                fields(entry,{"id","bytes_hex","size"});const auto id=entry.at("id").get<std::string>();
                if(id.empty()||id.size()>64||buffers.contains(id))throw std::invalid_argument("invalid_buffer_id");
                auto data=decode(entry.value("bytes_hex",std::string()));
                const auto size=entry.contains("size")?number(entry.at("size")):data.size();
                if(!size||size<data.size()||size>16384||(total_bytes+=size)>65536)throw std::invalid_argument("invalid_buffer_size");
                data.resize(size);const auto addr=space->alloc(size,context=="kernel"?prot_rw|prot_supervisor:prot_rw);
                space->write_mem(addr,data.data(),data.size());buffers.emplace(id,buffer{addr,std::move(data)});
            }
        }
        json trace=json::array();std::vector<std::optional<std::uint64_t>> results;
        const auto resolve=[&](const json& arg)->std::uint64_t {
            if(!arg.is_object())return number(arg);
            if(arg.contains("buffer")) {
                fields(arg,{"buffer","offset"});const auto& b=buffers.at(arg.at("buffer").get<std::string>());
                const auto offset=arg.contains("offset")?number(arg.at("offset")):0;
                if(offset>=b.bytes.size())throw std::invalid_argument("buffer_offset_out_of_range");return b.addr+offset;
            }
            if(arg.contains("result")) {
                fields(arg,{"result"});const auto index=number(arg.at("result"));
                if(index>=results.size()||!results[index])throw std::invalid_argument("invalid_result_reference");return *results[index];
            }
            if(arg.contains("read_u64")) {
                fields(arg,{"read_u64"});const auto& ref=arg.at("read_u64");fields(ref,{"buffer","offset"});
                const auto& b=buffers.at(ref.at("buffer").get<std::string>());const auto offset=ref.contains("offset")?number(ref.at("offset")):0;
                if(offset>b.bytes.size()||b.bytes.size()-offset<8)throw std::invalid_argument("buffer_read_out_of_range");
                return space->read_mem<std::uint64_t>(b.addr+offset);
            }
            throw std::invalid_argument("invalid_argument_reference");
        };
        if(args.contains("patches")) {
            const auto& patches=args.at("patches");
            if(!patches.is_array()||patches.size()>64)throw std::invalid_argument("invalid_patches");
            for(const auto& patch:patches) {
                fields(patch,{"buffer","offset","value"});const auto& b=buffers.at(patch.at("buffer").get<std::string>());
                const auto offset=number(patch.at("offset"));
                if(offset>b.bytes.size()||b.bytes.size()-offset<8)throw std::invalid_argument("patch_out_of_range");
                space->write_mem(b.addr+offset,resolve(patch.at("value")));
            }
        }
        // Capture the fully relocated inputs before any handler executes.
        for(auto& [id,b]:buffers)space->read_mem(b.addr,b.bytes.data(),b.bytes.size());
        std::string status="completed";
        for(const auto& call:calls) {
            fields(call,{"module","name","arguments"});
            const auto module=module_name(call.value("module",std::string("ntoskrnl.exe"))),name=call.at("name").get<std::string>();
            json event={{"module",module},{"name",name},{"source","kernemul"},{"status","unsupported_operation"}};
            const auto found=handlers.find({module,name});
            if(found==handlers.end()) {trace.push_back(event);status="unsupported_operation";break;}
            const auto& h=found->second;const auto& arguments=call.at("arguments");
            if(!arguments.is_array()||arguments.size()>16||arguments.size()<h.arguments)
                throw std::invalid_argument("invalid_operation_arguments: "+module+"!"+name+" requires "+std::to_string(h.arguments)+
                    ", received "+std::to_string(arguments.size())+" ("+arguments.type_name()+")");
            for(std::size_t i=0;i<16;++i)conv->write_arg(*cpu,i,0);
            json values=json::array();
            for(std::size_t i=0;i<arguments.size();++i) {const auto value=resolve(arguments[i]);conv->write_arg(*cpu,i,value);values.push_back(hex(value));}
            event["arguments"]=std::move(values);cpu->reg(x86::rax,std::uint64_t(0));
            const auto pc=cpu->pc();
            try {
                h.fn(*cpu);const auto result=conv->read_ret(*cpu);results.push_back(h.returns_value?std::optional<std::uint64_t>(result):std::nullopt);
                event["return_value"]=h.returns_value?json(hex(result)):json(nullptr);event["status"]="handled";
                const auto wt=std::dynamic_pointer_cast<win_thread>(t);
                if(cpu->pc()!=pc||t->is_sleeping()||t->is_finished()||(wt&&(wt->is_waiting()||wt->suspend_count()))) {
                    event["status"]="guest_scheduling_required";status="guest_scheduling_required";
                }
            } catch(const std::exception& error) {event["status"]="handler_error";event["error"]=error.what();status="handler_error";}
            trace.push_back(std::move(event));if(status!="completed")break;
        }
        json out_buffers=json::array();
        for(const auto& [id,b]:buffers) {
            auto after=b.bytes;space->read_mem(b.addr,after.data(),after.size());
            out_buffers.push_back({{"id",id},{"address",hex(b.addr)},{"before_hex",encode(b.bytes)},{"after_hex",encode(after)}});
        }
        json reads=json::array();std::size_t read_total=0;
        if(args.contains("reads")) {
            const auto& entries=args.at("reads");if(!entries.is_array()||entries.size()>16)throw std::invalid_argument("invalid_reads");
            for(const auto& entry:entries) {
                fields(entry,{"address","size"});const auto size=number(entry.at("size"));
                if(!size||size>16384||(read_total+=size)>65536)throw std::invalid_argument("invalid_read_size");
                const auto addr=resolve(entry.at("address"));std::vector<std::uint8_t> bytes(size);
                space->read_mem(addr,bytes.data(),size);reads.push_back({{"address",hex(addr)},{"bytes_hex",encode(bytes)}});
            }
        }
        return {{"status",status},{"context",context},{"source","kernemul"},{"upstream_revision",EVOKE_KERNEMUL_REVISION},
            {"operation_trace",trace},{"buffers",out_buffers},{"reads",reads},{"live_system_modified",false},
            {"state_lifetime","this_request"},{"numeric_syscall_dispatch",false}};
    }
};
}
int process_request(const std::filesystem::path& input_path,const std::filesystem::path& output_path) {
#ifndef _WIN32
    const rlimit memory_limit{2ULL*1024*1024*1024,2ULL*1024*1024*1024};
    const rlimit file_limit{1024*1024,1024*1024};
    const rlimit cpu_limit{12,12};
    if(setrlimit(RLIMIT_AS,&memory_limit)||setrlimit(RLIMIT_FSIZE,&file_limit)||setrlimit(RLIMIT_CPU,&cpu_limit))return 4;
#endif
    auto sink=std::make_shared<log_sink>();auto logger=std::make_shared<spdlog::logger>("kernemul",sink);spdlog::set_default_logger(logger);
    json out;
    try {
        if(std::filesystem::file_size(input_path)>16*1024*1024)throw std::invalid_argument("invalid_worker_input");
        std::ifstream input(input_path,std::ios::binary);std::string text((std::istreambuf_iterator<char>(input)),{});
        if(!input||text.size()>16*1024*1024)throw std::invalid_argument("invalid_worker_input");
        const auto request=json::parse(text);fields(request,{"action","arguments"});runtime machine;
        const auto action=request.at("action").get<std::string>();
        if(action=="catalog")out=machine.catalog(request.at("arguments"));
        else if(action=="image")out=machine.execute_image(request.at("arguments"));
        else if(action=="discover_contract")out=machine.discover_contract(request.at("arguments"));
        else if(action=="run")out=machine.run(request.at("arguments"));
        else throw std::invalid_argument("unknown_worker_action");
    } catch(const std::exception& error) {out={{"status","worker_error"},{"error",error.what()},{"source","kernemul"}};}
    out["diagnostics"]=sink->entries;out["diagnostics_truncated"]=sink->truncated;
    std::ofstream output(output_path,std::ios::binary|std::ios::trunc);output<<out.dump();return output.good()?0:3;
}

#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {return argc==3?process_request(argv[1],argv[2]):2;}
#else
int main(int argc,char** argv) {return argc==3?process_request(argv[1],argv[2]):2;}
#endif
