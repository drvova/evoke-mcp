#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "api_models.hpp"
#include <unicorn/x86.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>

namespace mcp_runtime {
    namespace {
        constexpr const char* memory_modules = "ntoskrnl.exe;ntkrnlmp.exe;ntdll.dll;ucrtbase.dll;msvcrt.dll";
        constexpr const char* kernel_modules = "ntoskrnl.exe;ntkrnlmp.exe";
        constexpr const char* win32_modules = "kernel32.dll;kernelbase.dll";
        constexpr const char* memory_limits = "Guest mappings only; at most 65536 bytes per call. Copy requires non-overlap; move permits overlap. No host pointers.";
        constexpr const char* pool_limits = "Deterministic guest-only pool, 1 MiB total, at most 64 KiB per allocation. No IRQL, quota, verifier, bugcheck, or Windows pool metadata model. Uninitialized allocations are zero-filled.";
        constexpr const char* host_limits = "Read-only Windows snapshot captured at the first host-backed call and frozen for this run. No live kernel call or host-pointer forwarding.";
        constexpr api_model models[] = {
            {"memcpy",memory_modules,"RCX destination, RDX source, R8 byte_count","RAX destination",memory_limits,api_kind::copy,3,false},
            {"memmove",memory_modules,"RCX destination, RDX source, R8 byte_count","RAX destination",memory_limits,api_kind::move,3,false},
            {"memset",memory_modules,"RCX destination, RDX byte_value, R8 byte_count","RAX destination",memory_limits,api_kind::fill_c,3,false},
            {"RtlCopyMemory",memory_modules,"RCX destination, RDX source, R8 byte_count","void",memory_limits,api_kind::copy,3,false},
            {"RtlMoveMemory",memory_modules,"RCX destination, RDX source, R8 byte_count","void",memory_limits,api_kind::move,3,false},
            {"RtlZeroMemory",memory_modules,"RCX destination, RDX byte_count","void",memory_limits,api_kind::zero,2,false},
            {"RtlFillMemory",memory_modules,"RCX destination, RDX byte_count, R8 byte_value","void",memory_limits,api_kind::fill_nt,3,false},
            {"RtlCompareMemory",memory_modules,"RCX source1, RDX source2, R8 byte_count","RAX leading_equal_bytes",memory_limits,api_kind::compare,3,false},
            {"ExAllocatePoolWithTag",kernel_modules,"RCX pool_type (0,1,512), RDX byte_count, R8 nonzero_tag","RAX guest_pointer_or_NULL",pool_limits,api_kind::allocate_legacy,3,false},
            {"ExAllocatePool2",kernel_modules,"RCX flags (0x40,0x80,0x100; optional 0x2), RDX byte_count, R8 nonzero_tag","RAX guest_pointer_or_NULL",pool_limits,api_kind::allocate2,3,false},
            {"ExFreePool",kernel_modules,"RCX guest_pool_pointer","void",pool_limits,api_kind::free_pool,1,false},
            {"ExFreePoolWithTag",kernel_modules,"RCX guest_pool_pointer, RDX matching_tag","void",pool_limits,api_kind::free_tagged,2,false},
            {"KeQuerySystemTime",kernel_modules,"RCX guest_output_FILETIME_pointer","void",host_limits,api_kind::time_write,1,true},
            {"KeQuerySystemTimePrecise",kernel_modules,"RCX guest_output_FILETIME_pointer","void",host_limits,api_kind::time_write,1,true},
            {"KeQueryPerformanceCounter",kernel_modules,"RCX optional_guest_frequency_pointer","RAX counter",host_limits,api_kind::kernel_counter,1,true},
            {"GetSystemTimeAsFileTime",win32_modules,"RCX guest_output_FILETIME_pointer","void",host_limits,api_kind::time_write,1,true},
            {"GetSystemTimePreciseAsFileTime",win32_modules,"RCX guest_output_FILETIME_pointer","void",host_limits,api_kind::time_write,1,true},
            {"QueryPerformanceCounter",win32_modules,"RCX guest_output_LARGE_INTEGER_pointer","RAX BOOL",host_limits,api_kind::counter_write,1,true},
            {"QueryPerformanceFrequency",win32_modules,"RCX guest_output_LARGE_INTEGER_pointer","RAX BOOL",host_limits,api_kind::frequency_write,1,true},
            {"GetTickCount64",win32_modules,"none","RAX milliseconds",host_limits,api_kind::ticks,0,true},
            {"GetNativeSystemInfo",win32_modules,"RCX guest_output_SYSTEM_INFO_pointer (48 bytes)","void",host_limits,api_kind::system_info,1,true},
            {"GlobalMemoryStatusEx",win32_modules,"RCX guest_MEMORYSTATUSEX_pointer (64 bytes, dwLength=64)","RAX BOOL",host_limits,api_kind::memory_status,1,true}
        };
        std::string lower(std::string_view text) {
            std::string out(text);
            for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return out;
        }
        bool matches_module(std::string_view module, std::string_view choices) {
            const auto wanted = lower(module);
            while (!choices.empty()) {
                const auto end = choices.find(';');
                if (choices.substr(0,end) == wanted) return true;
                if (end == std::string_view::npos) break;
                choices.remove_prefix(end+1);
            }
            return false;
        }
        void uc_check(uc_err value) {
            if (value != UC_ERR_OK) throw std::runtime_error(std::string("unicorn_api: ")+uc_strerror(value));
        }
        std::string hex(std::uint64_t value) {
            constexpr char digits[]="0123456789abcdef";
            std::string out;
            do {out.insert(out.begin(),digits[value&15]); value>>=4;} while(value);
            return "0x"+out;
        }
        std::size_t byte_count(std::uint64_t value) {
            if(value>65536) throw std::runtime_error("api_transfer_limit_exceeded");
            return static_cast<std::size_t>(value);
        }
    }
    std::span<const api_model> api_models() {return models;}
    const api_model* find_api_model(std::string_view module,std::string_view name) {
        for(const auto& model:models) if(name==model.name && matches_module(module,model.modules)) return &model;
        return nullptr;
    }
    json describe_api_models(host_system_provider& host,const json& args) {
        if(!args.is_object()) throw std::invalid_argument("arguments_must_be_object");
        for(const auto& item:args.items()) if(item.key()!="module" && item.key()!="name") throw std::invalid_argument("unexpected_catalog_argument");
        const auto module=args.value("module",std::string()), name=args.value("name",std::string());
        json entries=json::array();
        for(const auto& model:models) {
            if((!module.empty()&&!matches_module(module,model.modules)) || (!name.empty()&&name!=model.name)) continue;
            entries.push_back({{"name",model.name},{"modules",model.modules},{"calling_convention","windows_x64"},
                {"parameters",model.parameters},{"return",model.result},{"backend",model.host_backed?"host_snapshot":"model"},
                {"available",!model.host_backed||host.available()},{"fidelity",model.host_backed?"host_snapshot_bridge":"bounded_guest_model"},
                {"limitations",model.limitations},{"host_mutation",false}});
        }
        return make_tool_result("api_catalog",{{"apis",entries},{"host_provider",std::string(host.name())},
            {"complete_windows_api_coverage",false},{"binding","explicit_import_addresses"}});
    }
    void api_machine::require_access(std::uint64_t address,std::size_t size,unsigned permission) {
        if(!size) return;
        if(address>std::numeric_limits<std::uint64_t>::max()-size) throw std::runtime_error("api_guest_address_overflow");
        uc_mem_region* raw=nullptr; std::uint32_t count=0;
        uc_check(uc_mem_regions(engine_,&raw,&count));
        const std::unique_ptr<uc_mem_region,decltype(&uc_free)> regions(raw,uc_free);
        auto cursor=address; const auto end=address+size;
        while(cursor<end) {
            bool covered=false;
            for(std::uint32_t i=0;i<count;++i) {
                const auto& region=raw[i];
                if(cursor>=region.begin && cursor<=region.end && (region.perms&permission)==permission) {
                    cursor=std::min(end,region.end==std::numeric_limits<std::uint64_t>::max()?end:region.end+1);
                    covered=true; break;
                }
            }
            if(!covered) throw std::runtime_error("api_guest_memory_unmapped_or_protected");
        }
    }
    std::vector<std::uint8_t> api_machine::read(std::uint64_t addr,std::size_t size) {
        require_access(addr,size,UC_PROT_READ);
        std::vector<std::uint8_t> bytes(size);
        if(size) uc_check(uc_mem_read(engine_,addr,bytes.data(),size));
        return bytes;
    }
    void api_machine::write(std::uint64_t addr,const void* bytes,std::size_t size) {
        require_access(addr,size,UC_PROT_WRITE);
        if(size) uc_check(uc_mem_write(engine_,addr,bytes,size));
    }
    const host_snapshot& api_machine::snapshot() {
        if(!snapshot_) {
            if(!host_.available()) throw std::runtime_error("host_windows_apis_unavailable");
            snapshot_=host_.capture();
        }
        return *snapshot_;
    }
    std::uint64_t api_machine::allocate(std::uint64_t size,std::uint32_t tag,bool executable) {
        if(!size || size>65536) throw std::runtime_error("invalid_guest_pool_size");
        const auto count=static_cast<std::size_t>((size+4095)/4096);
        for(std::size_t start=0;start+count<=pages_.size();++start) {
            bool vacant=true;
            for(std::size_t index=start;index<start+count;++index) vacant&=!pages_[index];
            if(!vacant) continue;
            const auto addr=pool_base+start*4096, mapped=count*4096;
            uc_check(uc_mem_map(engine_,addr,mapped,UC_PROT_READ|UC_PROT_WRITE|(executable?UC_PROT_EXEC:0)));
            allocations_.push_back({addr,size,mapped,tag});
            for(std::size_t index=start;index<start+count;++index) pages_[index]=true;
            return addr;
        }
        return 0;
    }
    void api_machine::release(std::uint64_t addr,std::optional<std::uint32_t> tag) {
        const auto found=std::find_if(allocations_.begin(),allocations_.end(),[&](const auto& value){return value.address==addr;});
        if(found==allocations_.end()) throw std::runtime_error("invalid_guest_pool_free");
        if(tag && *tag!=found->tag) throw std::runtime_error("guest_pool_tag_mismatch");
        uc_check(uc_mem_unmap(engine_,found->address,static_cast<std::size_t>(found->mapped)));
        const auto first=static_cast<std::size_t>((found->address-pool_base)/4096);
        for(std::size_t i=first;i<first+found->mapped/4096;++i) pages_[i]=false;
        allocations_.erase(found);
    }
    json api_machine::invoke(const api_binding& binding) {
        json event={{"module",binding.module},{"name",binding.name},{"address",hex(binding.address)},
            {"backend",binding.model?(binding.model->host_backed?"host_snapshot":"model"):"unsupported"},
            {"status","unsupported_api"},{"ok",false},{"host_mutation",false},{"arguments",json::array()}};
        event["source"]=event["backend"];
        if(!binding.model) return event;
        const auto& model=*binding.model;
        event["limitations"]=model.limitations;
        try {
            std::array<std::uint64_t,3> args{};
            constexpr int argument_registers[]={UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8};
            for(unsigned i=0;i<model.arguments;++i) {
                uc_check(uc_reg_read(engine_,argument_registers[i],&args[i]));
                event["arguments"].push_back(hex(args[i]));
            }
            std::uint64_t rsp=0;
            uc_check(uc_reg_read(engine_,UC_X86_REG_RSP,&rsp));
            auto return_bytes=read(rsp,8); std::uint64_t return_to=0;
            std::memcpy(&return_to,return_bytes.data(),8);
            if(rsp>std::numeric_limits<std::uint64_t>::max()-8) throw std::runtime_error("api_stack_overflow");
            std::optional<std::uint64_t> result;
            const auto a=args[0],b=args[1],c=args[2];
            switch(model.kind) {
                case api_kind::copy:
                case api_kind::move: {
                    const auto size=byte_count(c);
                    auto bytes=read(b,size);
                    require_access(a,size,UC_PROT_WRITE);
                    if(model.kind==api_kind::copy && size && a<b+size && b<a+size) throw std::runtime_error("overlapping_memcpy");
                    write(a,bytes.data(),size);
                    if(std::string_view(model.result)!="void") result=a;
                    event["guest_bytes_written"]=size; break;
                }
                case api_kind::fill_c:
                case api_kind::fill_nt:
                case api_kind::zero: {
                    const auto size=byte_count(model.kind==api_kind::fill_c?c:b);
                    const auto value=static_cast<std::uint8_t>(model.kind==api_kind::zero?0:model.kind==api_kind::fill_c?b:c);
                    const std::vector<std::uint8_t> bytes(size,value);
                    write(a,bytes.data(),size);
                    if(model.kind==api_kind::fill_c) result=a;
                    event["guest_bytes_written"]=size; break;
                }
                case api_kind::compare: {
                    const auto size=byte_count(c); const auto first=read(a,size), second=read(b,size);
                    std::uint64_t matched=0;
                    while(matched<size && first[static_cast<std::size_t>(matched)]==second[static_cast<std::size_t>(matched)]) ++matched;
                    result=matched; break;
                }
                case api_kind::allocate_legacy:
                case api_kind::allocate2: {
                    if(!c || c>std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("invalid_guest_pool_tag");
                    bool executable=false;
                    if(model.kind==api_kind::allocate_legacy) {
                        if(a!=0&&a!=1&&a!=512) throw std::runtime_error("unsupported_guest_pool_type");
                        executable=(a&512)==0;
                    } else {
                        const auto type=a&0x1c0;
                        if((a&~std::uint64_t(0x1c2)) || (type!=0x40&&type!=0x80&&type!=0x100))
                            throw std::runtime_error("unsupported_guest_pool_flags_or_tag");
                        executable=type==0x80;
                    }
                    result=allocate(b,static_cast<std::uint32_t>(c),executable);
                    event["guest_pool_address"]=hex(*result);
                    if(!*result) event["allocation_failure"]="guest_pool_exhausted";
                    break;
                }
                case api_kind::free_pool: release(a,std::nullopt); event["guest_pool_freed"]=hex(a); break;
                case api_kind::free_tagged:
                    if(b>std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("invalid_guest_pool_tag");
                    release(a,static_cast<std::uint32_t>(b)); event["guest_pool_freed"]=hex(a); break;
                case api_kind::time_write: {const auto value=snapshot().filetime_100ns;write(a,&value,8);event["guest_bytes_written"]=8;break;}
                case api_kind::kernel_counter:
                    if(a) {const auto frequency=snapshot().performance_frequency;write(a,&frequency,8);event["guest_bytes_written"]=8;}
                    result=snapshot().performance_counter; break;
                case api_kind::counter_write: {const auto value=snapshot().performance_counter;write(a,&value,8);result=1;event["guest_bytes_written"]=8;break;}
                case api_kind::frequency_write: {const auto value=snapshot().performance_frequency;write(a,&value,8);result=1;event["guest_bytes_written"]=8;break;}
                case api_kind::ticks: result=snapshot().tick_count_ms; break;
                case api_kind::system_info: {const auto& value=snapshot().system_info;write(a,value.data(),value.size());event["guest_bytes_written"]=value.size();break;}
                case api_kind::memory_status: {
                    const auto bytes=read(a,4);std::uint32_t length=0;std::memcpy(&length,bytes.data(),4);
                    if(length!=64) throw std::runtime_error("guest_MEMORYSTATUSEX_length_must_be_64");
                    const auto& value=snapshot().memory_status;write(a,value.data(),value.size());result=1;event["guest_bytes_written"]=value.size();break;
                }
            }
            if(event.contains("guest_bytes_written")) event["guest_write_address"]=hex(a);
            if(result) {uc_check(uc_reg_write(engine_,UC_X86_REG_RAX,&*result));event["return_value"]=hex(*result);}
            const auto next_rsp=rsp+8;
            uc_check(uc_reg_write(engine_,UC_X86_REG_RSP,&next_rsp));
            uc_check(uc_reg_write(engine_,UC_X86_REG_RIP,&return_to));
            event["status"]="handled";event["ok"]=true;
            if(model.host_backed) {event["provider"]=std::string(host_.name());event["snapshot_filetime_100ns"]=std::to_string(snapshot().filetime_100ns);}
        } catch(const std::exception& exception) {event["status"]="api_model_error";event["error"]=exception.what();}
        return event;
    }
    json api_machine::allocations() const {
        auto out=json::array();
        for(const auto& value:allocations_) out.push_back({{"address",hex(value.address)},{"size",value.requested},{"mapped_size",value.mapped},{"tag",value.tag}});
        return out;
    }
    json api_machine::snapshot_description() const {
        if(!snapshot_) return nullptr;
        auto out=snapshot_->describe();out["provider"]=std::string(host_.name());out["source"]="host_snapshot";return out;
    }
}
