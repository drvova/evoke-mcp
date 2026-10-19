#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "execution_engine.hpp"
#include "emu/x86/unicorn.hpp"
#include <chrono>
#include <algorithm>
namespace {
void checked(uc_err err){if(err!=UC_ERR_OK)throw std::runtime_error(std::string("unicorn_execution: ")+uc_strerror(err));}
}
struct execution_engine::implementation {
    vcpu& cpu;uc_engine* native;std::vector<std::uint64_t> imports;
    unsigned maximum,trace_max;std::size_t count=0;
    std::chrono::steady_clock::time_point deadline;
    std::vector<execution_instruction> instructions;
    uc_hook code_hook{},interrupt_hook{},fault_hook{},invalid_hook{};
    const char* stopped=nullptr;std::uint64_t fault=0;unsigned interrupt=0,instruction_size=0;
    implementation(vcpu& c,std::vector<std::uint64_t> entries,unsigned limit,unsigned traces,unsigned timeout)
        :cpu(c),native(dynamic_cast<unicorn_vcpu_base&>(c).native()),imports(std::move(entries)),maximum(limit),trace_max(traces),
         deadline(std::chrono::steady_clock::now()+std::chrono::milliseconds(timeout)) {
        std::sort(imports.begin(),imports.end());instructions.reserve(trace_max);
        try {
            checked(uc_hook_add(native,&code_hook,UC_HOOK_CODE,reinterpret_cast<void*>(on_code),this,1,0));
            checked(uc_hook_add(native,&interrupt_hook,UC_HOOK_INTR,reinterpret_cast<void*>(on_interrupt),this,1,0));
            checked(uc_hook_add(native,&fault_hook,UC_HOOK_MEM_INVALID,reinterpret_cast<void*>(on_fault),this,1,0));
            checked(uc_hook_add(native,&invalid_hook,UC_HOOK_INSN_INVALID,reinterpret_cast<void*>(on_invalid),this,1,0));
        }catch(...){remove_hooks();throw;}
    }
    void remove_hooks(){for(auto h:{code_hook,interrupt_hook,fault_hook,invalid_hook})if(h)uc_hook_del(native,h);}
    ~implementation(){remove_hooks();}
    void stop(const char* reason){stopped=reason;uc_emu_stop(native);}
    static void on_code(uc_engine*,std::uint64_t address,std::uint32_t size,void* opaque) noexcept {
        auto& self=*static_cast<implementation*>(opaque);++self.count;self.instruction_size=size;
        try {
            execution_instruction item{address,size,{}};const auto length=std::min<std::size_t>(size,item.bytes.size());
            self.cpu.read_virt_mem(address,item.bytes.data(),length);
            if(self.instructions.size()<self.trace_max)self.instructions.push_back(item);
            if(std::binary_search(self.imports.begin(),self.imports.end(),address)){self.stop("import");return;}
            std::size_t off=0;
            while(off<length) {
                const auto b=item.bytes[off];
                if((b>=0x40&&b<=0x4f)||b==0x66||b==0x67||b==0xf0||b==0xf2||b==0xf3||b==0x2e||b==0x36||b==0x3e||b==0x26||b==0x64||b==0x65)++off;else break;
            }
            if(off<length) {
                const auto op=item.bytes[off];
                if(op==0x0f&&off+1<length&&item.bytes[off+1]==0x05)self.stop("syscall");
                else if(op==0xf4)self.stop("halted");
                else if((op>=0xe4&&op<=0xe7)||(op>=0xec&&op<=0xef)||(op>=0x6c&&op<=0x6f)||(op==0x0f&&off+1<length&&item.bytes[off+1]==0x34))self.stop("external_instruction");
            }
        }catch(...){self.stop("instruction_read_failed");}
    }
    static void on_interrupt(uc_engine*,std::uint32_t code,void* opaque) noexcept {
        auto& self=*static_cast<implementation*>(opaque);self.interrupt=code;
        try{self.fault=self.cpu.reg(x86::cr2);}catch(...){}
        self.stop(code==14?"memory_fault":"interrupt");
    }
    static bool on_fault(uc_engine*,uc_mem_type,std::uint64_t address,int,std::int64_t,void* opaque) noexcept {
        auto& self=*static_cast<implementation*>(opaque);self.fault=address;self.stop("memory_fault");return false;
    }
    static bool on_invalid(uc_engine*,void* opaque) noexcept {static_cast<implementation*>(opaque)->stop("unsupported_instruction");return false;}
};
execution_engine::execution_engine(vcpu& c,std::vector<std::uint64_t> imports,unsigned limit,unsigned traces,unsigned timeout)
    :impl_(std::make_unique<implementation>(c,std::move(imports),limit,traces,timeout)){}
execution_engine::~execution_engine()=default;
execution_event execution_engine::resume(std::uint64_t until) {
    auto& s=*impl_;s.stopped=nullptr;const auto pc=s.cpu.pc();
    const auto remaining=std::chrono::duration_cast<std::chrono::microseconds>(s.deadline-std::chrono::steady_clock::now()).count();
    if(remaining<=0)return {"timeout",pc};
    if(pc==until)return {"completed",pc};
    if(s.count>=s.maximum)return {"instruction_limit",pc};
    const auto result=uc_emu_start(s.native,pc,until,static_cast<std::uint64_t>(remaining),s.maximum-s.count);
    std::size_t timed_out=0;checked(uc_query(s.native,UC_QUERY_TIMEOUT,&timed_out));
    const auto final=s.cpu.pc();
    const std::string status=s.stopped?s.stopped:result!=UC_ERR_OK?std::string("engine_error: ")+uc_strerror(result):timed_out?"timeout":final==until?"completed":s.count>=s.maximum?"instruction_limit":"stopped";
    return {status,final,s.fault,s.interrupt,s.instruction_size};
}
void execution_engine::invalidate_code(){checked(uc_ctl_flush_tb(impl_->native));}
const std::vector<execution_instruction>& execution_engine::trace() const{return impl_->instructions;}
std::size_t execution_engine::observed() const{return impl_->count;}
