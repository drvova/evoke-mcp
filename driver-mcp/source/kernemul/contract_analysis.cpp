#include "contract_analysis.hpp"
#include <capstone/capstone.h>
#include <openssl/evp.h>
#include <array>
#include <compare>
#include <deque>
#include <set>
#include <sstream>
#include <iomanip>

namespace evoke_contract {
namespace {
using json = nlohmann::json;
enum class origin { unknown, driver, irp, stack_location, ioctl, input_length, output_length,
    system_buffer, user_buffer, type3_buffer, image_address, entry_stack, literal };
struct value { origin source{}; std::int64_t displacement=0; auto operator<=>(const value&) const = default; };
using registers = std::array<value,32>;
struct layout {
    unsigned pointer_size,major_base,irp_stack,irp_buffer,irp_user,control,input,output,type3;
};
layout driver_layout(evoke_pe::architecture arch) {
    if(arch==evoke_pe::architecture::x86)return {4,0x38,0x60,0x0c,0x3c,0x0c,0x08,0x04,0x10};
    return {8,0x70,0xb8,0x18,0x70,0x18,0x10,0x08,0x20};
}
int reg_index(unsigned r) {
    switch(r) {
#define REG(N,I) case X86_REG_R##N:case X86_REG_E##N:return I
        REG(AX,0);REG(CX,1);REG(DX,2);REG(BX,3);REG(SP,4);REG(BP,5);REG(SI,6);REG(DI,7);
#undef REG
#define REG(N,I) case X86_REG_R##N:case X86_REG_R##N##D:return I
        REG(8,8);REG(9,9);REG(10,10);REG(11,11);REG(12,12);REG(13,13);REG(14,14);REG(15,15);
#undef REG
        default:return -1;
    }
}
// Partial-register writes invalidate the full register's provenance.
int written_index(unsigned r) {
    if(const auto i=reg_index(r);i>=0)return i;
    switch(r) {
    case X86_REG_AX:case X86_REG_AL:case X86_REG_AH:return 0;
    case X86_REG_CX:case X86_REG_CL:case X86_REG_CH:return 1;
    case X86_REG_DX:case X86_REG_DL:case X86_REG_DH:return 2;
    case X86_REG_BX:case X86_REG_BL:case X86_REG_BH:return 3;
    case X86_REG_SP:case X86_REG_SPL:return 4;case X86_REG_BP:case X86_REG_BPL:return 5;
    case X86_REG_SI:case X86_REG_SIL:return 6;case X86_REG_DI:case X86_REG_DIL:return 7;
#define REG(N,I) case X86_REG_R##N##B:case X86_REG_R##N##W:return I
    REG(8,8);REG(9,9);REG(10,10);REG(11,11);REG(12,12);REG(13,13);REG(14,14);REG(15,15);
#undef REG
    default:return -1;
    }
}
int arm_index(unsigned r) {
    if(r>=ARM64_REG_X0&&r<=ARM64_REG_X28)return static_cast<int>(r-ARM64_REG_X0);
    if(r>=ARM64_REG_W0&&r<=ARM64_REG_W30)return static_cast<int>(r-ARM64_REG_W0);
    if(r==ARM64_REG_FP)return 29;if(r==ARM64_REG_LR)return 30;
    if(r==ARM64_REG_SP||r==ARM64_REG_WSP)return 31;return -1;
}
unsigned arm_width(unsigned r) {return (r>=ARM64_REG_W0&&r<=ARM64_REG_W30)||r==ARM64_REG_WSP||r==ARM64_REG_WZR?4:8;}
bool pointer(origin o) {return o==origin::driver||o==origin::irp||o==origin::stack_location||
    o==origin::system_buffer||o==origin::user_buffer||o==origin::type3_buffer||o==origin::image_address||o==origin::entry_stack;}
value field_value(value base,std::int64_t displacement,unsigned size,const layout& abi,bool entry) {
    const auto offset=base.displacement+displacement;
    if(base.source==origin::entry_stack&&size==4) {
        if(entry&&offset==4)return {origin::driver};
        if(!entry&&offset==8)return {origin::irp};
    }
    if(base.source==origin::irp&&size==abi.pointer_size) {
        if(offset==abi.irp_stack)return {origin::stack_location};
        if(offset==abi.irp_buffer)return {origin::system_buffer};
        if(offset==abi.irp_user)return {origin::user_buffer};
    }
    if(base.source==origin::stack_location) {
        if(offset==abi.control&&size==4)return {origin::ioctl};
        if(offset==abi.input&&size==4)return {origin::input_length};
        if(offset==abi.output&&size==4)return {origin::output_length};
        if(offset==abi.type3&&size==abi.pointer_size)return {origin::type3_buffer};
    }
    return {};
}
bool address_register(unsigned r,const layout& abi) {
    const auto index=reg_index(r);if(index<0)return false;
    constexpr unsigned full[]={X86_REG_RAX,X86_REG_RCX,X86_REG_RDX,X86_REG_RBX,X86_REG_RSP,X86_REG_RBP,X86_REG_RSI,X86_REG_RDI,
        X86_REG_R8,X86_REG_R9,X86_REG_R10,X86_REG_R11,X86_REG_R12,X86_REG_R13,X86_REG_R14,X86_REG_R15};
    return abi.pointer_size==8?r==full[index]:r!=full[index];
}
value memory_value(const cs_x86_op& op,const registers& regs,const layout& abi,bool entry) {
    if(op.type!=X86_OP_MEM||op.mem.index!=X86_REG_INVALID||op.mem.segment!=X86_REG_INVALID)return {};
    const auto i=reg_index(op.mem.base);if(i<0||!address_register(op.mem.base,abi))return {};
    return field_value(regs[i],op.mem.disp,op.size,abi,entry);
}
std::string digest(std::span<const std::uint8_t> raw) {
    std::array<unsigned char,EVP_MAX_MD_SIZE> bytes{};unsigned length=0;
    if(EVP_Digest(raw.data(),raw.size(),bytes.data(),&length,EVP_sha256(),nullptr)!=1)throw std::runtime_error("sha256_failed");
    std::ostringstream out;out<<std::hex<<std::setfill('0');for(unsigned i=0;i<length;++i)out<<std::setw(2)<<unsigned(bytes[i]);return out.str();
}
std::string code_hex(std::uint32_t n) {std::ostringstream out;out<<"0x"<<std::hex<<n;return out.str();}
const char* buffer_name(origin o) {return o==origin::system_buffer?"system_buffer":o==origin::user_buffer?"user_buffer":"type3_input_buffer";}
struct disassembler {
    csh handle{};cs_insn* instruction=nullptr;
    explicit disassembler(evoke_pe::architecture arch) {
        const auto isa=arch==evoke_pe::architecture::arm64?CS_ARCH_ARM64:CS_ARCH_X86;
        const auto mode=arch==evoke_pe::architecture::x86?CS_MODE_32:arch==evoke_pe::architecture::arm64?CS_MODE_ARM:CS_MODE_64;
        if(cs_open(isa,mode,&handle)!=CS_ERR_OK)throw std::runtime_error("disassembler_unavailable");
        if(cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK){cs_close(&handle);throw std::runtime_error("disassembler_detail_failed");}
        instruction=cs_malloc(handle);if(!instruction){cs_close(&handle);throw std::bad_alloc();}
    }
    ~disassembler(){cs_free(instruction,1);cs_close(&handle);}
};
struct analysis {
    const evoke_pe::image& image;
    layout abi;
    disassembler decoder;
    json roots=json::array(),ioctls=json::array(),lengths=json::array(),accesses=json::array(),paths=json::array();
    std::vector<dispatch_root> dispatches;
    std::set<std::tuple<unsigned,std::uint32_t,std::string>> root_keys;
    std::set<std::string> evidence_keys,path_keys;
    unsigned limit,count=0;bool truncated=false,indirect=false,undecodable=false;
    explicit analysis(const evoke_pe::image& im,unsigned n):image(im),abi(driver_layout(im.arch)),decoder(im.arch),limit(n){}
    value constant(std::uint64_t n) const {
        if(n>=image.preferred_base&&n-image.preferred_base<image.bytes.size())return {origin::image_address,static_cast<std::int64_t>(n-image.preferred_base)};
        return {origin::literal,static_cast<std::int64_t>(n)};
    }
    bool append(json& list,json entry) {
        const auto key=entry.dump();if(!evidence_keys.insert(key).second)return false;
        if(list.size()>=128){truncated=true;return false;}list.push_back(std::move(entry));return true;
    }
    void root(unsigned major,std::uint32_t rva,const std::string& evidence) {
        if(major>=28||!image.is_executable(rva)||!root_keys.emplace(major,rva,evidence).second)return;
        if(dispatches.size()>=64){truncated=true;return;}
        dispatches.push_back({major,rva,evidence});roots.push_back({{"major",major},{"rva",rva},{"evidence",evidence},
            {"role",major==14?"device_control":major==15?"internal_device_control":"other_dispatch"}});
    }
    void candidate(value v,std::uint32_t compared,std::uint32_t rva,const dispatch_root& root,const char* operation) {
        if(v.source==origin::ioctl) {
            const auto code=compared-static_cast<std::uint32_t>(v.displacement);
            static constexpr const char* methods[]={"buffered","in_direct","out_direct","neither"};
            append(ioctls,{{"code",code},{"code_hex",code_hex(code)},{"device_type",code>>16},{"function",(code>>2)&4095},
                {"method",methods[code&3]},{"access_bits",(code>>14)&3},{"comparison_rva",rva},{"dispatch_rva",root.rva},
                {"major",root.major},{"evidence","io_stack_location_dataflow"},{"dispatch_evidence",root.evidence},
                {"confidence","candidate"},{"operation",operation},{"accepted",false}});
        }else if(v.source==origin::input_length||v.source==origin::output_length) {
            append(lengths,{{"field",v.source==origin::input_length?"input_length":"output_length"},
                {"compared_value",compared},{"register_adjustment",v.displacement},{"comparison_rva",rva},
                {"dispatch_rva",root.rva},{"operation",operation},{"interpretation","comparison_only_not_a_proven_size_requirement"}});
        }
    }
    void walk(std::uint32_t start,bool entry,const dispatch_root& root) {
        if(image.arch==evoke_pe::architecture::arm64){walk_arm64(start,entry,root);return;}
        struct block {std::uint32_t rva;registers regs;};
        registers initial{};
        if(abi.pointer_size==4)initial[4]={origin::entry_stack};
        else {initial[1]={entry?origin::driver:origin::unknown};if(!entry)initial[2]={origin::irp};}
        std::deque<block> queue;queue.push_back({start,initial});
        std::set<std::pair<std::uint32_t,registers>> visited;
        auto enqueue=[&](std::uint64_t at,const registers& regs){if(at<=UINT32_MAX&&image.is_executable(static_cast<std::uint32_t>(at))) {
            if(queue.size()>=256){truncated=true;return;}queue.push_back({static_cast<std::uint32_t>(at),regs});}};
        while(!queue.empty()&&count<limit) {
            auto [pc,regs]=queue.front();queue.pop_front();
            while(image.is_executable(pc)&&count<limit) {
                if(!visited.emplace(pc,regs).second)break;
                const std::uint8_t* data=image.bytes.data()+pc;std::size_t size=std::min<std::size_t>(15,image.bytes.size()-pc);std::uint64_t address=pc;
                if(!cs_disasm_iter(decoder.handle,&data,&size,&address,decoder.instruction)){undecodable=true;break;}
                auto& ins=*decoder.instruction;const auto& x=ins.detail->x86;++count;
                bool executable=true;for(unsigned n=0;n<ins.size;++n)executable&=image.is_executable(pc+n);if(!executable)break;
                auto read=[&](const cs_x86_op& op)->value {
                    if(op.type==X86_OP_REG){const auto i=reg_index(op.reg);return i<0?value{}:regs[i];}
                    if(op.type==X86_OP_MEM)return memory_value(op,regs,abi,entry);
                    if(op.type==X86_OP_IMM)return constant(abi.pointer_size==4?static_cast<std::uint32_t>(op.imm):static_cast<std::uint64_t>(op.imm));
                    return {};
                };
                for(unsigned n=0;!entry&&n<x.op_count;++n)if(x.operands[n].type==X86_OP_MEM) {
                    const auto& op=x.operands[n];const auto i=reg_index(op.mem.base);
                    if(i>=0&&address_register(op.mem.base,abi)&&op.mem.index==X86_REG_INVALID&&op.mem.segment==X86_REG_INVALID) {
                        const auto v=regs[i];if(v.source==origin::system_buffer||v.source==origin::user_buffer||v.source==origin::type3_buffer)
                            append(accesses,{{"buffer",buffer_name(v.source)},{"offset",v.displacement+op.mem.disp},{"width",op.size},
                                {"read",bool(op.access&CS_AC_READ)},{"write",bool(op.access&CS_AC_WRITE)},
                                {"instruction_rva",pc},{"dispatch_rva",root.rva},{"evidence","pointer_dataflow"}});
                    }
                }
                if(!entry&&ins.id==X86_INS_CMP&&x.op_count==2) {
                    const auto right=read(x.operands[1]);if(right.source==origin::literal)
                        candidate(read(x.operands[0]),static_cast<std::uint32_t>(right.displacement),pc,root,"cmp");
                }
                value assigned{};int destination=-1;
                const auto stack_before=regs[4];
                if((ins.id==X86_INS_MOV||ins.id==X86_INS_MOVABS)&&x.op_count==2) {
                    assigned=read(x.operands[1]);
                    if(x.operands[0].type==X86_OP_REG) {
                        destination=reg_index(x.operands[0].reg);
                        if(pointer(assigned.source)&&x.operands[0].size!=abi.pointer_size)assigned={};
                    }
                    if(entry&&x.operands[0].type==X86_OP_MEM&&x.operands[0].size==abi.pointer_size&&x.operands[0].mem.index==X86_REG_INVALID&&address_register(x.operands[0].mem.base,abi)) {
                        const auto i=reg_index(x.operands[0].mem.base);const auto offset=i<0?-1:regs[i].displacement+x.operands[0].mem.disp;
                        if(i>=0&&regs[i].source==origin::driver&&offset>=abi.major_base&&offset<abi.major_base+28*abi.pointer_size&&(offset-abi.major_base)%abi.pointer_size==0&&assigned.source==origin::image_address)
                            this->root(static_cast<unsigned>((offset-abi.major_base)/abi.pointer_size),static_cast<std::uint32_t>(assigned.displacement),"static_driver_object_store");
                    }
                }else if(ins.id==X86_INS_LEA&&x.op_count==2&&x.operands[0].size==abi.pointer_size&&x.operands[1].type==X86_OP_MEM) {
                    destination=reg_index(x.operands[0].reg);const auto& m=x.operands[1].mem;
                    if(m.index==X86_REG_INVALID) {
                        if(m.base==X86_REG_RIP)assigned={origin::image_address,static_cast<std::int64_t>(address)+m.disp};
                        else if(m.base==X86_REG_INVALID&&abi.pointer_size==4)assigned=constant(static_cast<std::uint32_t>(m.disp));
                        else if(const auto i=reg_index(m.base);i>=0&&address_register(m.base,abi)&&pointer(regs[i].source)) {assigned=regs[i];assigned.displacement+=m.disp;}
                    }
                }else if((ins.id==X86_INS_ADD||ins.id==X86_INS_SUB)&&x.op_count==2&&x.operands[0].type==X86_OP_REG&&x.operands[1].type==X86_OP_IMM) {
                    destination=reg_index(x.operands[0].reg);if(destination>=0) {
                        assigned=regs[destination];const auto adjustment=ins.id==X86_INS_ADD?x.operands[1].imm:-x.operands[1].imm;
                        if(assigned.source==origin::ioctl||assigned.source==origin::input_length||assigned.source==origin::output_length)
                            assigned.displacement=static_cast<std::int32_t>(static_cast<std::uint32_t>(assigned.displacement)+static_cast<std::uint32_t>(adjustment));
                        else if(pointer(assigned.source)&&x.operands[0].size==abi.pointer_size)assigned.displacement+=adjustment;else assigned={};
                        // Only SUB immediately tested for equality supplies an equality candidate.
                        if(!entry&&ins.id==X86_INS_SUB&&address+1<image.bytes.size()&&
                            (image.bytes[address]==0x74||image.bytes[address]==0x75||
                                (image.bytes[address]==0x0f&&(image.bytes[address+1]==0x84||image.bytes[address+1]==0x85))))
                            candidate(assigned,0,pc,root,"sub_then_equality_branch");
                    }
                }
                cs_regs reads{},writes{};std::uint8_t nr=0,nw=0;
                if(cs_regs_access(decoder.handle,&ins,reads,&nr,writes,&nw)!=CS_ERR_OK)regs={};
                else for(unsigned i=0;i<nw;++i)if(const auto r=written_index(writes[i]);r>=0)regs[r]={};
                if(destination>=0)regs[destination]=assigned;
                if(abi.pointer_size==4&&stack_before.source==origin::entry_stack&&(ins.id==X86_INS_PUSH||ins.id==X86_INS_POP)) {
                    regs[4]=stack_before;regs[4].displacement+=ins.id==X86_INS_PUSH?-4:4;
                }
                const bool call=cs_insn_group(decoder.handle,&ins,CS_GRP_CALL),jump=cs_insn_group(decoder.handle,&ins,CS_GRP_JUMP);
                if(call||jump) {
                    auto target_regs=regs;if(call&&abi.pointer_size==4)target_regs[4]={};
                    if(x.op_count&&x.operands[0].type==X86_OP_IMM)enqueue(static_cast<std::uint64_t>(x.operands[0].imm),target_regs);else indirect=true;
                    if(call) {
                        for(auto i:{0,1,2,8,9,10,11})regs[i]={};
                        if(abi.pointer_size==4)regs[4]=stack_before;
                    }
                    if(jump&&ins.id==X86_INS_JMP)break;
                }
                if(cs_insn_group(decoder.handle,&ins,CS_GRP_RET)||cs_insn_group(decoder.handle,&ins,CS_GRP_IRET)||ins.id==X86_INS_INT3||ins.id==X86_INS_HLT)break;
                pc=static_cast<std::uint32_t>(address);
            }
        }
        if(count>=limit)truncated=true;
    }
    void walk_arm64(std::uint32_t start,bool entry,const dispatch_root& root) {
        struct block {std::uint32_t rva;registers regs;};
        registers initial{};initial[entry?0:1]={entry?origin::driver:origin::irp};
        std::deque<block> queue;queue.push_back({start,initial});std::set<std::pair<std::uint32_t,registers>> visited;
        auto enqueue=[&](std::uint64_t at,const registers& regs) {
            if(at<=UINT32_MAX&&at%4==0&&image.is_executable(static_cast<std::uint32_t>(at))) {
                if(queue.size()>=256){truncated=true;return;}queue.push_back({static_cast<std::uint32_t>(at),regs});
            }
        };
        while(!queue.empty()&&count<limit) {
            auto [pc,regs]=queue.front();queue.pop_front();
            while(pc%4==0&&image.is_executable(pc)&&count<limit) {
                if(!visited.emplace(pc,regs).second)break;
                const std::uint8_t* data=image.bytes.data()+pc;std::size_t size=std::min<std::size_t>(4,image.bytes.size()-pc);std::uint64_t address=pc;
                if(!cs_disasm_iter(decoder.handle,&data,&size,&address,decoder.instruction)){undecodable=true;break;}
                const auto& ins=*decoder.instruction;const auto& a=ins.detail->arm64;++count;
                bool executable=ins.size==4;for(unsigned i=0;i<ins.size;++i)executable&=image.is_executable(pc+i);if(!executable)break;
                auto read=[&](const cs_arm64_op& op)->value {
                    if(op.type==ARM64_OP_REG) {
                        if(op.reg==ARM64_REG_XZR||op.reg==ARM64_REG_WZR)return {origin::literal,0};
                        const auto i=arm_index(op.reg);if(i<0||op.ext!=ARM64_EXT_INVALID||op.shift.value)return {};
                        auto v=regs[i];if(pointer(v.source)&&arm_width(op.reg)!=8)return {};return v;
                    }
                    if(op.type==ARM64_OP_IMM) {
                        if(op.shift.type!=ARM64_SFT_INVALID&&op.shift.type!=ARM64_SFT_LSL)return {};
                        if(op.shift.value>=64)return {};
                        return {origin::literal,static_cast<std::int64_t>(static_cast<std::uint64_t>(op.imm)<<op.shift.value)};
                    }
                    return {};
                };
                if(!entry&&ins.id==ARM64_INS_CMP&&a.op_count==2) {
                    const auto right=read(a.operands[1]);if(right.source==origin::literal)
                        candidate(read(a.operands[0]),static_cast<std::uint32_t>(right.displacement),pc,root,"cmp");
                }
                if(!entry&&(ins.id==ARM64_INS_CBZ||ins.id==ARM64_INS_CBNZ)&&a.op_count)
                    candidate(read(a.operands[0]),0,pc,root,"compare_and_branch_zero");
                value assigned{};int destination=-1;
                if(a.op_count&&a.operands[0].type==ARM64_OP_REG)destination=arm_index(a.operands[0].reg);
                bool modeled=false;
                if((ins.id==ARM64_INS_MOV||ins.id==ARM64_INS_MOVZ||ins.id==ARM64_INS_MOVN)&&a.op_count==2) {
                    assigned=read(a.operands[1]);modeled=true;
                    if(ins.id==ARM64_INS_MOVN&&assigned.source==origin::literal)assigned.displacement=~assigned.displacement;
                    if(assigned.source==origin::literal) {
                        auto bits=static_cast<std::uint64_t>(assigned.displacement);if(arm_width(a.operands[0].reg)==4)bits&=UINT32_MAX;
                        assigned=constant(bits);
                    }
                }else if(ins.id==ARM64_INS_MOVK&&a.op_count==2&&destination>=0) {
                    const auto old=regs[destination];const auto& part=a.operands[1];
                    if((old.source==origin::literal||old.source==origin::image_address)&&part.type==ARM64_OP_IMM&&part.shift.value<64) {
                        const auto old_bits=old.source==origin::image_address?image.preferred_base+old.displacement:static_cast<std::uint64_t>(old.displacement);
                        const auto mask=std::uint64_t(0xffff)<<part.shift.value;
                        auto bits=(old_bits&~mask)|((static_cast<std::uint64_t>(part.imm)<<part.shift.value)&mask);
                        if(arm_width(a.operands[0].reg)==4)bits&=UINT32_MAX;assigned=constant(bits);
                    }modeled=true;
                }else if((ins.id==ARM64_INS_ADR||ins.id==ARM64_INS_ADRP)&&a.op_count==2&&a.operands[1].type==ARM64_OP_IMM) {
                    assigned={origin::image_address,a.operands[1].imm};modeled=true;
                }else if((ins.id==ARM64_INS_ADD||ins.id==ARM64_INS_ADDS||ins.id==ARM64_INS_SUB||ins.id==ARM64_INS_SUBS)&&a.op_count==3) {
                    assigned=read(a.operands[1]);const auto delta=read(a.operands[2]);modeled=true;
                    if(delta.source==origin::literal&&delta.displacement>=0&&delta.displacement<=0xffffff) {
                        const auto adjustment=(ins.id==ARM64_INS_SUB||ins.id==ARM64_INS_SUBS)?-delta.displacement:delta.displacement;
                        if(assigned.source==origin::ioctl||assigned.source==origin::input_length||assigned.source==origin::output_length)
                            assigned.displacement=static_cast<std::int32_t>(static_cast<std::uint32_t>(assigned.displacement)+static_cast<std::uint32_t>(adjustment));
                        else if(pointer(assigned.source))assigned.displacement+=adjustment;
                        else if(assigned.source==origin::literal)assigned=constant(static_cast<std::uint64_t>(assigned.displacement)+static_cast<std::uint64_t>(adjustment));
                        else assigned={};
                    }else assigned={};
                }
                bool load=false,store=false;unsigned width=0;
                switch(ins.id) {
                case ARM64_INS_LDR:case ARM64_INS_LDUR:load=true;break;
                case ARM64_INS_LDRB:case ARM64_INS_LDURB:load=true;width=1;break;
                case ARM64_INS_LDRH:case ARM64_INS_LDURH:load=true;width=2;break;
                case ARM64_INS_LDRSW:case ARM64_INS_LDURSW:load=true;width=4;break;
                case ARM64_INS_STR:case ARM64_INS_STUR:store=true;break;
                case ARM64_INS_STRB:case ARM64_INS_STURB:store=true;width=1;break;
                case ARM64_INS_STRH:case ARM64_INS_STURH:store=true;width=2;break;
                default:break;
                }
                if((load||store)&&a.op_count>=2&&a.operands[0].type==ARM64_OP_REG) {
                    if(!width)width=arm_width(a.operands[0].reg);
                    if(load){modeled=true;assigned={};}
                    const auto& operand=a.operands[1];const auto i=operand.type==ARM64_OP_MEM?arm_index(operand.mem.base):-1;
                    if(i>=0&&operand.mem.index==ARM64_REG_INVALID&&!a.writeback&&arm_width(operand.mem.base)==8) {
                        const auto base=regs[i];const auto offset=base.displacement+operand.mem.disp;
                        if(load)assigned=field_value(base,operand.mem.disp,width,abi,entry);
                        if(entry&&store&&width==8&&base.source==origin::driver&&offset>=abi.major_base&&offset<abi.major_base+28*8&&(offset-abi.major_base)%8==0) {
                            const auto target=read(a.operands[0]);if(target.source==origin::image_address)
                                this->root(static_cast<unsigned>((offset-abi.major_base)/8),static_cast<std::uint32_t>(target.displacement),"static_driver_object_store");
                        }
                        if(!entry&&(base.source==origin::system_buffer||base.source==origin::user_buffer||base.source==origin::type3_buffer))
                            append(accesses,{{"buffer",buffer_name(base.source)},{"offset",offset},{"width",width},{"read",load},{"write",store},
                                {"instruction_rva",pc},{"dispatch_rva",root.rva},{"evidence","pointer_dataflow"}});
                    }else if(load&&operand.type==ARM64_OP_IMM&&operand.imm>=0&&static_cast<std::uint64_t>(operand.imm)+width<=image.bytes.size()) {
                        if(width==4)assigned=constant(image.read<std::uint32_t>(operand.imm));
                        if(width==8)assigned=constant(image.read<std::uint64_t>(operand.imm));
                    }
                }
                cs_regs reads{},writes{};std::uint8_t nr=0,nw=0;
                if(cs_regs_access(decoder.handle,&ins,reads,&nr,writes,&nw)!=CS_ERR_OK)regs={};
                else for(unsigned i=0;i<nw;++i)if(const auto r=arm_index(writes[i]);r>=0)regs[r]={};
                if(destination>=0&&modeled) {
                    if(pointer(assigned.source)&&arm_width(a.operands[0].reg)!=8)assigned={};
                    regs[destination]=assigned;
                }
                const bool call=cs_insn_group(decoder.handle,&ins,CS_GRP_CALL),jump=cs_insn_group(decoder.handle,&ins,CS_GRP_JUMP);
                if(call||jump) {
                    bool direct=false;for(int i=a.op_count-1;i>=0;--i)if(a.operands[i].type==ARM64_OP_IMM){enqueue(static_cast<std::uint64_t>(a.operands[i].imm),regs);direct=true;break;}
                    if(!direct)indirect=true;
                    if(call)for(unsigned i=0;i<=18;++i)regs[i]={};
                    if(jump&&(ins.id==ARM64_INS_BR||(ins.id==ARM64_INS_B&&(a.cc==ARM64_CC_INVALID||a.cc==ARM64_CC_AL))))break;
                }
                if(cs_insn_group(decoder.handle,&ins,CS_GRP_RET)||ins.id==ARM64_INS_BRK||ins.id==ARM64_INS_HLT||
                    ins.id==ARM64_INS_SVC||ins.id==ARM64_INS_HVC||ins.id==ARM64_INS_SMC)break;
                pc=static_cast<std::uint32_t>(address);
            }
        }
        if(count>=limit)truncated=true;
    }
    void strings() {
        auto add=[&](std::size_t at,const std::string& s,const char* encoding) {
            if(!(s.starts_with("\\Device\\")||s.starts_with("\\DosDevices\\")||s.starts_with("\\??\\")||s.starts_with("\\\\.\\")))return;
            if(!path_keys.insert(s).second)return;if(paths.size()>=64){truncated=true;return;}
            paths.push_back({{"value",s},{"rva",at},{"encoding",encoding},{"evidence","embedded_string"},{"confidence","hint"}});
        };
        for(unsigned stride:{1u,2u})for(unsigned alignment=0;alignment<stride;++alignment) {
            for(std::size_t p=alignment;p<image.bytes.size();) {
                const auto start=p;std::string s;bool overlong=false;
                while(p+stride<=image.bytes.size()&&image.bytes[p]>=32&&image.bytes[p]<=126&&(stride==1||image.bytes[p+1]==0)) {
                    if(s.size()<512)s+=static_cast<char>(image.bytes[p]);else overlong=true;p+=stride;
                }
                if(!overlong&&p+stride<=image.bytes.size()&&image.bytes[p]==0&&(stride==1||image.bytes[p+1]==0))add(start,s,stride==1?"ascii":"utf16le_ascii_subset");
                p+=stride;
            }
        }
    }
};
}
json analyze(const evoke_pe::image& image,std::span<const std::uint8_t> raw,const std::vector<dispatch_root>& observed,unsigned limit) {
    if(!limit||limit>32768)throw std::invalid_argument("invalid_analysis_instruction_limit");
    analysis a(image,limit);for(const auto& r:observed)a.root(r.major,r.rva,r.evidence);
    a.walk(image.entry,true,{0,image.entry,"pe_entry"});
    // Roots are copied: analysis may discover additional registrations inside helper functions.
    const auto roots=a.dispatches;std::set<std::pair<unsigned,std::uint32_t>> analyzed;
    for(const auto& r:roots)if((r.major==14||r.major==15)&&analyzed.emplace(r.major,r.rva).second)a.walk(r.rva,false,r);
    a.strings();
    const auto abi=driver_layout(image.arch);
    return {{"source_sha256",digest(raw)},{"architecture",evoke_pe::architecture_name(image.arch)},{"pointer_size",image.pointer_size},{"entry_rva",image.entry},{"dispatch_routines",a.roots},
        {"target_abi",image.arch==evoke_pe::architecture::x86?"windows_x86_stdcall":image.arch==evoke_pe::architecture::arm64?"windows_arm64":"windows_x64"},
        {"layout",{{"driver_major_function_offset",abi.major_base},{"irp_current_stack_location_offset",abi.irp_stack},
            {"irp_system_buffer_offset",abi.irp_buffer},{"irp_user_buffer_offset",abi.irp_user},
            {"io_stack_control_code_offset",abi.control},{"io_stack_input_length_offset",abi.input},{"io_stack_output_length_offset",abi.output}}},
        {"ioctl_candidates",a.ioctls},{"length_comparisons",a.lengths},{"buffer_accesses",a.accesses},{"device_path_hints",a.paths},
        {"analysis_instructions",a.count},{"analysis_instruction_limit",limit},{"analysis_truncated",a.truncated},
        {"indirect_control_flow_seen",a.indirect},{"undecodable_code_seen",a.undecodable},
        {"buffer_layout_complete",false},{"live_adapter_ready",false},{"discovery_status","partial"},
        {"unresolved",json::array({"Operation semantics and nested pointer layouts require an authoritative contract or further validation.",
            "Branches are explored without proving feasibility; compared IOCTL values are candidates, not confirmed accepted operations.",
            "Indirect jump tables, stack spills, framework-generated dispatch and hardware-dependent initialization may remain unresolved."})}};
}
}
