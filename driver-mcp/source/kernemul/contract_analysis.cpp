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
    system_buffer, user_buffer, type3_buffer, image_address };
struct value { origin source{}; std::int64_t displacement=0; auto operator<=>(const value&) const = default; };
using registers = std::array<value,16>;
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
bool pointer(origin o) {return o==origin::driver||o==origin::irp||o==origin::stack_location||
    o==origin::system_buffer||o==origin::user_buffer||o==origin::type3_buffer||o==origin::image_address;}
value memory_value(const cs_x86_op& op,const registers& regs) {
    if(op.type!=X86_OP_MEM||op.mem.index!=X86_REG_INVALID||op.mem.segment!=X86_REG_INVALID)return {};
    const auto i=reg_index(op.mem.base);if(i<0)return {};
    const auto base=regs[i];const auto offset=base.displacement+op.mem.disp;
    if(base.source==origin::irp&&op.size==8) {
        if(offset==0xb8)return {origin::stack_location};
        if(offset==0x18)return {origin::system_buffer};
        if(offset==0x70)return {origin::user_buffer};
    }
    if(base.source==origin::stack_location) {
        if(offset==0x18&&op.size==4)return {origin::ioctl};
        if(offset==0x10&&op.size==4)return {origin::input_length};
        if(offset==0x08&&op.size==4)return {origin::output_length};
        if(offset==0x20&&op.size==8)return {origin::type3_buffer};
    }
    return {};
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
    disassembler() {
        if(cs_open(CS_ARCH_X86,CS_MODE_64,&handle)!=CS_ERR_OK)throw std::runtime_error("disassembler_unavailable");
        if(cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK){cs_close(&handle);throw std::runtime_error("disassembler_detail_failed");}
        instruction=cs_malloc(handle);if(!instruction){cs_close(&handle);throw std::bad_alloc();}
    }
    ~disassembler(){cs_free(instruction,1);cs_close(&handle);}
};
struct analysis {
    const evoke_pe::image& image;
    disassembler decoder;
    json roots=json::array(),ioctls=json::array(),lengths=json::array(),accesses=json::array(),paths=json::array();
    std::vector<dispatch_root> dispatches;
    std::set<std::tuple<unsigned,std::uint32_t,std::string>> root_keys;
    std::set<std::string> evidence_keys,path_keys;
    unsigned limit,count=0;bool truncated=false,indirect=false,undecodable=false;
    explicit analysis(const evoke_pe::image& im,unsigned n):image(im),limit(n){}
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
        struct block {std::uint32_t rva;registers regs;};
        registers initial{};initial[1]={entry?origin::driver:origin::unknown};if(!entry)initial[2]={origin::irp};
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
                    if(op.type==X86_OP_MEM)return memory_value(op,regs);
                    if(op.type==X86_OP_IMM&&static_cast<std::uint64_t>(op.imm)>=image.preferred_base&&
                        static_cast<std::uint64_t>(op.imm)-image.preferred_base<image.bytes.size())return {origin::image_address,static_cast<std::int64_t>(static_cast<std::uint64_t>(op.imm)-image.preferred_base)};
                    return {};
                };
                for(unsigned n=0;!entry&&n<x.op_count;++n)if(x.operands[n].type==X86_OP_MEM) {
                    const auto& op=x.operands[n];const auto i=reg_index(op.mem.base);
                    if(i>=0&&op.mem.index==X86_REG_INVALID&&op.mem.segment==X86_REG_INVALID) {
                        const auto v=regs[i];if(v.source==origin::system_buffer||v.source==origin::user_buffer||v.source==origin::type3_buffer)
                            append(accesses,{{"buffer",buffer_name(v.source)},{"offset",v.displacement+op.mem.disp},{"width",op.size},
                                {"read",bool(op.access&CS_AC_READ)},{"write",bool(op.access&CS_AC_WRITE)},
                                {"instruction_rva",pc},{"dispatch_rva",root.rva},{"evidence","pointer_dataflow"}});
                    }
                }
                if(!entry&&ins.id==X86_INS_CMP&&x.op_count==2&&x.operands[1].type==X86_OP_IMM)
                    candidate(read(x.operands[0]),static_cast<std::uint32_t>(x.operands[1].imm),pc,root,"cmp");
                value assigned{};int destination=-1;
                if((ins.id==X86_INS_MOV||ins.id==X86_INS_MOVABS)&&x.op_count==2) {
                    assigned=read(x.operands[1]);
                    if(x.operands[0].type==X86_OP_REG) {
                        destination=reg_index(x.operands[0].reg);
                        if(pointer(assigned.source)&&x.operands[0].size!=8)assigned={};
                    }
                    if(entry&&x.operands[0].type==X86_OP_MEM&&x.operands[0].size==8&&x.operands[0].mem.index==X86_REG_INVALID) {
                        const auto i=reg_index(x.operands[0].mem.base);const auto offset=i<0?-1:regs[i].displacement+x.operands[0].mem.disp;
                        if(i>=0&&regs[i].source==origin::driver&&offset>=0x70&&offset<0x150&&offset%8==0&&assigned.source==origin::image_address)
                            this->root(static_cast<unsigned>((offset-0x70)/8),static_cast<std::uint32_t>(assigned.displacement),"static_driver_object_store");
                    }
                }else if(ins.id==X86_INS_LEA&&x.op_count==2&&x.operands[0].size==8&&x.operands[1].type==X86_OP_MEM) {
                    destination=reg_index(x.operands[0].reg);const auto& m=x.operands[1].mem;
                    if(m.index==X86_REG_INVALID) {
                        if(m.base==X86_REG_RIP)assigned={origin::image_address,static_cast<std::int64_t>(address)+m.disp};
                        else if(const auto i=reg_index(m.base);i>=0&&pointer(regs[i].source)) {assigned=regs[i];assigned.displacement+=m.disp;}
                    }
                }else if((ins.id==X86_INS_ADD||ins.id==X86_INS_SUB)&&x.op_count==2&&x.operands[0].type==X86_OP_REG&&x.operands[1].type==X86_OP_IMM) {
                    destination=reg_index(x.operands[0].reg);if(destination>=0) {
                        assigned=regs[destination];const auto adjustment=ins.id==X86_INS_ADD?x.operands[1].imm:-x.operands[1].imm;
                        if(assigned.source==origin::ioctl||assigned.source==origin::input_length||assigned.source==origin::output_length)
                            assigned.displacement=static_cast<std::int32_t>(static_cast<std::uint32_t>(assigned.displacement)+static_cast<std::uint32_t>(adjustment));
                        else if(pointer(assigned.source)&&x.operands[0].size==8)assigned.displacement+=adjustment;else assigned={};
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
                const bool call=cs_insn_group(decoder.handle,&ins,CS_GRP_CALL),jump=cs_insn_group(decoder.handle,&ins,CS_GRP_JUMP);
                if(call||jump) {
                    if(x.op_count&&x.operands[0].type==X86_OP_IMM)enqueue(static_cast<std::uint64_t>(x.operands[0].imm),regs);else indirect=true;
                    if(call)for(auto i:{0,1,2,8,9,10,11})regs[i]={};
                    if(jump&&ins.id==X86_INS_JMP)break;
                }
                if(cs_insn_group(decoder.handle,&ins,CS_GRP_RET)||cs_insn_group(decoder.handle,&ins,CS_GRP_IRET)||ins.id==X86_INS_INT3||ins.id==X86_INS_HLT)break;
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
    return {{"source_sha256",digest(raw)},{"architecture","amd64"},{"entry_rva",image.entry},{"dispatch_routines",a.roots},
        {"ioctl_candidates",a.ioctls},{"length_comparisons",a.lengths},{"buffer_accesses",a.accesses},{"device_path_hints",a.paths},
        {"analysis_instructions",a.count},{"analysis_instruction_limit",limit},{"analysis_truncated",a.truncated},
        {"indirect_control_flow_seen",a.indirect},{"undecodable_code_seen",a.undecodable},
        {"buffer_layout_complete",false},{"live_adapter_ready",false},{"discovery_status","partial"},
        {"unresolved",json::array({"Operation semantics and nested pointer layouts require an authoritative contract or further validation.",
            "Branches are explored without proving feasibility; compared IOCTL values are candidates, not confirmed accepted operations.",
            "Indirect jump tables, stack spills, framework-generated dispatch and hardware-dependent initialization may remain unresolved."})}};
}
}
