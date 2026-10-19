#pragma once
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
namespace evoke_pe {
struct section {std::uint32_t rva,size,flags;};
struct import {std::string module,name;std::uint32_t slot;};
class image {
    template<class T> static T get(std::span<const std::uint8_t> data,std::size_t at) {
        if(at>data.size()||data.size()-at<sizeof(T))throw std::invalid_argument("pe_truncated_structure");
        T value{};std::memcpy(&value,data.data()+at,sizeof(T));return value;
    }
    void range(std::uint64_t at,std::uint64_t size) const {
        if(at>bytes.size()||size>bytes.size()-at)throw std::invalid_argument("pe_rva_out_of_bounds");
    }
    std::pair<std::uint32_t,std::uint32_t> directory(unsigned index) const {
        if(index>=directories_)return {};const auto at=optional_+112+index*8;
        return {get<std::uint32_t>(bytes,at),get<std::uint32_t>(bytes,at+4)};
    }
    std::size_t optional_=0;unsigned directories_=0;
public:
    std::vector<std::uint8_t> bytes;std::vector<section> sections;
    std::uint64_t preferred_base=0;std::uint32_t entry=0,header_size=0;
    explicit image(std::span<const std::uint8_t> raw,bool executable=true) {
        if(raw.size()>2*1024*1024||raw.size()<64||get<std::uint16_t>(raw,0)!=0x5a4d)throw std::invalid_argument("invalid_pe_dos_header");
        const auto nt=get<std::uint32_t>(raw,60);
        if(get<std::uint32_t>(raw,nt)!=0x4550||get<std::uint16_t>(raw,std::size_t(nt)+4)!=0x8664)throw std::invalid_argument("pe_requires_amd64");
        const auto count=get<std::uint16_t>(raw,std::size_t(nt)+6),optional_size=get<std::uint16_t>(raw,std::size_t(nt)+20);
        optional_=std::size_t(nt)+24;
        if(!count||count>32||optional_size<112||optional_>raw.size()||optional_size>raw.size()-optional_||get<std::uint16_t>(raw,optional_)!=0x20b)
            throw std::invalid_argument("invalid_pe_optional_header");
        directories_=get<std::uint32_t>(raw,optional_+108);
        if(directories_>16||112+directories_*8>optional_size)throw std::invalid_argument("invalid_pe_directories");
        const auto size=get<std::uint32_t>(raw,optional_+56);header_size=get<std::uint32_t>(raw,optional_+60);
        const auto alignment=get<std::uint32_t>(raw,optional_+32);
        if(!size||size>16*1024*1024||size%4096||!header_size||header_size>size||header_size>raw.size()||alignment<4096||(alignment&(alignment-1)))
            throw std::invalid_argument("invalid_pe_image_size_or_alignment");
        const auto table=optional_+optional_size;
        if(table>header_size||std::size_t(count)*40>header_size-table)throw std::invalid_argument("invalid_pe_section_table");
        preferred_base=get<std::uint64_t>(raw,optional_+24);entry=get<std::uint32_t>(raw,optional_+16);
        bytes.resize(size);std::copy_n(raw.begin(),header_size,bytes.begin());
        for(unsigned i=0;i<count;++i) {
            const auto p=table+i*40;const auto va=get<std::uint32_t>(raw,p+12),virtual_size=get<std::uint32_t>(raw,p+8);
            const auto raw_size=get<std::uint32_t>(raw,p+16),raw_at=get<std::uint32_t>(raw,p+20),flags=get<std::uint32_t>(raw,p+36);
            const auto extent=std::max(raw_size,virtual_size);
            if(!extent)continue;
            range(va,extent);
            if(va%alignment||va<(header_size+4095u)/4096u*4096u||raw_at>raw.size()||raw_size>raw.size()-raw_at)
                throw std::invalid_argument("invalid_pe_section_range");
            const auto rounded=(extent+4095u)&~4095u;
            for(const auto& previous:sections)if(va<std::uint64_t(previous.rva)+previous.size&&previous.rva<std::uint64_t(va)+rounded)
                throw std::invalid_argument("overlapping_pe_sections");
            sections.push_back({va,rounded,flags});std::copy_n(raw.begin()+raw_at,raw_size,bytes.begin()+va);
        }
        for(unsigned i=0;i<directories_;++i) {const auto [at,length]=directory(i);if(i!=4&&length)range(at,length);}
        if(executable) {
            if(!is_executable(entry))throw std::invalid_argument("pe_entry_not_executable");
            for(auto i:{9u,13u,14u})if(directory(i).second)throw std::invalid_argument("pe_tls_delay_imports_or_clr_unsupported");
        }
    }
    bool is_executable(std::uint32_t rva) const {
        for(const auto& s:sections)if(rva>=s.rva&&rva-s.rva<s.size&&(s.flags&0x20000000))return true;return false;
    }
    template<class T> T read(std::uint64_t at) const {range(at,sizeof(T));return get<T>(bytes,static_cast<std::size_t>(at));}
    template<class T> void write(std::uint64_t at,T value) {range(at,sizeof(T));std::memcpy(bytes.data()+at,&value,sizeof(T));}
    std::string string(std::uint32_t at) const {
        std::string text;
        for(unsigned i=0;i<256;++i){const auto c=read<std::uint8_t>(std::uint64_t(at)+i);if(!c)return text;if(c<32||c>126)throw std::invalid_argument("invalid_pe_symbol");text+=static_cast<char>(c);}
        throw std::invalid_argument("pe_symbol_too_long");
    }
    std::vector<import> imports() const {
        std::vector<import> out;const auto [at,size]=directory(1);if(!size)return out;
        for(std::uint32_t off=0;off+20<=size;off+=20) {
            const auto p=std::uint64_t(at)+off;const auto lookup=read<std::uint32_t>(p),name=read<std::uint32_t>(p+12),iat=read<std::uint32_t>(p+16);
            if(!lookup&&!name&&!iat)return out;
            if(!name||!iat)throw std::invalid_argument("invalid_pe_import_descriptor");
            const auto module=string(name);bool ended=false;
            for(unsigned i=0;i<512;++i) {
                const auto thunk=read<std::uint64_t>(std::uint64_t(lookup?lookup:iat)+i*8);
                if(!thunk){ended=true;break;}
                if(thunk>>63)throw std::invalid_argument("pe_ordinal_import_unsupported");
                if(thunk>UINT32_MAX-2)throw std::invalid_argument("invalid_pe_import_name");
                range(std::uint64_t(iat)+i*8,8);
                out.push_back({module,string(static_cast<std::uint32_t>(thunk)+2),iat+i*8});
                if(out.size()>512)throw std::invalid_argument("too_many_pe_imports");
            }
            if(!ended)throw std::invalid_argument("unterminated_pe_thunks");
        }
        throw std::invalid_argument("unterminated_pe_import_descriptors");
    }
    struct exported {std::string name;std::uint32_t rva;};
    std::vector<exported> exports() const {
        std::vector<exported> out;const auto [at,size]=directory(0);if(!size)return out;
        if(size<40)throw std::invalid_argument("invalid_pe_exports");
        const auto functions=read<std::uint32_t>(at+20),names=read<std::uint32_t>(at+24);
        if(functions>65536||names>65536)throw std::invalid_argument("too_many_pe_exports");
        const auto table=read<std::uint32_t>(at+28),name_table=read<std::uint32_t>(at+32),ordinals=read<std::uint32_t>(at+36);
        range(table,std::uint64_t(functions)*4);range(name_table,std::uint64_t(names)*4);range(ordinals,std::uint64_t(names)*2);
        for(unsigned i=0;i<names;++i) {
            const auto ordinal=read<std::uint16_t>(std::uint64_t(ordinals)+i*2);if(ordinal>=functions)throw std::invalid_argument("invalid_pe_export_ordinal");
            const auto rva=read<std::uint32_t>(std::uint64_t(table)+ordinal*4);range(rva,1);
            if(rva>=at&&std::uint64_t(rva)<std::uint64_t(at)+size)continue;
            out.push_back({string(read<std::uint32_t>(std::uint64_t(name_table)+i*4)),rva});
        }return out;
    }
    void relocate(std::uint64_t base) {
        const auto [at,size]=directory(5);const auto delta=base-preferred_base;
        if(delta&&!size)throw std::invalid_argument("pe_relocations_required");
        for(std::uint32_t off=0;off<size;) {
            if(size-off<8)throw std::invalid_argument("invalid_pe_relocation_block");
            const auto page=read<std::uint32_t>(std::uint64_t(at)+off),block=read<std::uint32_t>(std::uint64_t(at)+off+4);
            if(block<8||block>size-off||block%2)throw std::invalid_argument("invalid_pe_relocation_block");
            for(unsigned i=8;i<block;i+=2) {
                const auto fix=read<std::uint16_t>(std::uint64_t(at)+off+i);const auto type=fix>>12;
                if(!type)continue;if(type!=10)throw std::invalid_argument("unsupported_pe_relocation_type");
                const auto target=std::uint64_t(page)+(fix&4095);write(target,read<std::uint64_t>(target)+delta);
            }off+=block;
        }
        write<std::uint64_t>(optional_+24,base);
    }
};
}
