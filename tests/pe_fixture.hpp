#pragma once
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>
namespace pe_fixture {
using bytes=std::vector<std::uint8_t>;
template<class T> void put(bytes& data,std::size_t at,T value){std::memcpy(data.data()+at,&value,sizeof(value));}
inline std::string hex(const bytes& data){constexpr char digits[]="0123456789abcdef";std::string out;for(auto v:data){out+=digits[v>>4];out+=digits[v&15];}return out;}
inline void text(bytes& data,std::size_t at,const std::string& value){std::copy(value.begin(),value.end(),data.begin()+at);data[at+value.size()]=0;}
inline bytes image(const bytes& code) {
    bytes b(0x800);put<std::uint16_t>(b,0,0x5a4d);put<std::uint32_t>(b,60,0x80);put<std::uint32_t>(b,0x80,0x4550);
    put<std::uint16_t>(b,0x84,0x8664);put<std::uint16_t>(b,0x86,2);put<std::uint16_t>(b,0x94,240);put<std::uint16_t>(b,0x96,0x22);
    put<std::uint16_t>(b,0x98,0x20b);put<std::uint32_t>(b,0xa8,0x1000);put<std::uint64_t>(b,0xb0,0x140000000ULL);
    put<std::uint32_t>(b,0xb8,4096);put<std::uint32_t>(b,0xbc,512);put<std::uint32_t>(b,0xd0,0x3000);put<std::uint32_t>(b,0xd4,0x200);
    put<std::uint16_t>(b,0xdc,1);put<std::uint32_t>(b,0x104,16);
    text(b,0x188,".text");put<std::uint32_t>(b,0x190,0x200);put<std::uint32_t>(b,0x194,0x1000);put<std::uint32_t>(b,0x198,0x200);put<std::uint32_t>(b,0x19c,0x200);put<std::uint32_t>(b,0x1ac,0x60000020);
    text(b,0x1b0,".data");put<std::uint32_t>(b,0x1b8,0x1000);put<std::uint32_t>(b,0x1bc,0x2000);put<std::uint32_t>(b,0x1c0,0x400);put<std::uint32_t>(b,0x1c4,0x400);put<std::uint32_t>(b,0x1d4,0xc0000040);
    std::copy(code.begin(),code.end(),b.begin()+0x200);return b;
}
inline void imported(bytes& b,const std::string& module,const std::string& name) {
    put<std::uint32_t>(b,0x110,0x2100);put<std::uint32_t>(b,0x114,40);
    put<std::uint32_t>(b,0x500,0x2180);put<std::uint32_t>(b,0x50c,0x2140);put<std::uint32_t>(b,0x510,0x21a0);
    text(b,0x540,module);put<std::uint64_t>(b,0x580,0x21c0);put<std::uint64_t>(b,0x5a0,0x21c0);text(b,0x5c2,name);
}
inline bytes syscall(unsigned id=0x77) {
    auto b=image({0x48,0x8d,0x0d,0xf9,0x0f,0,0,0x4c,0x8b,0xd1,0xb8,0,0,0,0,0x0f,0x05,0xc3});put<std::uint32_t>(b,0x20b,id);return b;
}
inline bytes stubs() {
    auto b=image({0x4c,0x8b,0xd1,0xb8,0x77,0,0,0,0x0f,0x05,0xc3});
    put<std::uint32_t>(b,0x108,0x2100);put<std::uint32_t>(b,0x10c,0x80);
    put<std::uint32_t>(b,0x510,1);put<std::uint32_t>(b,0x514,1);put<std::uint32_t>(b,0x518,1);
    put<std::uint32_t>(b,0x51c,0x2140);put<std::uint32_t>(b,0x520,0x2148);put<std::uint32_t>(b,0x524,0x2150);
    put<std::uint32_t>(b,0x540,0x1000);put<std::uint32_t>(b,0x548,0x2160);text(b,0x560,"NtQuerySystemTime");return b;
}
}
