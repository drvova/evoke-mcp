#pragma once
#include "pe_fixture.hpp"
namespace contract_fixture {
inline pe_fixture::bytes driver(bool indexed=false) {
    auto b=pe_fixture::image(indexed?pe_fixture::bytes{
        0x4c,0x8d,0x05,0x39,0,0,0, 0xb8,14,0,0,0, 0x4c,0x89,0x44,0xc1,0x70, 0x31,0xc0,0xc3}:
        pe_fixture::bytes{0x48,0x8d,0x05,0x39,0,0,0,0x48,0x89,0x81,0xe0,0,0,0,0x31,0xc0,0xc3});
    const pe_fixture::bytes handler={
        0x4c,0x8b,0x82,0xb8,0,0,0,       // r8 = Irp->Tail.Overlay.CurrentStackLocation
        0x41,0x8b,0x40,0x18,              // eax = stack->Parameters.DeviceIoControl.IoControlCode
        0x3d,0x04,0x20,0x22,0,            // cmp eax, CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,...)
        0x75,0x0d,                       // explore both paths, without proving acceptance
        0x41,0x83,0x78,0x10,0x10,         // cmp InputBufferLength,16
        0x4c,0x8b,0x4a,0x18,              // r9 = Irp->AssociatedIrp.SystemBuffer
        0x49,0x8b,0x41,0x08,              // read 8 bytes at buffer+8
        0x41,0x89,0x41,0x10,              // write 4 bytes at buffer+16
        0xb9,0x08,0x20,0x22,0,            // unrelated immediate must not become an IOCTL
        0x31,0xc0,0xc3};
    std::copy(handler.begin(),handler.end(),b.begin()+0x240);
    pe_fixture::text(b,0x400,"\\Device\\ContractFixture");
    const std::string link="\\DosDevices\\ContractFixture";
    for(std::size_t i=0;i<link.size();++i)b[0x440+i*2]=static_cast<std::uint8_t>(link[i]);
    return b;
}
inline pe_fixture::bytes symbolic_link() {
    // DriverEntry calls the original IoCreateSymbolicLink model with real guest UNICODE_STRINGs.
    auto b=pe_fixture::image({0x48,0x83,0xec,0x28,0x48,0x8d,0x0d,0xf5,0x0f,0,0,
        0x48,0x8d,0x15,0xfe,0x0f,0,0,0xff,0x15,0x88,0x11,0,0,0x48,0x83,0xc4,0x28,0x31,0xc0,0xc3});
    pe_fixture::imported(b,"ntoskrnl.exe","IoCreateSymbolicLink");
    auto string=[&](std::size_t object,std::size_t data,const std::string& value) {
        pe_fixture::put<std::uint16_t>(b,object,static_cast<std::uint16_t>(value.size()*2));
        pe_fixture::put<std::uint16_t>(b,object+2,static_cast<std::uint16_t>(value.size()*2+2));
        pe_fixture::put<std::uint64_t>(b,object+8,0x140000000ULL+(data-0x400)+0x2000);
        for(std::size_t i=0;i<value.size();++i)b[data+i*2]=static_cast<std::uint8_t>(value[i]);
    };
    string(0x400,0x440,"\\DosDevices\\ContractFixture");string(0x410,0x490,"\\Device\\ContractFixture");return b;
}
inline pe_fixture::bytes x86_driver() {
    auto b=pe_fixture::pe32(driver());std::fill(b.begin()+0x200,b.begin()+0x400,0);
    const pe_fixture::bytes entry={0x55,0x89,0xe5,0x8b,0x45,0x08,0xc7,0x40,0x70,0x40,0x10,0x40,0x00,
        0x31,0xc0,0x5d,0xc2,8,0}; // DriverObject from [ebp+8]; MajorFunction[14] = 0x401040
    const pe_fixture::bytes dispatch={0x55,0x89,0xe5,0x8b,0x55,0x0c, // Irp from [ebp+12]
        0x8b,0x4a,0x60,0x8b,0x41,0x0c,0x3d,4,0x20,0x22,0, // stack+0x60, control code +0xc
        0x83,0x79,8,0x10,0x8b,0x72,0x0c,0x8b,0x5e,8,0x89,0x5e,0x10,0x31,0xc0,0x5d,0xc2,8,0};
    std::copy(entry.begin(),entry.end(),b.begin()+0x200);std::copy(dispatch.begin(),dispatch.end(),b.begin()+0x240);return b;
}
inline pe_fixture::bytes arm64_driver() {
    auto b=driver();pe_fixture::put<std::uint16_t>(b,0x84,0xaa64);std::fill(b.begin()+0x200,b.begin()+0x400,0);
    const std::uint32_t entry[]={0x10000208,0xf9007008,0x52800000,0xd65f03c0}; // ADR/STR/MOV/RET
    const std::uint32_t dispatch[]={0xf9405c29,0xb940192a,0x5284008b,0x72a0044b,0x6b0b015f,
        0xb940112c,0x7100419f,0xf9400c2d,0xf94005ae,0xb90011ae,0x52800000,0xd65f03c0};
    for(unsigned i=0;i<std::size(entry);++i)pe_fixture::put(b,0x200+i*4,entry[i]);
    for(unsigned i=0;i<std::size(dispatch);++i)pe_fixture::put(b,0x240+i*4,dispatch[i]);return b;
}
}
