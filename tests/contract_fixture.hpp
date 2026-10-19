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
}
