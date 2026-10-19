#include "system_drivers.hpp"
#include <filesystem>
#include <stdexcept>
#include <vector>
#ifdef _WIN32
#include <Windows.h>
#endif
namespace mcp_runtime {
namespace {
void valid_name(const std::string& s) {
    if(s.empty()||s.size()>256||s.find('\0')!=std::string::npos||s.find_first_of("/\\")!=std::string::npos)
        throw std::invalid_argument("invalid_driver_service_name");
}
#ifdef _WIN32
struct service_handle {SC_HANDLE h=nullptr;~service_handle(){if(h)CloseServiceHandle(h);}};
std::wstring wide(const std::string& s) {
    const int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    if(n<=0)throw std::invalid_argument("invalid_utf8_service_name");std::wstring out(n,L'\0');
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n);return out;
}
std::string utf8(const std::wstring& s) {
    if(s.empty())return {};const int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
    if(n<=0)throw std::runtime_error("invalid_utf16_service_data");std::string out(n,'\0');
    WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr);return out;
}
bool prefix(const std::wstring& s,const std::wstring& p) {
    return s.size()>=p.size()&&CompareStringOrdinal(s.data(),static_cast<int>(p.size()),p.data(),static_cast<int>(p.size()),TRUE)==CSTR_EQUAL;
}
std::wstring image_path(std::wstring path) {
    if(path.empty()||path.size()>32767)throw std::runtime_error("driver_image_path_unresolved");
    if(path.front()==L'"') {
        const auto end=path.find(L'"',1);
        if(end==std::wstring::npos||path.find_first_not_of(L" \t",end+1)!=std::wstring::npos)throw std::runtime_error("driver_image_command_line_unsupported");
        path=path.substr(1,end-1);
    }
    std::wstring expanded(32768,L'\0');const auto n=ExpandEnvironmentStringsW(path.c_str(),expanded.data(),static_cast<DWORD>(expanded.size()));
    if(!n||n>expanded.size())throw std::runtime_error("driver_image_path_unresolved");expanded.resize(n-1);path=std::move(expanded);
    std::wstring windows(32768,L'\0');const auto length=GetWindowsDirectoryW(windows.data(),static_cast<UINT>(windows.size()));
    if(!length||length>=windows.size())throw std::runtime_error("windows_directory_unavailable");windows.resize(length);
    if(prefix(path,L"\\SystemRoot\\"))path=windows+path.substr(11);
    else if(prefix(path,L"System32\\"))path=windows+L"\\"+path;
    else if(prefix(path,L"\\??\\"))path=path.substr(4);
    if(!std::filesystem::path(path).is_absolute())throw std::runtime_error("driver_image_path_unresolved");
    return path;
}
json config(SC_HANDLE manager,const std::wstring& name) {
    service_handle service{OpenServiceW(manager,name.c_str(),SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS)};
    if(!service.h)throw std::runtime_error("driver_service_query_failed: "+std::to_string(GetLastError()));
    DWORD needed=0;QueryServiceConfigW(service.h,nullptr,0,&needed);
    if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER||needed>65536||needed<sizeof(QUERY_SERVICE_CONFIGW))throw std::runtime_error("driver_service_config_unavailable");
    std::vector<std::uint8_t> buffer(needed);
    if(!QueryServiceConfigW(service.h,reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data()),needed,&needed))throw std::runtime_error("driver_service_config_changed");
    const auto& value=*reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(buffer.data());
    if(!(value.dwServiceType&(SERVICE_KERNEL_DRIVER|SERVICE_FILE_SYSTEM_DRIVER)))throw std::invalid_argument("service_is_not_kernel_or_filesystem_driver");
    SERVICE_STATUS status{};if(!QueryServiceStatus(service.h,&status))throw std::runtime_error("driver_service_status_unavailable");
    json result={{"service_name",utf8(name)},{"configured_image",utf8(value.lpBinaryPathName)},
        {"service_type",value.dwServiceType},{"state",status.dwCurrentState},{"running",status.dwCurrentState==SERVICE_RUNNING},
        {"source","windows_service_configuration"},{"device_association_proven",false}};
    try {result["image_path"]=utf8(image_path(value.lpBinaryPathName));}
    catch(const std::exception& error){result["image_path_error"]=error.what();}
    return result;
}
#endif
}
json resolve_system_driver(const std::string& name) {
    valid_name(name);
#ifdef _WIN32
    service_handle manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT)};
    if(!manager.h)throw std::runtime_error("service_manager_unavailable");
    auto result=config(manager.h,wide(name));
    if(!result.contains("image_path"))throw std::runtime_error(result.at("image_path_error").get<std::string>());
    return result;
#else
    throw std::runtime_error("windows_driver_services_unavailable");
#endif
}
json list_system_drivers(const json& args) {
    if(!args.is_object())throw std::invalid_argument("object_required");
    for(const auto& entry:args.items())if(entry.key()!="name"&&entry.key()!="offset"&&entry.key()!="limit")throw std::invalid_argument("unexpected_driver_catalog_argument");
    const auto name=args.value("name",std::string());if(args.contains("name"))valid_name(name);
    auto bound=[&](const char* key,unsigned fallback,unsigned maximum) {
        if(!args.contains(key))return fallback;const auto& n=args.at(key);
        if(!n.is_number_integer()||n.get<std::int64_t>()<0||n.get<std::uint64_t>()>maximum)throw std::invalid_argument("invalid_driver_catalog_bound");
        return n.get<unsigned>();
    };
    const auto offset=bound("offset",0,4096),limit=bound("limit",100,200);if(!limit)throw std::invalid_argument("invalid_driver_catalog_bound");
#ifdef _WIN32
    service_handle manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_ENUMERATE_SERVICE|SC_MANAGER_CONNECT)};
    if(!manager.h)return make_tool_result("system_drivers_unavailable",{{"status","service_manager_unavailable"},{"win32_error",GetLastError()}},true);
    std::vector<std::uint8_t> buffer(65536);DWORD resume=0;unsigned count=0;bool truncated=false;json drivers=json::array();
    const auto filter=name.empty()?std::wstring():wide(name);
    for(unsigned round=0;round<32;++round) {
        DWORD needed=0,returned=0;
        const bool ok=EnumServicesStatusExW(manager.h,SC_ENUM_PROCESS_INFO,SERVICE_DRIVER,SERVICE_STATE_ALL,
            buffer.data(),static_cast<DWORD>(buffer.size()),&needed,&returned,&resume,nullptr)!=FALSE;
        const auto error=ok?ERROR_SUCCESS:GetLastError();
        if(!ok&&error!=ERROR_MORE_DATA)return make_tool_result("system_driver_enumeration_failed",{{"status","enumeration_failed"},{"win32_error",error}},true);
        const auto* entries=reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for(DWORD i=0;i<returned;++i) {
            if(!filter.empty()&&CompareStringOrdinal(filter.c_str(),-1,entries[i].lpServiceName,-1,TRUE)!=CSTR_EQUAL)continue;
            if(count++<offset||drivers.size()>=limit)continue;
            try {drivers.push_back(config(manager.h,entries[i].lpServiceName));}
            catch(const std::exception& e){drivers.push_back({{"service_name",utf8(entries[i].lpServiceName)},{"query_error",e.what()}});}
        }
        if(ok)break;
        if(count>=4096||round==31){truncated=true;break;}
    }
    return make_tool_result("system_drivers",{{"status","completed"},{"source","windows_service_configuration"},{"drivers",drivers},
        {"filtered_total",count},{"next_offset",offset+drivers.size()<count?json(offset+drivers.size()):json(nullptr)},
        {"truncated",truncated},{"live_system_modified",false},{"device_association_proven",false}});
#else
    return make_tool_result("system_drivers_unavailable",{{"status","windows_driver_services_unavailable"},{"live_system_modified",false}},true);
#endif
}
}
