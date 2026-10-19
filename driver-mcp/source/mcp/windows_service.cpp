#include "windows_service.hpp"
#include <chrono>
#include <fstream>
#include <random>
#include <stdexcept>
#include <thread>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#else
#include <cerrno>
#include <csignal>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif
namespace mcp_runtime {
namespace {
    std::filesystem::path sibling_worker() {
#ifdef _WIN32
        std::wstring name(32768,L'\0');
        const auto size=GetModuleFileNameW(nullptr,name.data(),static_cast<DWORD>(name.size()));
        if(!size||size>=name.size())throw std::runtime_error("cannot_locate_executable");
        name.resize(size);return std::filesystem::path(name).parent_path()/L"evoke-kernemul.exe";
#else
        std::string name(65536,'\0');const auto size=readlink("/proc/self/exe",name.data(),name.size());
        if(size<0||static_cast<std::size_t>(size)>=name.size())throw std::runtime_error("cannot_locate_executable");
        name.resize(static_cast<std::size_t>(size));return std::filesystem::path(name).parent_path()/"evoke-kernemul";
#endif
    }
    struct workspace {
        std::filesystem::path path;
        workspace() {
            std::random_device random;
            for(unsigned attempt=0;attempt<16;++attempt) {
                auto candidate=std::filesystem::temp_directory_path()/("evoke-kernemul-"+std::to_string(random())+"-"+std::to_string(random()));
#ifdef _WIN32
                if(std::filesystem::create_directory(candidate)){path=std::move(candidate);return;}
#else
                if(::mkdir(candidate.c_str(),0700)==0){path=std::move(candidate);return;}
                if(errno!=EEXIST)throw std::runtime_error("worker_workspace_failed");
#endif
            }
            throw std::runtime_error("worker_workspace_failed");
        }
        ~workspace(){std::error_code ec;std::filesystem::remove_all(path,ec);}
    };
    // Never uses a shell. A deadline kills and reaps the worker before its files go away.
    bool execute(const std::filesystem::path& executable,const std::filesystem::path& input,
                 const std::filesystem::path& output,unsigned timeout) {
#ifdef _WIN32
        struct handle {
            HANDLE value=nullptr;
            ~handle(){if(value)CloseHandle(value);}
        } job,process,thread;
        job.value=CreateJobObjectW(nullptr,nullptr);
        if(!job.value)throw std::runtime_error("worker_job_failed");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS|JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.BasicLimitInformation.ActiveProcessLimit=1;limits.ProcessMemoryLimit=2ULL*1024*1024*1024;
        if(!SetInformationJobObject(job.value,JobObjectExtendedLimitInformation,&limits,sizeof(limits)))throw std::runtime_error("worker_job_limits_failed");
        auto command=L"\""+executable.wstring()+L"\" \""+input.wstring()+L"\" \""+output.wstring()+L"\"";
        STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION details{};
        if(!CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,nullptr,nullptr,&startup,&details))
            throw std::runtime_error("worker_launch_failed");
        process.value=details.hProcess;thread.value=details.hThread;
        if(!AssignProcessToJobObject(job.value,process.value)) {
            TerminateProcess(process.value,1);WaitForSingleObject(process.value,5000);throw std::runtime_error("worker_job_assignment_failed");
        }
        if(ResumeThread(thread.value)==static_cast<DWORD>(-1)) {
            TerminateJobObject(job.value,1);WaitForSingleObject(process.value,5000);throw std::runtime_error("worker_resume_failed");
        }
        const auto waited=WaitForSingleObject(process.value,timeout);
        if(waited==WAIT_TIMEOUT){TerminateJobObject(job.value,1);WaitForSingleObject(process.value,5000);return false;}
        if(waited!=WAIT_OBJECT_0) {
            TerminateJobObject(job.value,1);WaitForSingleObject(process.value,5000);throw std::runtime_error("worker_wait_failed");
        }
        DWORD code=0;if(!GetExitCodeProcess(process.value,&code)||code!=0)throw std::runtime_error("worker_failed");
#else
        auto executable_text=executable.string(),input_text=input.string(),output_text=output.string();
        char* argv[]={executable_text.data(),input_text.data(),output_text.data(),nullptr};
        pid_t child=0;const auto launched=posix_spawn(&child,executable.c_str(),nullptr,nullptr,argv,environ);
        if(launched)throw std::runtime_error("worker_launch_failed");
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(timeout);
        while(true) {
            int status=0;const auto waited=waitpid(child,&status,WNOHANG);
            if(waited==child) {
                if(!WIFEXITED(status)||WEXITSTATUS(status)!=0)throw std::runtime_error("worker_failed");
                return true;
            }
            if(waited<0&&errno!=EINTR) {
                kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}
                throw std::runtime_error("worker_wait_failed");
            }
            if(std::chrono::steady_clock::now()>=deadline) {
                kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
#endif
        return true;
    }
}
windows_service::windows_service():worker_(sibling_worker()){}
json windows_service::info(const json& args) {
    if(!args.is_object()||!args.empty())throw std::invalid_argument("unexpected_windows_info_argument");
    return make_tool_result("windows_emulation_info",{{"backend","kernemul"},{"bundled_worker_available",std::filesystem::is_regular_file(worker_)},
        {"upstream_revision","cf3aedc6cc1755d2fedad77dcd4671bf045f9de8"},{"architecture","x86_64"},
        {"operation_discovery","list_windows_operations"},{"execution","emulate_windows_operations"},
        {"state_lifetime","this_request"},{"max_operations",64},{"max_buffers",32},{"max_buffer_bytes",16384},
        {"max_total_buffer_bytes",65536},{"max_timeout_ms",10000},{"default_timeout_ms",3000},
        {"numeric_syscall_dispatch",false},{"live_system_modified",false},
        {"limitations","Original upstream Windows models in an image-free guest. Nt/Zw handlers are called by name. No PE loading, numeric syscall table, or guest scheduler execution. Upstream approximations and unsupported branches remain; handled does not mean NTSTATUS success. Not an OS sandbox."}});
}
json windows_service::catalog(const json& args){return invoke("catalog",args);}
json windows_service::run(const json& args){return invoke("run",args);}
json windows_service::invoke(const char* action,const json& args) {
    if(!args.is_object())throw std::invalid_argument("arguments_must_be_object");
    unsigned timeout=3000;
    if(args.contains("timeout_ms")) {
        if(!args.at("timeout_ms").is_number_integer())throw std::invalid_argument("invalid_timeout_ms");
        const auto n=args.at("timeout_ms").get<std::int64_t>();if(n<100||n>10000)throw std::invalid_argument("invalid_timeout_ms");timeout=static_cast<unsigned>(n);
    }
    const auto text=json({{"action",action},{"arguments",args}}).dump();
    if(text.size()>131072)throw std::invalid_argument("windows_request_too_large");
    std::unique_lock lock(mutex_,std::try_to_lock);
    if(!lock.owns_lock())return make_tool_result("windows_emulation_busy",{{"status","windows_emulation_busy"}},true);
    if(!std::filesystem::is_regular_file(worker_))return make_tool_result("kernemul_worker_unavailable",{{"status","kernemul_worker_unavailable"}},true);
    try {
        workspace temp;const auto input=temp.path/"request.json",output=temp.path/"response.json";
        {std::ofstream stream(input,std::ios::binary);stream<<text;if(!stream.good())throw std::runtime_error("worker_input_failed");}
        if(!execute(worker_,input,output,timeout))return make_tool_result("windows_emulation_timeout",{{"status","timeout"},{"source","kernemul"},{"timeout_ms",timeout}},true);
        if(!std::filesystem::is_regular_file(output)||std::filesystem::file_size(output)>1024*1024)throw std::runtime_error("invalid_worker_response");
        std::ifstream stream(output,std::ios::binary);json value;stream>>value;
        const auto status=value.value("status",std::string("completed"));
        return make_tool_result(std::string("windows_")+status,value,status!="completed");
    }catch(const std::exception& error){return make_tool_result("kernemul_worker_error",{{"status","worker_error"},{"source","kernemul"},{"error",error.what()}},true);}
}
}
