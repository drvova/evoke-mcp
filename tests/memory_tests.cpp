#include "memory_service.hpp"
#include "server.hpp"
#include "http_security.hpp"

#include <atomic>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>

using namespace mcp_runtime;
namespace {
    int assertions = 0;
    void check(bool value, const char* message) {
        ++assertions;
        if (!value) throw std::runtime_error(message);
    }
    template<class Function> void rejects(Function function, const char* message) {
        bool rejected = false;
        try { function(); } catch (const std::exception&) { rejected = true; }
        check(rejected, message);
    }
    struct fake_backend : memory_backend {
        std::optional<target_identity> target = target_identity{42, 123456, 0x10000};
        std::vector<std::uint8_t> data = std::vector<std::uint8_t>(8, 0);
        int reads = 0, writes = 0;
        int fail_read = -1;
        bool fail_write = false, ignore_write = false;
        std::function<void(int)> on_read;
        std::function<void()> on_write;
        std::optional<target_identity> identity() override { return target; }
        bool read(std::uint64_t, void* out, std::size_t size) override {
            ++reads;
            if (on_read) on_read(reads);
            if (reads == fail_read) return false;
            std::memcpy(out, data.data(), size);
            return true;
        }
        bool write(std::uint64_t, const void* value, std::size_t size) override {
            ++writes;
            if (on_write) on_write();
            if (fail_write) return false;
            if (!ignore_write) std::memcpy(data.data(), value, size);
            return true;
        }
    };
    struct fixture {
        fake_backend backend;
        memory_service::clock::time_point time{};
        int next = 0;
        std::vector<json> audit;
        memory_service service;
        fixture(std::size_t capacity = 128) : service(backend,
            [&] { return "patch-" + std::to_string(++next); },
            [&](const json& record) { audit.push_back(record); }, [&] { return time; },
            std::chrono::seconds(60), capacity) { backend.data[0] = 12; }
        json prepare(json value = 20, std::string type = "u8") {
            return service.prepare({{"addr", 0x10000}, {"type", type}, {"value", value}}).at("structuredContent");
        }
        json apply(const json& plan) {
            return service.apply({{"patch_id", plan.at("patch_id")}});
        }
    };
    json record(const json& result) { return result.at("structuredContent"); }
    void status(const json& result, const char* expected, bool is_error = true) {
        check(record(result).at("status") == expected, expected);
        check(result.at("isError") == is_error, "correct error flag");
    }
    void success_and_replay() {
        fixture f;
        const auto plan = f.prepare();
        check(f.backend.writes == 0, "prepare never writes");
        check(plan.at("before") == 12 && plan.at("after") == 20, "preview values");
        check(plan.at("before_bytes") == "0c" && plan.at("after_bytes") == "14", "preview bytes");
        auto result = f.apply(plan);
        status(result, "verified", false);
        check(record(result).at("verified") == true, "readback verified");
        check(record(result).at("write_attempted") == true && f.backend.writes == 1, "one write");
        check(f.backend.reads == 3 && f.backend.data[0] == 20, "preview, precondition, verification reads");
        check(f.audit.size() == 2 && f.audit[0].at("status") == "apply_started", "audit before and after write");
        rejects([&] { f.apply(plan); }, "single-use patch ID");
    }
    void stale_and_expired() {
        { fixture f; auto p=f.prepare(); f.backend.data[0]=13; auto r=f.apply(p);
          status(r,"memory_changed"); check(f.backend.writes==0,"stale bytes never written"); }
        { fixture f; auto p=f.prepare(); ++f.backend.target->creation_time;
          status(f.apply(p),"target_changed"); check(f.backend.writes==0,"PID reuse rejected"); }
        { fixture f; auto p=f.prepare(); f.backend.target.reset(); status(f.apply(p),"target_changed"); }
        { fixture f; auto p=f.prepare(); ++f.backend.target->base; status(f.apply(p),"target_changed"); }
        { fixture f; auto p=f.prepare(); f.time+=std::chrono::seconds(60);
          status(f.apply(p),"patch_expired"); check(f.backend.writes==0,"expiry boundary"); }
        { fixture f; auto p=f.prepare(); f.backend.on_read=[&](int n) { if(n==2) f.time+=std::chrono::seconds(60); };
          status(f.apply(p),"patch_expired"); check(f.backend.writes==0,"expiry during precondition read"); }
        { fixture f; auto p=f.prepare(); f.backend.on_read=[&](int n) { if(n==2) f.backend.target.reset(); };
          status(f.apply(p),"target_changed"); check(f.backend.writes==0,"process exits during read"); }
        { fixture f; f.backend.on_read=[&](int) { f.backend.target.reset(); };
          rejects([&] { f.prepare(); },"process exits during preview"); }
    }
    void driver_failures() {
        { fixture f; f.backend.fail_read=1; rejects([&] { f.prepare(); },"failed preview rejected"); }
        { fixture f; f.backend.fail_read=1; rejects([&] { f.service.read({{"addr",65536},{"type","u8"}}); },"failed read rejected"); }
        { fixture f; auto p=f.prepare(); f.backend.fail_read=2; status(f.apply(p),"driver_read_failed");
          check(f.backend.writes==0,"failed precondition never written"); }
        { fixture f; auto p=f.prepare(); f.backend.fail_write=true; auto r=f.apply(p); status(r,"driver_write_failed");
          check(record(r).at("write_attempted")==true,"failed writes marked attempted"); rejects([&] { f.apply(p); },"failure consumes ID"); }
        { fixture f; auto p=f.prepare(); f.backend.fail_read=3; status(f.apply(p),"verification_read_failed"); }
        { fixture f; auto p=f.prepare(); f.backend.ignore_write=true; status(f.apply(p),"verification_failed"); }
        { fixture f; auto p=f.prepare(); f.backend.on_write=[&] { f.backend.target.reset(); };
          status(f.apply(p),"target_changed_after_write"); }
        { fixture f; auto p=f.prepare(); f.backend.on_read=[&](int n) { if(n==3) f.backend.target.reset(); };
          status(f.apply(p),"target_changed_after_write"); }
    }
    void strict_validation() {
        fixture f;
        const auto good=json{{"addr",65536},{"type","u8"},{"value",20}};
        for (auto addr : {json(-1),json(0),json(65535),json(65536.0),json(true),json("65536"),json(0x800000000000ULL)}) {
            auto args=good; args["addr"]=addr;
            rejects([&] { f.service.prepare(args); },"invalid address rejected");
        }
        for(auto value : {json(-1),json(256),json(1.5),json(true),json("20"),json(nullptr)})
            rejects([&] { f.prepare(value); },"invalid u8 rejected");
        for (auto type : {"i8","i16","i32","i64"})
            rejects([&] { f.prepare(std::numeric_limits<std::uint64_t>::max(),type); },"unsigned overflow to signed rejected");
        rejects([&] { f.prepare(128,"i8"); },"signed overflow rejected");
        rejects([&] { f.prepare(-129,"i8"); },"signed underflow rejected");
        rejects([&] { f.prepare(1e100,"float"); },"float overflow rejected");
        rejects([&] { f.prepare(1e-100,"float"); },"float underflow rejected");
        rejects([&] { f.prepare(std::numeric_limits<double>::infinity(),"double"); },"infinity rejected");
        rejects([&] { f.prepare(std::numeric_limits<double>::quiet_NaN(),"double"); },"NaN rejected");
        rejects([&] { f.prepare(1,"unknown"); },"unknown type rejected");
        auto args=good; args["addr"]=0x7fffffffffffULL; args["type"]="u16";
        rejects([&] { f.service.prepare(args); },"transfer cannot cross user boundary");
        args=good; args["extra"]=1; rejects([&] { f.service.prepare(args); },"extra arguments rejected");
        args=good; args.erase("type"); rejects([&] { f.service.prepare(args); },"missing arguments rejected");
        check(f.backend.reads==0 && f.backend.writes==0,"validation precedes driver access");
        args=good; args["expected"]=11; rejects([&] { f.service.prepare(args); },"expected mismatch rejected");
        args["expected"]=12; check(record(f.service.prepare(args)).at("before")==12,"expected value accepted");
    }
    void primitive_roundtrips() {
        const std::vector<std::pair<std::string,json>> cases={
            {"byte",255},{"u8",0},{"u16",65535},{"u32",4294967295ULL},
            {"u64",std::numeric_limits<std::uint64_t>::max()},
            {"i8",-128},{"i16",-32768},{"i32",std::numeric_limits<std::int32_t>::min()},
            {"i64",std::numeric_limits<std::int64_t>::min()}, {"float",1.25},{"double",-2.5}};
        for(const auto& [type,value]:cases) {
            fixture f;
            auto p=f.prepare(value,type); status(f.apply(p),"verified",false);
            auto result=f.service.read({{"addr",65536},{"type",type}});
            check(record(result).at("value")==value,"primitive round trip");
        }
    }
    void limits_audit_and_concurrency() {
        { fixture f(1); f.prepare(); rejects([&] { f.prepare(); },"pending patch limit");
          f.time+=std::chrono::seconds(60); check(!f.prepare().empty(),"expired previews pruned"); }
        { fake_backend b; int id=0; memory_service service(b,[&] {return std::to_string(++id);},
              [](const json&) { throw std::runtime_error("disk_full"); });
          auto p=record(service.prepare({{"addr",65536},{"type","u8"},{"value",20}}));
          status(service.apply({{"patch_id",p.at("patch_id")}}),"audit_unavailable_no_write");
          check(b.writes==0,"audit failure blocks write"); }
        { fake_backend b; int calls=0; memory_service service(b,[] {return "id";},
              [&](const json&) { if(++calls==2) throw std::runtime_error("disk_full"); });
          auto p=record(service.prepare({{"addr",65536},{"type","u8"},{"value",20}}));
          auto r=service.apply({{"patch_id",p.at("patch_id")}}); status(r,"verified",true);
          check(record(r).at("verified")==true && record(r).contains("audit_error"),"audit failure does not hide completed write"); }
        { fake_backend b; memory_service::clock::time_point time{};
          memory_service service(b,[] {return "id";}, [&](const json& entry) {
              if(entry.at("status")=="apply_started") time+=std::chrono::seconds(60);
          }, [&] {return time;});
          auto p=record(service.prepare({{"addr",65536},{"type","u8"},{"value",20}}));
          status(service.apply({{"patch_id",p.at("patch_id")}}),"patch_expired");
          check(b.writes==0,"expiry during audit blocks write"); }
        { fixture f; auto p=f.prepare(); auto q=f.prepare(30); json a,b;
          std::thread first([&] { a=f.apply(p); }); std::thread second([&] { b=f.apply(q); }); first.join(); second.join();
          check(f.backend.writes==1,"competing patches serialized");
          check(record(a).at("verified")!=record(b).at("verified"),"only one competing patch verifies"); }
    }
    struct management_backend : fake_backend {
        bool ready = true, fail = false;
        int calls = 0;
        std::uint64_t result_address = 0x20000, result_size = 4096;
        page_protection last_protection = page_protection::no_access;
        std::function<void()> on_control;
        std::string_view name() const override { return "mock-control"; }
        bool supports(driver_operation) const override { return true; }
        bool connected() override { return ready; }
        std::optional<target_identity> identity() override { return ready ? target : std::nullopt; }
        bool begin() { ++calls; if(on_control) on_control(); return !fail; }
        bool connect() override { if(!begin()) return false; ready=true; return true; }
        bool attach(std::uint32_t pid) override {
            if(!begin() || !ready) return false;
            target=target_identity{pid,987654,0x10000}; return true;
        }
        bool detach() override { if(!begin()) return false; target.reset(); return true; }
        bool query_process(process_information& out) override {
            if(!begin()) return false;
            out={0x20000,std::numeric_limits<std::uint64_t>::max()}; return true;
        }
        bool allocate(std::uint64_t& addr,std::uint64_t& size,page_protection protection) override {
            last_protection=protection;
            if(!begin()) return false;
            addr=result_address; size=result_size; return true;
        }
        bool protect(std::uint64_t& addr,std::uint64_t& size,page_protection protection,std::uint32_t& old) override {
            last_protection=protection;
            if(!begin()) return false;
            addr=result_address; size=result_size; old=4; return true;
        }
        bool unload() override { if(!begin()) return false; ready=false; target.reset(); return true; }
    };
    struct management_fixture {
        management_backend backend;
        int id=0;
        std::vector<json> audit;
        memory_service service;
        management_fixture() : service(backend,[&] {return "control-"+std::to_string(++id);},
            [&](const json& entry) {audit.push_back(entry);}) {}
        json preview() { return record(service.prepare({{"addr",65536},{"type","u8"},{"value",20}})); }
    };
    void management_lifecycle_and_capabilities() {
        { fixture f; auto p=f.prepare();
          auto info=record(f.service.driver_status(json::object()));
          check(info.at("adapter")=="custom" && info.at("execution_exposed")==false,"custom adapter capabilities");
          rejects([&] {f.service.unload_driver(json::object());},"unsupported operation rejected before dispatch");
          status(f.apply(p),"verified",false); }
        management_fixture f;
        auto info=record(f.service.driver_status(json::object()));
        check(info.at("supported_operations").size()==12,"adapter reports memory and management operations");
        check(info.at("capabilities_source")=="adapter_declarations_not_runtime_probe","capabilities not presented as probed");
        auto p=f.preview();
        status(f.service.detach_process(json::object()),"process_detached",false);
        rejects([&] {f.service.apply({{"patch_id",p.at("patch_id")}});},"detach invalidates patches");
        rejects([&] {f.service.read({{"addr",65536},{"type","u8"}});},"read without target rejected");
        status(f.service.attach_process({{"pid",27}}),"process_attached",false);
        info=record(f.service.process_info(json::object()));
        check(info.at("target").at("pid")==27 && info.at("peb")=="131072","query attached process");
        check(info.at("dtb")=="18446744073709551615","full-width metadata preserved");
        f.backend.fail=true;
        rejects([&] {f.service.process_info(json::object());},"metadata failure reported");
        f.backend.fail=false;
        status(f.service.unload_driver(json::object()),"driver_unloaded",false);
        check(record(f.service.driver_status(json::object())).at("driver_available")==false,"unloaded status");
        status(f.service.connect_driver(json::object()),"driver_connected",false);
        check(record(f.service.driver_status(json::object())).at("target").is_null(),"connect does not select target");
        status(f.service.attach_process({{"pid",28}}),"process_attached",false);
        check(f.audit.front().at("status")=="operation_started","management audit begins before action");
    }
    void management_memory_and_validation() {
        management_fixture f;
        auto p=f.preview();
        auto allocation=f.service.allocate_memory({{"size",100},{"protection","execute_read"}});
        status(allocation,"memory_allocated",false);
        check(record(allocation).at("addr")==0x20000 && record(allocation).at("size")==4096,"allocation returns rounded range");
        check(f.backend.last_protection==page_protection::execute_read,"typed protection forwarded");
        rejects([&] {f.service.apply({{"patch_id",p.at("patch_id")}});},"allocation invalidates previews");
        auto protection=f.service.protect_memory({{"addr",0x20001},{"size",15},{"protection","read_only"}});
        status(protection,"memory_protection_changed",false);
        check(record(protection).at("previous_native_protection")==4,"previous native protection preserved");
        f.backend.result_address=0;
        status(f.service.allocate_memory({{"size",1},{"protection","read_write"}}),"invalid_driver_allocation_range");
        f.backend.result_address=0x20000; f.backend.result_size=1;
        status(f.service.allocate_memory({{"size",2},{"protection","read_write"}}),"driver_allocation_too_small");
        status(f.service.protect_memory({{"addr",0x20000},{"size",2},{"protection","read_write"}}),"driver_protection_range_mismatch");
        f.backend.result_address=0; f.backend.result_size=4096;
        status(f.service.protect_memory({{"addr",0x20000},{"size",1},{"protection","read_write"}}),"invalid_driver_protection_range");
        f.backend.result_address=0x20000;
        f.backend.on_control=[&] {f.backend.target.reset();};
        status(f.service.allocate_memory({{"size",1},{"protection","read_write"}}),"target_changed_after_operation");
        management_fixture invalid;
        for(auto pid:{json(0),json(-1),json(true),json(1.5),json(4294967296ULL)})
            rejects([&] {invalid.service.attach_process({{"pid",pid}});},"invalid PID rejected");
        for(auto size:{json(0),json(-1),json(true),json(1.5),json(std::numeric_limits<std::uint64_t>::max())})
            rejects([&] {invalid.service.allocate_memory({{"size",size},{"protection","read_write"}});},"invalid allocation size rejected");
        rejects([&] {invalid.service.allocate_memory({{"size",1},{"protection","raw_flags"}});},"unknown protection rejected");
        rejects([&] {invalid.service.protect_memory({{"addr",0x7fffffffffffULL},{"size",2},{"protection","read_write"}});},"protection range overflow rejected");
        rejects([&] {invalid.service.connect_driver({{"extra",true}});},"unexpected management arguments rejected");
        check(invalid.backend.calls==0,"management validation before driver access");
        invalid.backend.fail=true;
        status(invalid.service.connect_driver(json::object()),"driver_connect_failed");
        status(invalid.service.attach_process({{"pid",27}}),"driver_attach_failed");
        status(invalid.service.detach_process(json::object()),"driver_detach_failed");
        status(invalid.service.unload_driver(json::object()),"driver_unload_failed");
        status(invalid.service.allocate_memory({{"size",1},{"protection","read_write"}}),"driver_allocate_failed");
        status(invalid.service.protect_memory({{"addr",65536},{"size",1},{"protection","read_write"}}),"driver_protect_failed");
    }
    void management_audit_failures() {
        { management_backend b;
          memory_service service(b,[] {return "id";},[](const json&) {throw std::runtime_error("disk_full");});
          service.prepare({{"addr",65536},{"type","u8"},{"value",20}});
          status(service.detach_process(json::object()),"audit_unavailable_no_operation");
          check(b.calls==0,"audit failure prevents management dispatch");
          check(record(service.driver_status(json::object())).at("pending_patches")==1,"pre-audit failure retains previews"); }
        { management_backend b; int calls=0;
          memory_service service(b,[] {return "id";},[&](const json&) {if(++calls==2) throw std::runtime_error("disk_full");});
          auto result=service.detach_process(json::object());
          status(result,"process_detached",true);
          check(record(result).at("ok")==true && record(result).contains("audit_error"),"post-audit failure preserves completed operation"); }
        { management_fixture f; auto p=f.preview(); f.backend.fail=true;
          status(f.service.allocate_memory({{"size",1},{"protection","read_write"}}),"driver_allocate_failed");
          rejects([&] {f.service.apply({{"patch_id",p.at("patch_id")}});},"failed management action also invalidates preview"); }
    }
    void protocol_and_http_security() {
        fixture f; mcp_server server(f.service);
        auto call=[&](json message) { return server.handle(message).value(); };
        check(call({{"id",1},{"method","ping"}}).at("error").at("code")==-32600,"JSON-RPC version required");
        check(call(json::array()).at("error").at("code")==-32600,"batch rejected");
        check(call({{"jsonrpc","2.0"},{"id",1},{"method","tools/call"}}).at("error").at("code")==-32602,"missing tool name is protocol error");
        check(call({{"jsonrpc","2.0"},{"id",1},{"method","bad"}}).at("error").at("code")==-32601,"unknown method code");
        check(!server.handle({{"jsonrpc","2.0"},{"method","tools/call"},{"params",{{"name","apply_memory_patch"}}}}),"notifications do not execute tools");
        const auto tools=call({{"jsonrpc","2.0"},{"id",1},{"method","tools/list"}}).at("result").at("tools");
        check(tools.size()==12,"memory and management tools registered");
        for(const auto& tool:tools) check(tool.at("name")!="write_memory","blind writes removed");
        auto r=call({{"jsonrpc","2.0"},{"id",1},{"method","tools/call"},
            {"params",{{"name","prepare_memory_patch"},{"arguments",{{"addr",65536},{"type","u8"},{"value",256}}}}}});
        check(r.at("result").at("isError")==true && f.backend.writes==0,"tool validation error surfaced");
        for(auto origin:{"","http://localhost","https://127.0.0.1:8888","http://localhost:3000"})
            check(origin_allowed(origin),"local origin allowed");
        for(auto origin:{"null","http://localhost.attacker.example","http://127.0.0.1.evil", "http://localhost@evil", "http://localhost/evil", "http://localhost:","http://localhost:65536","http://localhost:0","http://localhost:80/path","file://localhost"})
            check(!origin_allowed(origin),"malformed or nonlocal origin rejected");
        check(host_allowed("127.0.0.1:8888") && host_allowed("localhost:8888"),"loopback host allowed");
        check(!host_allowed("evil:8888") && !host_allowed("localhost.evil:8888"),"DNS rebinding host rejected");
        check(token_matches("Bearer secret","secret"),"valid bearer accepted");
        check(!token_matches("Bearer wrong","secret") && !token_matches("secret","secret") && !token_matches("Bearer ",""),"invalid bearer rejected");
    }
}
int main() {
    try {
        success_and_replay(); stale_and_expired(); driver_failures(); strict_validation();
        primitive_roundtrips(); limits_audit_and_concurrency();
        management_lifecycle_and_capabilities(); management_memory_and_validation();
        management_audit_failures(); protocol_and_http_security();
        std::cout << assertions << " assertions passed\n";
        return 0;
    } catch(const std::exception& exception) {
        std::cerr << "FAIL after " << assertions << " assertions: " << exception.what() << '\n';
        return 1;
    }
}
