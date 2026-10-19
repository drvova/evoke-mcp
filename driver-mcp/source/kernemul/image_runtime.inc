    json execute_image(const json& args, json* observations=nullptr) {
        fields(args,{"image_hex","image_path","kind","base_address","entry_rva","arguments","registers","watch","syscalls","syscall_stubs_hex","syscall_stubs_path","instruction_limit","trace_limit","execution_timeout_ms","timeout_ms"});
        const auto raw=image_input(args,"image_hex","image_path",2*1024*1024);
        evoke_pe::image image(raw);
        auto bounded=[&](const char* key,unsigned fallback,unsigned max) {
            const auto n=args.contains(key)?number(args.at(key)):fallback;
            if(!n||n>max)throw std::invalid_argument(std::string("invalid_")+key);return static_cast<unsigned>(n);
        };
        const auto instruction_limit=bounded("instruction_limit",10000,100000),trace_limit=bounded("trace_limit",128,512),execution_ms=bounded("execution_timeout_ms",100,1000);
        const auto kind=args.value("kind",std::string("driver"));if(kind!="driver"&&kind!="application")throw std::invalid_argument("invalid_image_kind");
        auto& state=win.kernel();state.initialize_headless();win.disable_guest_exceptions();state.calls.allow_guest_calls=false;
        win.create_vcpus(1);auto cpu=win.cpus().front();state.init_per_cpu(*cpu);set_log_cpu(cpu.get());
        proc_module empty_nt{};empty_nt.name="ntoskrnl.exe";x86_win_seg::init_vcpu(*cpu,empty_nt);
        auto proc=kind=="application"?std::dynamic_pointer_cast<windows_process>(state.create_process("guest.exe")):
            std::static_pointer_cast<windows_process>(state.sys_proc);
        proc->set_scheduler(&win.scheduler());auto thread=proc->create_suspended_thread(*cpu,0);cpu->set_thread(thread);thread->restore(*cpu);
        auto space=proc->addr_space();memory->switch_to(*cpu,space);win.set_kernel_mode(*cpu,kind=="driver");
        const auto supervisor=kind=="driver"?prot_supervisor:prot_none;
        const auto base=args.contains("base_address")?number(args.at("base_address")):image.preferred_base;
        auto canonical=[](std::uint64_t address){return address<=0x7fffffffffffULL||address>=0xffff800000000000ULL;};
        if(base<65536||base%4096||base>UINT64_MAX-image.bytes.size()||!canonical(base)||!canonical(base+image.bytes.size()-1)||
            (kind=="application"&&base+image.bytes.size()>0x800000000000ULL))throw std::invalid_argument("invalid_pe_base_address");
        for(std::size_t off=0;off<image.bytes.size();off+=4096)if(memory->virt_to_phys(*space,base+off))throw std::invalid_argument("pe_base_overlaps_guest_memory");
        image.relocate(base);
        struct binding {std::string module,name,implementation_module;const handler* model;};
        std::map<std::uint64_t,binding> bindings;
        std::map<std::pair<std::string,std::string>,std::uint64_t> exports;
        std::map<std::string,std::vector<std::pair<std::string,const handler*>>> module_entries;
        for(const auto& [key,h]:handlers) {
            module_entries[key.first].push_back({key.second,&h});
            if(key.first=="ntoskrnl.exe")module_entries["ntdll.dll"].push_back({key.second,&h});
        }
        for(const auto& [name,entries]:module_entries) {
            const auto length=(entries.size()*16+4095)&~std::size_t(4095);const auto address=space->alloc(length,prot_rx|supervisor);
            std::vector<std::uint8_t> stubs(length,0xcc);auto mod=std::make_shared<proc_module>();mod->name=name;mod->addr=address;mod->size=static_cast<std::uint32_t>(length);
            for(std::size_t i=0;i<entries.size();++i) {
                const auto& [api,h]=entries[i];const auto entry=address+i*16;stubs[i*16]=0xc3;
                bindings.emplace(entry,binding{name,api,name=="ntdll.dll"?"ntoskrnl.exe":name,h});exports[{name,api}]=entry;
                mod->exports[api]=entry;mod->symbols.insert(api,entry,1);
            }
            space->write_mem(address,stubs.data(),stubs.size());proc->register_emulated_module(mod);
        }
        json resolved_imports=json::array();
        for(const auto& imp:image.imports()) {
            auto module=module_name(imp.module);if(module=="ntkrnlmp.exe")module="ntoskrnl.exe";
            const auto found=exports.find({module,imp.name});
            if(found==exports.end())return {{"status","unresolved_import"},{"source","kernemul"},{"module",imp.module},{"name",imp.name}};
            image.write(imp.slot,found->second);resolved_imports.push_back({{"module",imp.module},{"name",imp.name},{"iat_rva",imp.slot},{"address",hex(found->second)}});
        }
        struct service_binding {std::string module,name,source;const handler* model;};
        std::map<std::uint32_t,service_binding> services;
        auto bind_service=[&](std::uint64_t id,const std::string& module,const std::string& name,const std::string& source) {
            if(id>UINT32_MAX||!name.starts_with("Nt"))throw std::invalid_argument("invalid_syscall_mapping");
            const auto h=handlers.find({module,name});if(h==handlers.end())throw std::invalid_argument("unknown_syscall_handler: "+module+"!"+name);
            const auto prior=services.find(static_cast<std::uint32_t>(id));
            if(prior!=services.end()&&(prior->second.module!=module||prior->second.name!=name))throw std::invalid_argument("conflicting_syscall_mapping");
            services.insert_or_assign(static_cast<std::uint32_t>(id),service_binding{module,name,source,&h->second});
            if(services.size()>512)throw std::invalid_argument("too_many_syscall_mappings");
        };
        std::size_t unsupported_stubs=0;
        if(args.contains("syscall_stubs_hex")||args.contains("syscall_stubs_path")) {
            const evoke_pe::image stubs(image_input(args,"syscall_stubs_hex","syscall_stubs_path",4*1024*1024),false);
            for(const auto& exp:stubs.exports())if(exp.name.starts_with("Nt")) {
                const auto id=state.syscalls->decode_id(std::span<const std::uint8_t>(stubs.bytes).subspan(exp.rva));
                if(!id)continue;
                if(!handlers.contains({"ntoskrnl.exe",exp.name})){++unsupported_stubs;continue;}
                bind_service(*id,"ntoskrnl.exe",exp.name,"supplied_stub_image");
            }
        }
        if(args.contains("syscalls")) {
            const auto& entries=args.at("syscalls");if(!entries.is_array()||entries.size()>512)throw std::invalid_argument("invalid_syscall_mappings");
            for(const auto& e:entries) {fields(e,{"id","module","name"});bind_service(number(e.at("id")),module_name(e.value("module",std::string("ntoskrnl.exe"))),e.at("name").get<std::string>(),"explicit_mapping");}
        }
        memory->map_virt(*space,base,image.bytes.size(),prot_rw|supervisor);space->write_mem(base,image.bytes.data(),image.bytes.size());
        space->prot_mem(base,image.bytes.size(),prot_read|supervisor);
        for(const auto& sec:image.sections) {
            auto protection=prot_read|supervisor;if(sec.flags&0x80000000)protection|=prot_write;if(sec.flags&0x20000000)protection|=prot_exec;
            space->prot_mem(base+sec.rva,sec.size,protection);
        }
        const auto entry=args.contains("entry_rva")?number(args.at("entry_rva")):image.entry;
        if(entry>UINT32_MAX||!image.is_executable(static_cast<std::uint32_t>(entry)))throw std::invalid_argument("pe_entry_not_executable");
        auto mod=std::make_shared<proc_module>();mod->name=kind=="driver"?"guest.sys":"guest.exe";mod->addr=base;mod->size=static_cast<std::uint32_t>(image.bytes.size());mod->entry_point=base+entry;mod->image=image.bytes;
        for(const auto& e:image.exports()){mod->exports[e.name]=base+e.rva;mod->symbols.insert(e.name,base+e.rva);}
        proc->register_emulated_module(mod);state.fs.create("C:\\"+mod->name)->write(raw.data(),raw.size());
        const auto until=space->alloc(4096,prot_rx|supervisor);const std::uint8_t trap=0xcc;space->write_mem(until,&trap,1);
        std::uint64_t driver_address=0;
        if(kind=="driver") {
            const auto driver=state.create_driver(*mod,u"EvokeGuest");conv->write_arg(*cpu,0,driver.driver_object.address());conv->write_arg(*cpu,1,driver.registry_path.address());
            driver_address=driver.driver_object.address();
        }
        auto resolve=[&](const json& value)->std::uint64_t {
            if(!value.is_object())return number(value);fields(value,{"image_rva"});const auto rva=number(value.at("image_rva"));
            if(rva>=image.bytes.size())throw std::invalid_argument("argument_rva_out_of_bounds");return base+rva;
        };
        if(args.contains("arguments")) {
            const auto& values=args.at("arguments");if(!values.is_array()||values.size()>16)throw std::invalid_argument("invalid_image_arguments");
            for(std::size_t i=0;i<values.size();++i)conv->write_arg(*cpu,i,resolve(values[i]));
        }
        const std::pair<const char*,reg_t> registers[]={{"rax",x86::rax},{"rbx",x86::rbx},{"rcx",x86::rcx},{"rdx",x86::rdx},{"rsi",x86::rsi},{"rdi",x86::rdi},{"rbp",x86::rbp},{"rsp",x86::rsp},{"r8",x86::r8},{"r9",x86::r9},{"r10",x86::r10},{"r11",x86::r11},{"r12",x86::r12},{"r13",x86::r13},{"r14",x86::r14},{"r15",x86::r15},{"rflags",x86::rflags}};
        if(args.contains("registers")) {
            const auto& values=args.at("registers");if(!values.is_object())throw std::invalid_argument("invalid_image_registers");
            for(const auto& item:values.items()) {
                bool found=false;for(const auto& [name,id]:registers)if(item.key()==name){cpu->reg(id,resolve(item.value()));found=true;break;}
                if(!found)throw std::invalid_argument("unsupported_image_register");
            }
        }
        space->write_mem(cpu->sp(),until);cpu->set_pc(base+entry);
        struct watch_range {std::uint32_t rva,size;std::vector<std::uint8_t> before;};std::vector<watch_range> watches;
        if(args.contains("watch")) {
            const auto& entries=args.at("watch");if(!entries.is_array()||entries.size()>8)throw std::invalid_argument("invalid_image_watch");
            for(const auto& e:entries) {
                fields(e,{"rva","size"});const auto rva=number(e.at("rva")),size=number(e.at("size"));
                if(!size||size>4096||rva>image.bytes.size()||size>image.bytes.size()-rva)throw std::invalid_argument("invalid_image_watch");
                std::vector<std::uint8_t> before(size);space->read_mem(base+rva,before.data(),size);watches.push_back({static_cast<std::uint32_t>(rva),static_cast<std::uint32_t>(size),std::move(before)});
            }
        }
        std::vector<std::uint64_t> addresses;for(const auto& [address,b]:bindings)addresses.push_back(address);
        execution_engine engine(*cpu,std::move(addresses),instruction_limit,trace_limit,execution_ms);
        json trace=json::array();std::string status;execution_event event;
        while(true) {
            event=engine.resume(until);status=event.status;if(status!="import"&&status!="syscall")break;
            if(trace.size()>=256){status="api_call_limit";break;}
            const bool syscall=status=="syscall";const handler* h=nullptr;std::string module,name;
            json call={{"source","kernemul"},{"address",hex(event.pc)},{"kind",syscall?"syscall":"import"},{"arguments",json::array()}};
            if(syscall) {
                const auto id=static_cast<std::uint32_t>(cpu->reg(x86::rax));call["syscall_id"]=id;
                const auto found=services.find(id);if(found==services.end()){status="unsupported_syscall";call["status"]=status;trace.push_back(call);break;}
                const auto& s=found->second;h=s.model;module=s.module;name=s.name;call["mapping_source"]=s.source;
                cpu->reg(x86::rcx,cpu->reg(x86::r10));
            }else {const auto& b=bindings.at(event.pc);h=b.model;module=b.module;name=b.name;call["implementation_module"]=b.implementation_module;}
            call["module"]=module;call["name"]=name;
            try {
                for(std::size_t i=0;i<h->arguments;++i)call["arguments"].push_back(hex(conv->arg<std::uint64_t>(*cpu,i)));
                // Read names before the handler can change its guest argument registers.
                json names=json::array();
                if(observations&&(name=="IoCreateDevice"||name=="IoCreateSymbolicLink")) {
                    const auto read_name=[&](unsigned argument) {
                        const auto addr=conv->arg<std::uint64_t>(*cpu,argument);if(!addr)return std::string();
                        const emu_object<_UNICODE_STRING> str(*space,addr);
                        if(str.read().Length>1024)throw std::invalid_argument("discovery_name_too_long");
                        return narrow_wstring(win::read_unicode_string(str));
                    };
                    try {if(name=="IoCreateDevice")names.push_back(read_name(2));
                        else {names.push_back(read_name(0));names.push_back(read_name(1));}}
                    catch(const std::exception&){names=json::array();}
                }
                h->fn(*cpu);call["return_value"]=h->returns_value?json(hex(conv->read_ret(*cpu))):json(nullptr);
                if(observations&&!names.empty()&&static_cast<std::int32_t>(conv->read_ret(*cpu))>=0) {
                    auto& events=(*observations)["namespace_events"];if(events.size()<64)
                        events.push_back({{"api",name},{"names",names},{"evidence","successful_modeled_api_call"}});
                }
                if(cpu->pc()==event.pc) {
                    if(syscall) {
                        const auto next=event.pc+event.instruction_size;
                        cpu->reg(x86::rcx,next);cpu->reg(x86::r11,cpu->reg(x86::rflags));cpu->set_pc(next);
                    }else cpu->set_pc(cpu->arch()->ret_addr(*cpu));
                }
                call["status"]="handled";
                const auto wt=std::dynamic_pointer_cast<win_thread>(thread);
                if(thread->is_sleeping()||thread->is_finished()||(wt&&(wt->is_waiting()||wt->suspend_count()))){status="guest_scheduling_required";call["status"]=status;}
            }catch(const std::exception& error){status="handler_error";call["status"]=status;call["error"]=error.what();}
            trace.push_back(std::move(call));if(status=="handler_error"||status=="guest_scheduling_required")break;
            engine.invalidate_code();
        }
        json instructions=json::array(),watch=json::array(),regs=json::object(),mapping=json::array();
        for(const auto& i:engine.trace())instructions.push_back({{"address",hex(i.address)},{"size",i.size},{"bytes_hex",encode(std::vector<std::uint8_t>(i.bytes.begin(),i.bytes.begin()+std::min<std::size_t>(i.size,15)))}});
        for(const auto& w:watches) {std::vector<std::uint8_t> after(w.size);space->read_mem(base+w.rva,after.data(),after.size());watch.push_back({{"rva",w.rva},{"before_hex",encode(w.before)},{"after_hex",encode(after)}});}
        for(const auto& [name,id]:registers)regs[name]=hex(cpu->reg(id));regs["rip"]=hex(cpu->pc());
        for(const auto& [id,s]:services)mapping.push_back({{"id",id},{"module",s.module},{"name",s.name},{"source",s.source}});
        if(observations&&driver_address) {
            (*observations)["driver_object_address"]=hex(driver_address);
            try {
                for(unsigned major=0;major<28;++major) {
                    const auto address=space->read_mem<std::uint64_t>(driver_address+offsetof(_DRIVER_OBJECT,MajorFunction)+major*8);
                    if(!address)continue;
                    json record={{"major",major},{"address",hex(address)},{"evidence","guest_driver_object"}};
                    if(address>=base&&address-base<image.bytes.size()&&image.is_executable(static_cast<std::uint32_t>(address-base)))record["rva"]=address-base;
                    else record["unresolved_target"]=true;
                    (*observations)["dispatch_routines"].push_back(record);
                }
            }catch(const std::exception& error){(*observations)["observation_error"]=error.what();}
        }
        return {{"status",status},{"source","kernemul"},{"image_source",args.contains("image_path")?"host_file":"supplied_hex"},{"kind",kind},{"image_base",hex(base)},{"entry_rva",entry},{"entry_return_value",hex(conv->read_ret(*cpu))},
            {"registers",regs},{"watch",watch},{"imports",resolved_imports},{"api_trace",trace},{"instruction_trace",instructions},{"instructions_observed",engine.observed()},
            {"trace_truncated",engine.observed()>trace_limit},{"fault_address",hex(event.fault_address)},{"interrupt",event.interrupt},
            {"syscall_mapping",mapping},{"unsupported_stub_exports",unsupported_stubs},{"numeric_syscall_dispatch",true},{"live_system_modified",false},
            {"state_lifetime","this_request"},{"guest_scheduler_execution",false},{"upstream_revision",EVOKE_KERNEMUL_REVISION}};
    }
