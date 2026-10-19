# Required Windows handler runtime. Upstream is fetched as source, not configured
# through its standalone CMake project (which also downloads a vcpkg checkout).
file(READ "${CMAKE_CURRENT_LIST_DIR}/kernemul/dependencies.json" evoke_dependencies)
foreach(dep kernemul pe ia32 raw_pdb spdlog)
    string(JSON dep_url GET "${evoke_dependencies}" "${dep}" url)
    string(JSON dep_hash GET "${evoke_dependencies}" "${dep}" sha256)
    FetchContent_Declare(evoke_${dep} URL "${dep_url}" URL_HASH "SHA256=${dep_hash}"
        SOURCE_SUBDIR _evoke_source_only)
    FetchContent_MakeAvailable(evoke_${dep})
endforeach()
get_filename_component(evoke_source_parent "${evoke_kernemul_SOURCE_DIR}" DIRECTORY)
set(evoke_adapter_previous "${evoke_kernemul_BINARY_DIR}/evoke-applied.patch")
if(EXISTS "${evoke_adapter_previous}")
    file(READ "${evoke_adapter_previous}" old_adapter)
    file(READ "${CMAKE_CURRENT_LIST_DIR}/kernemul/adapter.patch" new_adapter)
    if(NOT old_adapter STREQUAL new_adapter)
        execute_process(COMMAND "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${evoke_source_parent}" git apply --reverse --check "${evoke_adapter_previous}"
            WORKING_DIRECTORY "${evoke_kernemul_SOURCE_DIR}" RESULT_VARIABLE old_applied OUTPUT_QUIET ERROR_QUIET)
        if(old_applied EQUAL 0)
            execute_process(COMMAND "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${evoke_source_parent}" git apply --reverse "${evoke_adapter_previous}"
                WORKING_DIRECTORY "${evoke_kernemul_SOURCE_DIR}" RESULT_VARIABLE reverted)
            if(NOT reverted EQUAL 0)
                message(FATAL_ERROR "Cannot update previous KernEmul adapter")
            endif()
        endif()
    endif()
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${evoke_source_parent}" git apply --reverse --check "${CMAKE_CURRENT_LIST_DIR}/kernemul/adapter.patch"
    WORKING_DIRECTORY "${evoke_kernemul_SOURCE_DIR}" RESULT_VARIABLE adapted OUTPUT_QUIET ERROR_QUIET)
if(NOT adapted EQUAL 0)
    execute_process(COMMAND "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${evoke_source_parent}" git apply "${CMAKE_CURRENT_LIST_DIR}/kernemul/adapter.patch"
        WORKING_DIRECTORY "${evoke_kernemul_SOURCE_DIR}" RESULT_VARIABLE adapted ERROR_VARIABLE adaptation_error)
    if(NOT adapted EQUAL 0)
        message(FATAL_ERROR "KernEmul adapter patch failed: ${adaptation_error}")
    endif()
endif()
configure_file("${CMAKE_CURRENT_LIST_DIR}/kernemul/adapter.patch" "${evoke_adapter_previous}" COPYONLY)
# Use KernEmul's patched Unicorn revision for both emulation paths.
string(JSON dep_url GET "${evoke_dependencies}" unicorn url)
string(JSON dep_hash GET "${evoke_dependencies}" unicorn sha256)
set(unicorn_patches "${evoke_kernemul_SOURCE_DIR}/patches/unicorn-arm64-fault-regs.patch|${evoke_kernemul_SOURCE_DIR}/patches/unicorn-x86-clear-old-exception.patch|${evoke_kernemul_SOURCE_DIR}/patches/unicorn-x86-ss-cpl.patch|${evoke_kernemul_SOURCE_DIR}/patches/unicorn-x86-cpu-identity.patch")
FetchContent_Declare(unicorn URL "${dep_url}" URL_HASH "SHA256=${dep_hash}"
    PATCH_COMMAND "${CMAKE_COMMAND}" "-DSRC=<SOURCE_DIR>" "-DPATCHES=${unicorn_patches}"
        -P "${evoke_kernemul_SOURCE_DIR}/cmake/apply_patch.cmake")
FetchContent_MakeAvailable(unicorn)
# Apply explicitly too: tar sources can live inside this checkout. Stop Git from
# resolving the parent repository and silently skipping dependency-relative paths.
get_filename_component(evoke_unicorn_parent "${unicorn_SOURCE_DIR}" DIRECTORY)
execute_process(COMMAND "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${evoke_unicorn_parent}"
    "${CMAKE_COMMAND}" "-DSRC=${unicorn_SOURCE_DIR}" "-DPATCHES=${unicorn_patches}"
    -P "${evoke_kernemul_SOURCE_DIR}/cmake/apply_patch.cmake" RESULT_VARIABLE unicorn_patch_result)
if(NOT unicorn_patch_result EQUAL 0)
    message(FATAL_ERROR "Required KernEmul Unicorn patches failed")
endif()
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory("${evoke_spdlog_SOURCE_DIR}" "${evoke_spdlog_BINARY_DIR}" EXCLUDE_FROM_ALL)
add_subdirectory("${evoke_raw_pdb_SOURCE_DIR}" "${evoke_raw_pdb_BINARY_DIR}" EXCLUDE_FROM_ALL)
find_package(OpenSSL REQUIRED)
file(GLOB_RECURSE evoke_kernemul_sources CONFIGURE_DEPENDS "${evoke_kernemul_SOURCE_DIR}/src/*.cpp")
list(FILTER evoke_kernemul_sources EXCLUDE REGEX "/main\\.cpp$|/emu/x86/whp\\.cpp$")
add_executable(evoke-kernemul driver-mcp/source/kernemul/worker.cpp driver-mcp/source/kernemul/execution_engine.cpp ${evoke_kernemul_sources})
target_compile_features(evoke-kernemul PRIVATE cxx_std_23)
target_compile_definitions(evoke-kernemul PRIVATE KERNEMUL_ARCH_X64=1 NOMINMAX
    EVOKE_KERNEMUL_REVISION="cf3aedc6cc1755d2fedad77dcd4671bf045f9de8")
target_include_directories(evoke-kernemul PRIVATE "${evoke_kernemul_SOURCE_DIR}/src"
    "${evoke_pe_SOURCE_DIR}/src" "${evoke_ia32_SOURCE_DIR}/out")
target_link_libraries(evoke-kernemul PRIVATE unicorn raw_pdb spdlog::spdlog
    OpenSSL::Crypto nlohmann_json::nlohmann_json Threads::Threads)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(evoke-kernemul PRIVATE -mms-bitfields -Wno-changes-meaning -Wno-error)
endif()
if(MSVC)
    target_compile_options(evoke-kernemul PRIVATE /Zc:preprocessor /bigobj)
endif()
