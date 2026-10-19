cmake_minimum_required(VERSION 3.20)
project(evoke_mcp VERSION 2.0.0 LANGUAGES CXX)

if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
include(FetchContent)
# A pinned archive and digest keep dependency resolution reproducible.
FetchContent_Declare(nlohmann_json
    URL https://codeload.github.com/nlohmann/json/tar.gz/refs/tags/v3.12.0
    URL_HASH SHA256=4b92eb0c06d10683f7447ce9406cb97cd4b453be18d7279320f7b2f025c10187)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(nlohmann_json)
find_package(Threads REQUIRED)

add_library(evoke_core
    driver-mcp/source/mcp/server.cpp
    driver-mcp/source/mcp/memory_service.cpp)
target_compile_features(evoke_core PUBLIC cxx_std_20)
target_include_directories(evoke_core PUBLIC driver-mcp/source/mcp)
target_link_libraries(evoke_core PUBLIC nlohmann_json::nlohmann_json Threads::Threads)

if(WIN32)
    if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "The Windows driver adapter requires x64")
    endif()
    add_executable(driver-mcp driver-mcp/source/entry/main.cpp)
    target_compile_definitions(driver-mcp PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
    target_link_libraries(driver-mcp PRIVATE evoke_core bcrypt ws2_32)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(evoke_tests tests/memory_tests.cpp)
    target_link_libraries(evoke_tests PRIVATE evoke_core)
    add_test(NAME evoke_tests COMMAND evoke_tests)
endif()
