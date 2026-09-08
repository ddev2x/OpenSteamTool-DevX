cmake_minimum_required(VERSION 3.20)
project(OpenSteamToolTools LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "" FORCE)

add_executable(ipc_codegen
    ipc_codegen/ipc_codegen.cpp
)
target_compile_features(ipc_codegen PRIVATE cxx_std_20)


if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "extract_tickets requires 64-bit Windows")
endif()
add_library(extract_tickets SHARED
    extract_tickets/extract_tickets.cpp
)
target_compile_features(extract_tickets PRIVATE cxx_std_20)
target_compile_definitions(extract_tickets PRIVATE EXTRACT_TICKETS_BUILD)
if(MSVC)
    set_property(TARGET extract_tickets PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
target_link_libraries(extract_tickets PRIVATE advapi32)
target_include_directories(extract_tickets PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/extract_tickets)
