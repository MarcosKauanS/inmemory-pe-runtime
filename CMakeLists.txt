cmake_minimum_required(VERSION 3.20)
project(inmemory_pe_runtime
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enforce 64-bit target architecture
if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "inmemory-pe-runtime requires a 64-bit target architecture (x64 / AMD64).")
endif()

# Strict compiler warnings for MSVC
if (MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /Oi)
endif()

# Core static library implementing the manual PE loader engine
add_library(inmemory_pe_core STATIC
    src/loader.cpp
)

target_include_directories(inmemory_pe_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(inmemory_pe_core PUBLIC cxx_std_20)

# Standalone CLI runner executable
add_executable(pe_runner
    src/main.cpp
)

target_link_libraries(pe_runner PRIVATE
    inmemory_pe_core
)

target_compile_features(pe_runner PRIVATE cxx_std_20)

# Sample validation DLL fixture
add_subdirectory(tests/fixtures)
