cmake_minimum_required(VERSION 3.20)
project(vault_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)
find_package(pybind11 CONFIG REQUIRED)

# BLAKE3 C sources (cloned into native/third_party/BLAKE3 by the Docker build).
set(B3 ${CMAKE_CURRENT_SOURCE_DIR}/third_party/BLAKE3/c)
add_library(blake3 STATIC ${B3}/blake3.c ${B3}/blake3_dispatch.c ${B3}/blake3_portable.c)
# Simplest portable build: disable SIMD variants (enable them later for speed).
target_compile_definitions(blake3 PRIVATE BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_USE_NEON=0)
target_include_directories(blake3 PUBLIC ${B3})

pybind11_add_module(vault_native src/bindings.cpp src/erasure.cpp src/bitrot.cpp)
target_link_libraries(vault_native PRIVATE blake3 isal)
target_compile_options(vault_native PRIVATE -O3 -march=x86-64-v2)
install(TARGETS vault_native DESTINATION .)
