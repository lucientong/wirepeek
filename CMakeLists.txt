cmake_minimum_required(VERSION 3.20)
project(wirepeek
  VERSION 1.2.0
  LANGUAGES CXX
  DESCRIPTION "High-performance network packet analyzer with modern TUI"
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(WIREPEEK_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(WIREPEEK_BUILD_FUZZERS "Build libFuzzer targets" OFF)
option(WIREPEEK_BUILD_BENCHMARKS "Build Google Benchmark targets" OFF)
option(WIREPEEK_ENABLE_TLS_DECRYPT "Enable experimental OpenSSL TLS decryption support" OFF)

if(WIREPEEK_ENABLE_SANITIZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    message(FATAL_ERROR "WIREPEEK_ENABLE_SANITIZERS requires Clang or GCC")
  endif()
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

if(WIREPEEK_BUILD_FUZZERS AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "WIREPEEK_BUILD_FUZZERS requires Clang")
endif()
if(WIREPEEK_BUILD_FUZZERS)
  add_compile_options(-fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address)
endif()

# Generate version header from CMake project version.
configure_file(
  ${CMAKE_SOURCE_DIR}/include/wirepeek/version.h.in
  ${CMAKE_BINARY_DIR}/generated/wirepeek/version.h
  @ONLY
)

# Compiler warnings
add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

# Custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# ── Dependencies via FetchContent ──────────────────────────────────────────────

include(FetchContent)

FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 10.2.1
  GIT_SHALLOW TRUE
)

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.14.1
  GIT_SHALLOW TRUE
)
set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "" FORCE)

FetchContent_Declare(
  CLI11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
  GIT_TAG v2.4.2
  GIT_SHALLOW TRUE
)

FetchContent_Declare(
  xxHash
  GIT_REPOSITORY https://github.com/Cyan4973/xxHash.git
  GIT_TAG v0.8.3
  GIT_SHALLOW TRUE
  SOURCE_SUBDIR cmake_unofficial
)

FetchContent_Declare(
  ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
  GIT_TAG v5.0.0
  GIT_SHALLOW TRUE
)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.15.2
  GIT_SHALLOW TRUE
)

if(WIREPEEK_BUILD_BENCHMARKS)
  set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG v1.9.1
    GIT_SHALLOW TRUE
  )
endif()

FetchContent_MakeAvailable(fmt spdlog CLI11 xxHash ftxui googletest)
if(WIREPEEK_BUILD_BENCHMARKS)
  FetchContent_MakeAvailable(benchmark)
endif()

# ── System dependencies ────────────────────────────────────────────────────────

find_package(Pcap REQUIRED)
if(WIREPEEK_ENABLE_TLS_DECRYPT)
  find_package(OpenSSL REQUIRED)
  # FindOpenSSL exposed OPENSSL_VERSION before CMake 4.2 and OpenSSL_VERSION
  # starting with CMake 4.2. Support both spellings so CI and local builds agree.
  if(DEFINED OpenSSL_VERSION)
    set(WIREPEEK_OPENSSL_VERSION "${OpenSSL_VERSION}")
  else()
    set(WIREPEEK_OPENSSL_VERSION "${OPENSSL_VERSION}")
  endif()
  if(NOT WIREPEEK_OPENSSL_VERSION OR WIREPEEK_OPENSSL_VERSION VERSION_LESS "3.0.0")
    message(FATAL_ERROR
      "WIREPEEK_ENABLE_TLS_DECRYPT requires OpenSSL 3.x "
      "(found ${WIREPEEK_OPENSSL_VERSION})")
  endif()
endif()

# ── Subdirectories ─────────────────────────────────────────────────────────────

add_subdirectory(src)

enable_testing()
add_subdirectory(tests)

if(WIREPEEK_BUILD_FUZZERS)
  add_subdirectory(tests/fuzz)
endif()

if(WIREPEEK_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()
