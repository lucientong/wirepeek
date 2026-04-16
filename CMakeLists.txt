cmake_minimum_required(VERSION 3.20)
project(wirepeek
  VERSION 0.7.0
  LANGUAGES CXX
  DESCRIPTION "High-performance network packet analyzer with modern TUI"
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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

FetchContent_MakeAvailable(fmt spdlog CLI11 xxHash ftxui googletest)

# ── System dependencies ────────────────────────────────────────────────────────

find_package(Pcap REQUIRED)

# ── Subdirectories ─────────────────────────────────────────────────────────────

add_subdirectory(src)

enable_testing()
add_subdirectory(tests)
