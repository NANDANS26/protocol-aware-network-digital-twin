cmake_minimum_required(VERSION 3.20)
project(protocol_engine VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings and diagnostic flags
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Sanitizer options (documented for local debugging & CI)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

if(ENABLE_ASAN)
    if(MSVC)
        add_compile_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address)
        add_link_options(-fsanitize=address)
    endif()
endif()

if(ENABLE_UBSAN)
    if(NOT MSVC)
        add_compile_options(-fsanitize=undefined)
        add_link_options(-fsanitize=undefined)
    endif()
endif()

# Core static library
add_library(protocol_engine_core STATIC
    src/config.cpp
    src/logger.cpp
    src/capture_reader.cpp
    src/packet_source.cpp
    src/engine.cpp
    src/decoders/decoder_types.cpp
    src/decoders/ethernet_decoder.cpp
    src/decoders/ipv4_decoder.cpp
    src/decoders/ipv6_decoder.cpp
    src/decoders/arp_decoder.cpp
    src/decoders/icmp_decoder.cpp
    src/decoders/tcp_decoder.cpp
    src/decoders/udp_decoder.cpp
    src/flow/flow_key.cpp
    src/flow/tcp_state_tracker.cpp
    src/flow/flow_table.cpp
    src/reassembly/tcp_stream_reassembler.cpp
    src/protocols/dns_parser.cpp
    src/protocols/ptp_parser.cpp
    src/protocols/http_parser.cpp
    src/protocols/tls_parser.cpp
    src/protocols/quic_classifier.cpp
    src/crypto/sha256.cpp
    src/analysis_pipeline.cpp
)

target_include_directories(protocol_engine_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../packages/contracts/cpp/include>
    $<INSTALL_INTERFACE:include>
)

# Standalone executable
add_executable(protocol_engine src/main.cpp)
target_link_libraries(protocol_engine PRIVATE protocol_engine_core)

# Enable testing
enable_testing()
add_subdirectory(tests)
