add_executable(protocol_engine_tests
    test_main.cpp
    test_config.cpp
    test_packet_source.cpp
    test_engine.cpp
    test_decoders.cpp
    test_flow_and_reassembly.cpp
    test_app_protocols.cpp
)

target_include_directories(protocol_engine_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../packages/contracts/cpp/include
)

target_link_libraries(protocol_engine_tests PRIVATE protocol_engine_core)

add_test(NAME ProtocolEngineUnitTests COMMAND protocol_engine_tests)
