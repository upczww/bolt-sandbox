cmake_minimum_required(VERSION 3.15)
project(bolt_sandbox_native LANGUAGES CXX)

enable_testing()

add_executable(bolt-sandbox-native-tests
    tests/protocol_tests.cpp
)
target_compile_features(bolt-sandbox-native-tests PRIVATE cxx_std_17)
target_compile_options(bolt-sandbox-native-tests PRIVATE /W4 /WX /permissive-)
target_include_directories(bolt-sandbox-native-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME native.protocol COMMAND bolt-sandbox-native-tests)
