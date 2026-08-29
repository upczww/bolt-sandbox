cmake_minimum_required(VERSION 3.15)
project(bolt_sandbox_native LANGUAGES CXX)

enable_testing()

function(bolt_native_warnings target)
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
endfunction()

add_library(bolt-sandbox-protocol STATIC
    protocol/policy_payload.cpp
)
bolt_native_warnings(bolt-sandbox-protocol)
target_include_directories(bolt-sandbox-protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-protocol PRIVATE bcrypt)

add_library(bolt-sandbox-common STATIC
    common/execution_job.cpp
    common/private_pipe.cpp
)
bolt_native_warnings(bolt-sandbox-common)
target_include_directories(bolt-sandbox-common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-common PUBLIC advapi32)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_executable(bolt-sandbox-launcher
        launcher/main.cpp
    )
    bolt_native_warnings(bolt-sandbox-launcher)
endif()

add_library(bolt-sandbox-hook SHARED
    hook/dllmain.cpp
)
bolt_native_warnings(bolt-sandbox-hook)
target_include_directories(bolt-sandbox-hook PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-hook PRIVATE bolt-sandbox-protocol)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(bolt-sandbox-hook PROPERTIES OUTPUT_NAME bolt-sandbox-x64)
else()
    set_target_properties(bolt-sandbox-hook PROPERTIES OUTPUT_NAME bolt-sandbox-x86)
endif()

add_executable(bolt-sandbox-native-tests
    tests/job_tests.cpp
    tests/named_pipe_tests.cpp
    tests/policy_payload_tests.cpp
    tests/protocol_tests.cpp
)
bolt_native_warnings(bolt-sandbox-native-tests)
target_include_directories(bolt-sandbox-native-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-native-tests PRIVATE bolt-sandbox-protocol)
target_link_libraries(bolt-sandbox-native-tests PRIVATE bolt-sandbox-common)

add_test(NAME native.protocol COMMAND bolt-sandbox-native-tests)
