cmake_minimum_required(VERSION 3.15)
project(bolt_sandbox_native LANGUAGES CXX)

enable_testing()

function(bolt_native_warnings target)
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
endfunction()

set(DETOURS_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/detours/src)
add_library(bolt-sandbox-detours STATIC
    ${DETOURS_SOURCE_DIR}/creatwth.cpp
    ${DETOURS_SOURCE_DIR}/detours.cpp
    ${DETOURS_SOURCE_DIR}/disasm.cpp
    ${DETOURS_SOURCE_DIR}/disolarm.cpp
    ${DETOURS_SOURCE_DIR}/disolarm64.cpp
    ${DETOURS_SOURCE_DIR}/disolia64.cpp
    ${DETOURS_SOURCE_DIR}/disolx64.cpp
    ${DETOURS_SOURCE_DIR}/disolx86.cpp
    ${DETOURS_SOURCE_DIR}/image.cpp
    ${DETOURS_SOURCE_DIR}/modules.cpp
)
target_compile_options(bolt-sandbox-detours PRIVATE /W4 /WX)
target_compile_definitions(bolt-sandbox-detours PRIVATE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(bolt-sandbox-detours PUBLIC _AMD64_)
else()
    target_compile_definitions(bolt-sandbox-detours PUBLIC _X86_)
endif()
target_include_directories(bolt-sandbox-detours PUBLIC ${DETOURS_SOURCE_DIR})

set(BUILDXL_DETOURS_SERVICES_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/buildxl/Public/Src/Sandbox/Windows/DetoursServices
)
set(BUILDXL_ADAPTED_DIR ${CMAKE_CURRENT_BINARY_DIR}/buildxl-adapted)
file(MAKE_DIRECTORY ${BUILDXL_ADAPTED_DIR})
foreach(BUILDXL_PATH_CORE_FILE
    CanonicalizedPath.cpp
    CanonicalizedPath.h
    FilesCheckedForAccess.cpp
    FilesCheckedForAccess.h
    PathTree.cpp
    PathTree.h
    ResolvedPathCache.h
    TreeNode.cpp
    TreeNode.h
)
    configure_file(
        ${BUILDXL_DETOURS_SERVICES_DIR}/${BUILDXL_PATH_CORE_FILE}
        ${BUILDXL_ADAPTED_DIR}/${BUILDXL_PATH_CORE_FILE}
        COPYONLY
    )
endforeach()
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/adapters/buildxl/FileAccessHelpers.h
    ${BUILDXL_ADAPTED_DIR}/FileAccessHelpers.h
    COPYONLY
)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/adapters/buildxl/UtilityHelpers.h
    ${BUILDXL_ADAPTED_DIR}/UtilityHelpers.h
    COPYONLY
)
configure_file(
    ${BUILDXL_DETOURS_SERVICES_DIR}/StringOperations.h
    ${BUILDXL_ADAPTED_DIR}/StringOperations.h
    COPYONLY
)
configure_file(
    ${BUILDXL_DETOURS_SERVICES_DIR}/DetouredFunctionTypes.h
    ${BUILDXL_ADAPTED_DIR}/DetouredFunctionTypes.h
    COPYONLY
)
configure_file(
    ${BUILDXL_DETOURS_SERVICES_DIR}/DetouredScope.cpp
    ${BUILDXL_ADAPTED_DIR}/DetouredScope.cpp
    COPYONLY
)
configure_file(
    ${BUILDXL_DETOURS_SERVICES_DIR}/DetouredScope.h
    ${BUILDXL_ADAPTED_DIR}/DetouredScope.h
    COPYONLY
)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/adapters/buildxl/stdafx.h
    ${BUILDXL_ADAPTED_DIR}/stdafx.h
    COPYONLY
)
add_library(bolt-sandbox-buildxl STATIC
    ${BUILDXL_DETOURS_SERVICES_DIR}/Assertions.cpp
    ${BUILDXL_DETOURS_SERVICES_DIR}/StringOperations.cpp
    ${BUILDXL_ADAPTED_DIR}/CanonicalizedPath.cpp
    ${BUILDXL_ADAPTED_DIR}/DetouredScope.cpp
    ${BUILDXL_ADAPTED_DIR}/FilesCheckedForAccess.cpp
    ${BUILDXL_ADAPTED_DIR}/PathTree.cpp
    ${BUILDXL_ADAPTED_DIR}/TreeNode.cpp
)
bolt_native_warnings(bolt-sandbox-buildxl)
target_compile_definitions(bolt-sandbox-buildxl PRIVATE _DO_NOT_EXPORT TEST)
target_include_directories(bolt-sandbox-buildxl PUBLIC
    ${BUILDXL_ADAPTED_DIR}
)
target_include_directories(bolt-sandbox-buildxl PRIVATE
    ${BUILDXL_DETOURS_SERVICES_DIR}
    ${DETOURS_SOURCE_DIR}
)
target_link_libraries(bolt-sandbox-buildxl PRIVATE pathcch)

# Compile the complete upstream interception translation unit as an immutable
# compatibility contract. It is intentionally not linked into Bolt until its
# BuildXL policy/report seams have been replaced by PolicyView and EventSink.
add_library(bolt-sandbox-buildxl-detoured-functions OBJECT
    ${BUILDXL_DETOURS_SERVICES_DIR}/DetouredFunctions.cpp
)
bolt_native_warnings(bolt-sandbox-buildxl-detoured-functions)
target_compile_definitions(
    bolt-sandbox-buildxl-detoured-functions PRIVATE
        _DO_NOT_EXPORT
        UNICODE
        _UNICODE
)
target_compile_options(
    bolt-sandbox-buildxl-detoured-functions PRIVATE
        /wd4189
        /wd4595
)
target_include_directories(bolt-sandbox-buildxl-detoured-functions PRIVATE
    ${BUILDXL_DETOURS_SERVICES_DIR}
    ${DETOURS_SOURCE_DIR}
)

add_library(bolt-sandbox-protocol STATIC
    protocol/dns_proxy_startup.cpp
    protocol/dns_proxy_protocol.cpp
    protocol/tcp_proxy_protocol.cpp
    protocol/event_frame.cpp
    protocol/inherited_handle_payload.cpp
    protocol/launcher_control.cpp
    protocol/launcher_startup.cpp
    protocol/launcher_transport.cpp
    protocol/policy_payload.cpp
    protocol/projected_workspace_protocol.cpp
    protocol/recovery_protocol.cpp
    protocol/runtime_payload.cpp
    protocol/workspace_security_protocol.cpp
)
bolt_native_warnings(bolt-sandbox-protocol)
target_include_directories(bolt-sandbox-protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-protocol PRIVATE bcrypt)

add_library(bolt-sandbox-common STATIC
    common/immutable_mapping.cpp
    common/execution_job.cpp
    common/immutable_policy_mapping.cpp
    common/private_pipe.cpp
    common/projfs_api.cpp
    common/projected_workspace_provider.cpp
    common/pseudo_console.cpp
    common/suspended_process.cpp
    common/workspace_security.cpp
)
bolt_native_warnings(bolt-sandbox-common)
target_include_directories(bolt-sandbox-common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-common PUBLIC advapi32 ole32)
target_link_libraries(bolt-sandbox-common PRIVATE bolt-sandbox-detours)
target_link_libraries(bolt-sandbox-common PRIVATE bolt-sandbox-protocol)

add_library(bolt-sandbox-process STATIC
    hook/process/process_mitigations.cpp
    hook/process/process_hooks.cpp
)

bolt_native_warnings(bolt-sandbox-process)
target_include_directories(bolt-sandbox-process PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-process PRIVATE
    bolt-sandbox-buildxl
    bolt-sandbox-detours
    bolt-sandbox-protocol
    shell32
)

add_library(bolt-sandbox-network STATIC
    hook/network/bounded_dns_resolver.cpp
    hook/network/dns_binding_table.cpp
    hook/network/dns_proxy_server.cpp
    hook/network/dns_proxy_session.cpp
    hook/network/dns_proxy_client.cpp
    hook/network/dns_proxy_client_channel.cpp
    hook/network/dns_proxy_process.cpp
    hook/network/dns_proxy_handle_transport.cpp
    hook/network/dns_record_parser.cpp
    hook/network/http_connect_policy.cpp
    hook/network/network_hooks.cpp
    hook/network/network_policy.cpp
    hook/network/socket_target_table.cpp
    hook/network/system_dns_resolver.cpp
    hook/network/system_tcp_connector.cpp
    hook/network/tcp_relay.cpp
    hook/network/tcp_proxy_connection.cpp
    hook/network/tcp_proxy_client.cpp
    hook/network/tcp_proxy_listener.cpp
    hook/network/tcp_proxy_server.cpp
    hook/network/winhttp_hooks.cpp
    hook/network/wininet_hooks.cpp
)
bolt_native_warnings(bolt-sandbox-network)
target_include_directories(bolt-sandbox-network PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-network PRIVATE
    bolt-sandbox-buildxl
    bolt-sandbox-common
    bolt-sandbox-detours
    bolt-sandbox-protocol
    dnsapi
    winhttp
    wininet
    ws2_32
)

add_library(bolt-sandbox-registry STATIC
    hook/registry/registry_hooks.cpp
    hook/registry/registry_policy.cpp
)
bolt_native_warnings(bolt-sandbox-registry)
target_include_directories(bolt-sandbox-registry PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-registry PRIVATE
    advapi32
    bolt-sandbox-detours
    bolt-sandbox-protocol
)

add_library(bolt-sandbox-filesystem STATIC
    hook/event_sink.cpp
    hook/recovery/recovery_client.cpp
    hook/filesystem/access_classifier.cpp
    hook/filesystem/final_path_resolver.cpp
    hook/filesystem/file_hooks.cpp
    hook/filesystem/filesystem_policy.cpp
    hook/filesystem/handle_access_cache.cpp
    hook/filesystem/path_cache.cpp
    hook/filesystem/policy_decision_cache.cpp
    hook/filesystem/safe_device.cpp
)
bolt_native_warnings(bolt-sandbox-filesystem)
target_include_directories(bolt-sandbox-filesystem PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-filesystem PRIVATE
    advapi32
    bolt-sandbox-buildxl
    bolt-sandbox-detours
    bolt-sandbox-process
    bolt-sandbox-protocol
    ole32
    shell32
)

add_executable(bolt-sandbox-launcher
    launcher/main.cpp
)
bolt_native_warnings(bolt-sandbox-launcher)
target_include_directories(bolt-sandbox-launcher PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-launcher PRIVATE
    bolt-sandbox-common
    bolt-sandbox-network
    bolt-sandbox-protocol
    bcrypt
)
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(
        bolt-sandbox-launcher PROPERTIES OUTPUT_NAME bolt-sandbox-launcher-x86
    )
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_executable(bolt-sandbox-dns-proxy
        dns_proxy/main.cpp
    )
    bolt_native_warnings(bolt-sandbox-dns-proxy)
    target_include_directories(bolt-sandbox-dns-proxy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(bolt-sandbox-dns-proxy PRIVATE
        bolt-sandbox-network
        bolt-sandbox-protocol
    )
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(BOLT_HOOK_EXPORTS hook/hook-x64.def)
else()
    set(BOLT_HOOK_EXPORTS hook/hook-x86.def)
endif()
add_library(bolt-sandbox-hook SHARED
    hook/dllmain.cpp
    ${BOLT_HOOK_EXPORTS}
)
bolt_native_warnings(bolt-sandbox-hook)
target_include_directories(bolt-sandbox-hook PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bolt-sandbox-hook PRIVATE bolt-sandbox-protocol bolt-sandbox-detours)
target_link_libraries(bolt-sandbox-hook PRIVATE bolt-sandbox-filesystem)
target_link_libraries(bolt-sandbox-hook PRIVATE bolt-sandbox-network)
target_link_libraries(bolt-sandbox-hook PRIVATE bolt-sandbox-registry)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(bolt-sandbox-hook PROPERTIES OUTPUT_NAME bolt-sandbox-x64)
else()
    set_target_properties(bolt-sandbox-hook PROPERTIES OUTPUT_NAME bolt-sandbox-x86)
endif()

add_executable(bolt-sandbox-native-tests
    tests/bounded_dns_resolver_tests.cpp
    tests/buildxl_tree_tests.cpp
    tests/detours_tests.cpp
    tests/event_frame_tests.cpp
    tests/handle_access_cache_tests.cpp
    tests/policy_decision_cache_tests.cpp
    tests/filesystem_policy_tests.cpp
    tests/filesystem_race_tests.cpp
    tests/job_tests.cpp
    tests/launcher_startup_tests.cpp
    tests/named_pipe_tests.cpp
    tests/network_policy_tests.cpp
    tests/registry_policy_tests.cpp
    tests/recovery_fixture.cpp
    tests/registry_hook_tests.cpp
    tests/http_connect_policy_tests.cpp
    tests/system_dns_resolver_tests.cpp
    tests/network_hook_tests.cpp
    tests/network_initialization_failure_tests.cpp
    tests/network_startup_handle_tests.cpp
    tests/network_event_saturation_tests.cpp
    tests/winhttp_test_client.cpp
    tests/wininet_test_client.cpp
    tests/dns_binding_tests.cpp
    tests/dns_record_parser_tests.cpp
    tests/dns_proxy_protocol_tests.cpp
    tests/tcp_proxy_protocol_tests.cpp
    tests/tcp_proxy_server_tests.cpp
    tests/system_tcp_connector_tests.cpp
    tests/tcp_relay_tests.cpp
    tests/tcp_proxy_connection_tests.cpp
    tests/tcp_proxy_client_tests.cpp
    tests/socket_target_table_tests.cpp
    tests/dns_proxy_server_tests.cpp
    tests/dns_proxy_session_tests.cpp
    tests/dns_proxy_process_tests.cpp
    tests/dns_proxy_client_tests.cpp
    tests/dns_proxy_client_channel_tests.cpp
    tests/dns_proxy_handle_transport_tests.cpp
    tests/dns_proxy_startup_tests.cpp
    tests/policy_payload_tests.cpp
    tests/policy_fixture.cpp
    tests/policy_mapping_tests.cpp
    tests/projfs_api_tests.cpp
    tests/projected_workspace_provider_tests.cpp
    tests/projected_workspace_protocol_tests.cpp
    tests/immutable_mapping_tests.cpp
    tests/inherited_handle_payload_tests.cpp
    tests/process_tests.cpp
    tests/protocol_mutation_tests.cpp
    tests/protocol_tests.cpp
    tests/runtime_payload_tests.cpp
    tests/shell_file_operation_tests.cpp
    tests/stream_tests.cpp
    tests/workspace_security_tests.cpp
    tests/workspace_security_protocol_tests.cpp
)
bolt_native_warnings(bolt-sandbox-native-tests)
target_include_directories(bolt-sandbox-native-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(bolt-sandbox-native-tests PRIVATE bolt-sandbox-protocol)
target_link_libraries(bolt-sandbox-native-tests PRIVATE bolt-sandbox-common)
target_link_libraries(bolt-sandbox-native-tests PRIVATE bolt-sandbox-detours)
target_link_libraries(bolt-sandbox-native-tests PRIVATE bolt-sandbox-buildxl)
target_link_libraries(
    bolt-sandbox-native-tests PRIVATE
        bolt-sandbox-filesystem
        bolt-sandbox-network
        bolt-sandbox-registry
        advapi32
        bcrypt
        dnsapi
        ole32
        shell32
        winhttp
        wininet
        ws2_32
)

add_test(NAME native.protocol COMMAND bolt-sandbox-native-tests)
add_test(
    NAME native.startup_latency
    COMMAND bolt-sandbox-native-tests --process-startup-latency-tests
)
add_dependencies(bolt-sandbox-native-tests bolt-sandbox-hook)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_dependencies(bolt-sandbox-native-tests bolt-sandbox-dns-proxy)
endif()
