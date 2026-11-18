find_package(GTest REQUIRED)
include(GoogleTest)

set(XTUN_TEST_SOURCES
    test_contract.cpp
    test_dns.cpp
    test_killswitch.cpp
    test_net_dns.cpp
    test_net_ip.cpp
    test_net_socket.cpp
    test_net_packet_builder.cpp
    test_proxy.cpp
    test_router.cpp
    test_routing.cpp
    test_scenario.cpp
    test_tunnel.cpp
)

add_executable(xtun_tests ${XTUN_TEST_SOURCES})
target_link_libraries(xtun_tests PRIVATE xtun GTest::gtest GTest::gtest_main)
target_include_directories(xtun_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(xtun_tests PRIVATE
    XTUN_TEST_SECRETS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/secrets")

if(WIN32)
    target_sources(xtun_tests PRIVATE test_split_tunnel_windows.cpp test_wfp_windows.cpp)
    target_link_libraries(xtun_tests PRIVATE amnezia::wintun advapi32 iphlpapi fwpuclnt)

    add_custom_command(TARGET xtun_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_RUNTIME_DLLS:xtun_tests>
                "$<TARGET_PROPERTY:amnezia::wintun,INTERFACE_INCLUDE_DIRECTORIES>/../bin/wintun.dll"
                $<TARGET_FILE_DIR:xtun_tests>
        COMMAND_EXPAND_LISTS)

    find_package(win-split-tunnel QUIET)
    if(win-split-tunnel_FOUND)
        add_test(NAME install_split_driver
                 COMMAND powershell -NoProfile -ExecutionPolicy Bypass
                         -File "${CMAKE_CURRENT_SOURCE_DIR}/install-split-driver.ps1" -Source "${WIN_SPLIT_TUNNEL_BIN}")
        set_tests_properties(install_split_driver PROPERTIES FIXTURES_SETUP SplitDriver SKIP_RETURN_CODE 77)
    endif()
endif()

gtest_discover_tests(xtun_tests TEST_FILTER "Killswitch*:Dns*:Routing*" PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE)
# These tests own the driver while they run, so they must not run in parallel with other tests.
gtest_discover_tests(xtun_tests TEST_FILTER "SplitTunnelDriver*"
                     PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE FIXTURES_REQUIRED SplitDriver)
gtest_discover_tests(xtun_tests TEST_FILTER "-Killswitch*:Dns*:Routing*:SplitTunnelDriver*" PROPERTIES TIMEOUT 30)
