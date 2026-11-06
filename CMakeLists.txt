cmake_minimum_required(VERSION 3.25.0)

get_property(is_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT CMAKE_BUILD_TYPE AND NOT is_multi_config)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# We compile against c++20, but remain runnable against c++17
# Do NOT use any runtime-based features like:
#   <format>, <jthread>, <latch>, <barrier>, <syncstream>,
#   <chrono> tz/calendar, and others.
SET(CMAKE_CXX_STANDARD 20)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CMakeDependentOption)

option(USE_CONAN_PROVIDER "Use conan via cmake-conan" ON)

option(BUNDLE_GOXTUN "Bundle goxtun" ON)
option(BUNDLE_WINTUN "Bundle wintun" ON)

option(BINDINGS_CPP  "Build C++ bindings" ON)
option(BINDINGS_JAVA "Build Java bindings" OFF)
option(BINDINGS_SWIFT "Build Swift bindings (Xtun.xcframework, macOS host only)" OFF)

cmake_dependent_option(BUILD_TESTS "Build tests" ON "BUNDLE_GOXTUN;BUNDLE_WINTUN" OFF)

if(USE_CONAN_PROVIDER)
    include(${CMAKE_SOURCE_DIR}/cmake/cmake-conan/conan_bootstrap.cmake)
    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES
        ${CMAKE_SOURCE_DIR}/cmake/cmake-conan/conan_provider.cmake
        CACHE STRING "" FORCE)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/cmake/version.cmake)
project(xtun VERSION ${XTUN_VERSION_BASE})

add_library(${PROJECT_NAME}
    ${CMAKE_CURRENT_LIST_DIR}/src/error.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/health/dns_probe.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/health/dns_query.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/health/health_io.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/health/health_monitor.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/health/icmp_probe.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/health/scheduler.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/io/awaiting_io.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/io/remapping_io.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/net/checksum.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/net/ip.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/net/socket.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/proto/awg.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/proto/awg_conf.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/proto/xray.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/platform.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/proxy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/tunnel.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/killswitch.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/router.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dns.cpp
)
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /we4062)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Werror=switch)
endif()

add_subdirectory(goxtun)
target_include_directories(${PROJECT_NAME} PRIVATE $<TARGET_PROPERTY:goxtun,INTERFACE_INCLUDE_DIRECTORIES>)
if (BUNDLE_GOXTUN)
    target_link_libraries(${PROJECT_NAME} PRIVATE goxtun)
endif()

find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)

if(WIN32)
    find_package(wintun REQUIRED)
    target_include_directories(${PROJECT_NAME} PRIVATE $<TARGET_PROPERTY:amnezia::wintun,INTERFACE_INCLUDE_DIRECTORIES>)
    if (BUNDLE_WINTUN)
        target_link_libraries(${PROJECT_NAME} PRIVATE amnezia::wintun)
    endif()
    target_link_libraries(${PROJECT_NAME} PRIVATE iphlpapi ws2_32 fwpuclnt advapi32)
    target_compile_definitions(${PROJECT_NAME} PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
elseif(LINUX AND NOT ANDROID)
    find_package(libsystemd REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE libsystemd::libsystemd)
elseif(APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE "-framework SystemConfiguration" "-framework CoreFoundation")
endif()

if(BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    add_subdirectory(tests)
endif()

if (BINDINGS_CPP)
    add_subdirectory(cpp)
endif()

if (BINDINGS_JAVA)
    add_subdirectory(java)
endif()

if (BINDINGS_SWIFT)
    add_subdirectory(swift)
endif()

install(TARGETS ${PROJECT_NAME})
install(FILES include/xtun.h DESTINATION include)
