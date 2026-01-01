cmake_minimum_required(VERSION 3.16)
project(argus_native VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /WX- /O2 /MP)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -O2)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -fsanitize=address)
        add_link_options(-fsanitize=address)
    endif()
endif()

# ============================================================================
# System Info Library
# ============================================================================

add_library(argus_sysinfo SHARED
    sysinfo/src/sysinfo.cpp
)

target_include_directories(argus_sysinfo
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sysinfo/include>
        $<INSTALL_INTERFACE:include>
)

if(WIN32)
    target_link_libraries(argus_sysinfo PRIVATE
        pdh
        psapi
        iphlpapi
        ws2_32
    )
    target_compile_definitions(argus_sysinfo PRIVATE SYSINFO_EXPORTS)
else()
    target_link_libraries(argus_sysinfo PRIVATE pthread)
endif()

set_target_properties(argus_sysinfo PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "argus_sysinfo"
)

# ============================================================================
# Process Manager Library (optional additional module)
# ============================================================================

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/procmgr/src/procmgr.cpp")
    add_library(argus_procmgr SHARED
        procmgr/src/procmgr.cpp
    )

    target_include_directories(argus_procmgr
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/procmgr/include>
            $<INSTALL_INTERFACE:include>
    )

    if(WIN32)
        target_link_libraries(argus_procmgr PRIVATE psapi)
    endif()

    set_target_properties(argus_procmgr PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 1
        OUTPUT_NAME "argus_procmgr"
    )
endif()

# ============================================================================
# Static Library for Go CGO binding
# ============================================================================

add_library(argus_sysinfo_static STATIC
    sysinfo/src/sysinfo.cpp
)

target_include_directories(argus_sysinfo_static
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sysinfo/include>
)

if(WIN32)
    target_link_libraries(argus_sysinfo_static PUBLIC
        pdh
        psapi
        iphlpapi
        ws2_32
    )
    target_compile_definitions(argus_sysinfo_static PRIVATE SYSINFO_EXPORTS)
else()
    target_link_libraries(argus_sysinfo_static PUBLIC pthread)
endif()

set_target_properties(argus_sysinfo_static PROPERTIES
    OUTPUT_NAME "argus_sysinfo_static"
)

# ============================================================================
# Installation
# ============================================================================

include(GNUInstallDirs)

install(TARGETS argus_sysinfo argus_sysinfo_static
    EXPORT argus_native_targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY sysinfo/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT argus_native_targets
    FILE argus_native_targets.cmake
    NAMESPACE argus::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/argus_native
)

# ============================================================================
# Test executable
# ============================================================================

option(BUILD_TESTS "Build test executable" OFF)

if(BUILD_TESTS)
    add_executable(sysinfo_test
        sysinfo/test/test_main.cpp
    )
    target_link_libraries(sysinfo_test PRIVATE argus_sysinfo)
    
    if(NOT WIN32)
        target_link_libraries(sysinfo_test PRIVATE pthread)
    endif()
endif()

# ============================================================================
# Package config
# ============================================================================

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/argus_native_config_version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/argus_native_config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/argus_native_config.cmake"
    @ONLY
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/argus_native_config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/argus_native_config_version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/argus_native
)

message(STATUS "")
message(STATUS "Argus Native Components Configuration:")
message(STATUS "  Version:      ${PROJECT_VERSION}")
message(STATUS "  Build type:   ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
