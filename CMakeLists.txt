cmake_minimum_required(VERSION 3.20)
project(hinv LANGUAGES CXX)

if (NOT WIN32)
    message(FATAL_ERROR "hinv requires Windows")
endif()
if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "hinv requires a 64-bit build")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(HINV_INCLUDE_DIR
    src/hinv-core
)

set(HINV_CORE_SOURCES
    src/hinv-core/hinv_byovd.cpp
    src/hinv-core/hinv_kmem.cpp
    src/hinv-core/hinv_iat.cpp
    src/hinv-core/hinv_vmm.cpp
    src/hinv-core/hinv_maintenance.cpp
    src/hinv-core/hinv_mapper.cpp
    src/hinv-core/headless/hinv_headless.cpp
)

set(HINV_CLI_SOURCES
    src/hinv-cli/main.cpp
)

add_executable(hinv ${HINV_CORE_SOURCES} ${HINV_CLI_SOURCES})

target_compile_definitions(hinv PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_include_directories(hinv PRIVATE ${HINV_INCLUDE_DIR})
if (MSVC)
    target_compile_options(hinv PRIVATE /W4)
else()
    target_compile_options(hinv PRIVATE -Wall -Wextra)
    # Static-link the whole MinGW runtime: a mismatched libstdc++-6.dll earlier
    # in PATH (e.g. Git for Windows' mingw64) ABI-crashes fstream at runtime,
    # and -static-lib* alone still leaves libwinpthread-1.dll dynamic.
    target_link_options(hinv PRIVATE -static)
endif()

target_link_libraries(hinv PRIVATE psapi advapi32 ntdll bcrypt)

# Lab-only HyperDbg API smoke binary. It is deliberately excluded from the
# default build and is not registered as a CTest because it requires a live
# HyperDbg device in the disposable VM.
option(HINV_BUILD_LAB_SMOKE "Build the lab-only HyperDbg API smoke binary" OFF)
if (HINV_BUILD_LAB_SMOKE)
    add_executable(hinv_hyperdbg_api_smoke EXCLUDE_FROM_ALL
        tests/hyperdbg_api_smoke.cpp
        src/hinv-core/hinv_kmem.cpp
        src/hinv-core/hinv_vmm.cpp
    )
    target_compile_definitions(hinv_hyperdbg_api_smoke PRIVATE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_include_directories(hinv_hyperdbg_api_smoke PRIVATE ${HINV_INCLUDE_DIR})
    if (MSVC)
        target_compile_options(hinv_hyperdbg_api_smoke PRIVATE /W4)
    else()
        target_compile_options(hinv_hyperdbg_api_smoke PRIVATE -Wall -Wextra)
        target_link_options(hinv_hyperdbg_api_smoke PRIVATE -static)
    endif()
    target_link_libraries(hinv_hyperdbg_api_smoke PRIVATE psapi advapi32 ntdll bcrypt)
    set_target_properties(hinv_hyperdbg_api_smoke PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lab")
endif()

# Tests
include(CTest)
if (BUILD_TESTING)

set(TEST_SOURCES
    tests/test_pe_parser.cpp
)

add_executable(hinv_tests ${TEST_SOURCES} ${HINV_CORE_SOURCES})
target_compile_definitions(hinv_tests PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_include_directories(hinv_tests PRIVATE ${HINV_INCLUDE_DIR})
if (MSVC)
    target_compile_options(hinv_tests PRIVATE /W4)
else()
    target_compile_options(hinv_tests PRIVATE -Wall -Wextra)
    target_link_options(hinv_tests PRIVATE -static)
endif()
target_link_libraries(hinv_tests PRIVATE psapi advapi32 ntdll bcrypt)

add_test(NAME pe_parser_safety COMMAND hinv_tests)

add_executable(hinv_client_tests tests/test_client_contract.cpp)
target_compile_definitions(hinv_client_tests PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_include_directories(hinv_client_tests PRIVATE ${HINV_INCLUDE_DIR})
if (MSVC)
    target_compile_options(hinv_client_tests PRIVATE /W4)
else()
    target_compile_options(hinv_client_tests PRIVATE -Wall -Wextra)
    target_link_options(hinv_client_tests PRIVATE -static)
endif()
target_link_libraries(hinv_client_tests PRIVATE advapi32 ntdll)
add_test(NAME client_sdk_contract COMMAND hinv_client_tests)
endif()
