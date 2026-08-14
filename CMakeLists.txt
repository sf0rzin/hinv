cmake_minimum_required(VERSION 3.20)
project(hinv LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    src/hinv-core
)

set(HINV_CORE_SOURCES
    src/hinv-core/hinv_byovd.cpp
    src/hinv-core/hinv_kmem.cpp
    src/hinv-core/hinv_iat.cpp
    src/hinv-core/hinv_vmm.cpp
    src/hinv-core/hinv_cleaner.cpp
    src/hinv-core/hinv_ept_shadow.cpp
    src/hinv-core/hinv_mapper.cpp
    src/hinv-core/headless/hinv_headless.cpp
)

set(HINV_CLI_SOURCES
    src/hinv-cli/main.cpp
)

add_executable(hinv ${HINV_CORE_SOURCES} ${HINV_CLI_SOURCES})

target_compile_definitions(hinv PRIVATE UNICODE _UNICODE)
if (MSVC)
    target_compile_options(hinv PRIVATE /W4)
else()
    target_compile_options(hinv PRIVATE -Wall -Wextra)
endif()

target_link_libraries(hinv PRIVATE psapi advapi32 ntdll)

# Tests
enable_testing()

set(TEST_SOURCES
    tests/test_pe_parser.cpp
)

add_executable(hinv_tests ${TEST_SOURCES} ${HINV_CORE_SOURCES})
target_compile_definitions(hinv_tests PRIVATE UNICODE _UNICODE)
target_include_directories(hinv_tests PRIVATE src/hinv-core)
if (MSVC)
    target_compile_options(hinv_tests PRIVATE /W4)
else()
    target_compile_options(hinv_tests PRIVATE -Wall -Wextra)
endif()
target_link_libraries(hinv_tests PRIVATE psapi advapi32 ntdll)

add_test(NAME pe_parser_safety COMMAND hinv_tests)
