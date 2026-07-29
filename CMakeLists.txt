cmake_minimum_required(VERSION 3.20)
project(hinv LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    src/hinv-core
)

set(HINV_CORE_SOURCES
    src/hinv-core/hinv_hijack.cpp
    src/hinv-core/hinv_iat.cpp
    src/hinv-core/hinv_vmm.cpp
    src/hinv-core/hinv_cleaner.cpp
    src/hinv-core/hinv_ept_shadow.cpp
    src/hinv-core/headless/hinv_headless.cpp
)

set(HINV_CLI_SOURCES
    src/hinv-cli/main.cpp
)

add_executable(hinv ${HINV_CORE_SOURCES} ${HINV_CLI_SOURCES})

target_link_libraries(hinv PRIVATE psapi advapi32)
