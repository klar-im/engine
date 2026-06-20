cmake_minimum_required(VERSION 3.14)
project(klar_milter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Version info
set(KLAR_VERSION "1.0.0" CACHE STRING "Release version")
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/..
    OUTPUT_VARIABLE KLAR_GIT_SHA
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT KLAR_GIT_SHA)
    set(KLAR_GIT_SHA "unknown")
endif()

add_compile_definitions(
    KLAR_VERSION="${KLAR_VERSION}"
    KLAR_GIT_SHA="${KLAR_GIT_SHA}"
)

# Engine C API (from sibling engine/ directory)
set(ENGINE_DIR "${CMAKE_SOURCE_DIR}/../engine")
set(ENGINE_BUILD_DIR "${ENGINE_DIR}/build")

# Copy ggml CPU backend plugins next to the postfix binaries so
# ggml_backend_load_all() finds them via get_executable_path() at runtime.
# (The engine cmake already populated ENGINE_BUILD_DIR with these.)
file(GLOB POSTFIX_GGML_PLUGINS "${ENGINE_BUILD_DIR}/libggml-cpu-*.so")
if(POSTFIX_GGML_PLUGINS)
    file(COPY ${POSTFIX_GGML_PLUGINS} DESTINATION ${CMAKE_BINARY_DIR})
    foreach(_lib libggml.so libggml-base.so)
        if(EXISTS "${ENGINE_BUILD_DIR}/${_lib}")
            file(COPY "${ENGINE_BUILD_DIR}/${_lib}" DESTINATION ${CMAKE_BINARY_DIR})
        endif()
    endforeach()
endif()

# libmilter is only needed by klar-milterd (the SMTP-side daemon).
# klar-policy-cli is a standalone CLI used by replay tests and dry-runs;
# it has no milter dependency. macOS dev machines don't have libmilter
# (it's a Linux server library), so we make the milter daemon optional —
# missing libmilter just disables klar-milterd, the CLI still builds.
find_path(MILTER_INCLUDE_DIR libmilter/mfapi.h)
find_library(MILTER_LIBRARY milter)
if(MILTER_INCLUDE_DIR AND MILTER_LIBRARY)
    set(KLAR_BUILD_MILTERD ON)
    message(STATUS "libmilter found — klar-milterd will be built")
else()
    set(KLAR_BUILD_MILTERD OFF)
    message(STATUS "libmilter not found — skipping klar-milterd (klar-policy-cli still built)")
endif()

# Find SQLite3
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# Find pthread
find_package(Threads REQUIRED)

# Shared sources (everything except main entry points)
set(COMMON_SOURCES
    src/config.cpp
    src/model_runtime.cpp
    src/policy.cpp
    src/event_store.cpp
    src/health_server.cpp
)

# klar-milterd daemon (only built when libmilter is present)
if(KLAR_BUILD_MILTERD)
    add_executable(klar-milterd
        src/main.cpp
        src/milter_server.cpp
        ${COMMON_SOURCES}
    )
    target_include_directories(klar-milterd PRIVATE
        src
        ${ENGINE_DIR}
        ${MILTER_INCLUDE_DIR}
        ${SQLITE3_INCLUDE_DIRS}
    )
    target_link_directories(klar-milterd PRIVATE
        ${ENGINE_BUILD_DIR}
        ${SQLITE3_LIBRARY_DIRS}
    )
    target_link_libraries(klar-milterd PRIVATE
        spam_engine_c_api
        ${MILTER_LIBRARY}
        ${SQLITE3_LIBRARIES}
        Threads::Threads
    )
endif()

# klar-policy-cli (no milter dependency)
add_executable(klar-policy-cli
    src/main_cli.cpp
    src/config.cpp
    src/model_runtime.cpp
    src/policy.cpp
)
target_include_directories(klar-policy-cli PRIVATE
    src
    ${ENGINE_DIR}
)
target_link_directories(klar-policy-cli PRIVATE
    ${ENGINE_BUILD_DIR}
)
target_link_libraries(klar-policy-cli PRIVATE
    spam_engine_c_api
    Threads::Threads
)

# Unit tests. config.cpp is self-contained (TOML parser is internal, no
# engine/milter/sqlite), so this links only config.cpp and runs in milliseconds.
enable_testing()
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/config_tests.cpp")
    add_executable(config_tests
        tests/config_tests.cpp
        src/config.cpp
    )
    target_include_directories(config_tests PRIVATE src)
    add_test(NAME config_tests COMMAND config_tests)
endif()
