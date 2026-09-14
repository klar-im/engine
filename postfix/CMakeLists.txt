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

# Copy ggml backend plugins next to the postfix binaries so
# ggml_backend_load_all() finds them via get_executable_path() at runtime.
# (The engine cmake already populated ENGINE_BUILD_DIR with these.) Shared
# with spamd/CMakeLists.txt via engine/cmake/copy_ggml_plugins.cmake — this
# used to be a copy-pasted glob that only matched the cpu backend, silently
# missing metal/blas (code-review finding, 2026-09-07).
include("${ENGINE_DIR}/cmake/copy_ggml_plugins.cmake")
klar_copy_ggml_plugins("${CMAKE_BINARY_DIR}" "${ENGINE_BUILD_DIR}")

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

# nlohmann/json (header-only; the engine already requires it): model_runtime.cpp
# reads the model directory's MANIFEST.json for its model_uuid.
find_package(nlohmann_json REQUIRED)

# Shared sources (everything except main entry points)
set(COMMON_SOURCES
    src/config.cpp
    src/auth_results.cpp
    src/model_runtime.cpp
    src/origin_ip_blocklist.cpp
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
        nlohmann_json::nlohmann_json
        ${MILTER_LIBRARY}
        ${SQLITE3_LIBRARIES}
        Threads::Threads
    )
endif()

# klar-policy-cli (no milter dependency)
add_executable(klar-policy-cli
    src/main_cli.cpp
    src/config.cpp
    src/auth_results.cpp
    src/model_runtime.cpp
    src/origin_ip_blocklist.cpp
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
    nlohmann_json::nlohmann_json
    Threads::Threads
)

# Unit tests. config.cpp is self-contained (TOML parser is internal, no
# engine/milter/sqlite), so this links only config.cpp and runs in milliseconds.
enable_testing()
# event_store.cpp needs only sqlite3 (no engine/milter), so this runs in
# milliseconds and covers the schema migration (TASK-388).
# The trusted-relay origin walk (TASK-387): pure address logic, links nothing.
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/origin_ip_tests.cpp")
    add_executable(origin_ip_tests
        tests/origin_ip_tests.cpp
        src/origin_ip_blocklist.cpp
    )
    target_include_directories(origin_ip_tests PRIVATE src ${ENGINE_DIR})
    add_test(NAME origin_ip_tests COMMAND origin_ip_tests)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/tests/event_store_tests.cpp")
    add_executable(event_store_tests
        tests/event_store_tests.cpp
        src/event_store.cpp
    )
    target_include_directories(event_store_tests PRIVATE src ${SQLITE3_INCLUDE_DIRS})
    target_link_directories(event_store_tests PRIVATE ${SQLITE3_LIBRARY_DIRS})
    target_link_libraries(event_store_tests PRIVATE ${SQLITE3_LIBRARIES})
    add_test(NAME event_store_tests COMMAND event_store_tests)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/tests/config_tests.cpp")
    # config.cpp now validates trusted_relay_cidrs, which lives in
    # origin_ip_blocklist.cpp and parses addresses with the engine's header-only
    # ip_blocklist.h — still no engine library, milter or sqlite to link.
    add_executable(config_tests
        tests/config_tests.cpp
        src/config.cpp
        src/origin_ip_blocklist.cpp
    )
    target_include_directories(config_tests PRIVATE src ${ENGINE_DIR})
    add_test(NAME config_tests COMMAND config_tests)
endif()

# The auth_results = "ignore" switch (TASK-503): header predicate, whole-message
# strip, and its config validation. Links config.cpp for validate_config, so the
# same origin_ip_blocklist.cpp dependency as config_tests, and nothing heavier.
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/auth_results_tests.cpp")
    add_executable(auth_results_tests
        tests/auth_results_tests.cpp
        src/auth_results.cpp
        src/config.cpp
        src/origin_ip_blocklist.cpp
    )
    target_include_directories(auth_results_tests PRIVATE src ${ENGINE_DIR})
    add_test(NAME auth_results_tests COMMAND auth_results_tests)
endif()

# ModelRuntime drives the lower-level classify + decide API because the milter
# adds connection-origin facts between the two calls. Stub the C API here so the
# test can pin calibration propagation without loading a 400 MiB model.
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/model_runtime_calibration_tests.cpp")
    add_executable(model_runtime_calibration_tests
        tests/model_runtime_calibration_tests.cpp
        src/model_runtime.cpp
    )
    target_include_directories(model_runtime_calibration_tests PRIVATE
        src
        ${ENGINE_DIR}
    )
    target_link_libraries(model_runtime_calibration_tests PRIVATE nlohmann_json::nlohmann_json)
    add_test(NAME model_runtime_calibration_tests
             COMMAND model_runtime_calibration_tests)
endif()
