cmake_minimum_required(VERSION 3.14)
project(spam_classifier LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()

find_package(PkgConfig REQUIRED)
pkg_check_modules(GMIME REQUIRED IMPORTED_TARGET gmime-3.0)
pkg_check_modules(XXHASH REQUIRED libxxhash)
# llama.cpp (GGML/Metal encoder backend)
# On macOS: resolved via pkg-config from Homebrew (llama + ggml formulae).
# On Linux: pass -DLLAMA_INSTALL=/path to skip pkg-config and use the dir directly.
if(DEFINED LLAMA_INSTALL)
    set(CMAKE_BUILD_RPATH "${LLAMA_INSTALL}/lib")
    set(LLAMA_INCLUDE_DIRS "${LLAMA_INSTALL}/include")
    set(LLAMA_LIBRARY_DIRS "${LLAMA_INSTALL}/lib")
    set(LLAMA_LIBRARIES
        "${LLAMA_INSTALL}/lib/libllama.so"
        "${LLAMA_INSTALL}/lib/libggml.so"
        "${LLAMA_INSTALL}/lib/libggml-base.so")
    set(GGML_INCLUDE_DIRS "${LLAMA_INSTALL}/include")
    set(GGML_LIBRARY_DIRS "${LLAMA_INSTALL}/lib")
    set(GGML_LIBRARIES "${LLAMA_INSTALL}/lib/libggml.so")
    # ggml_backend_load_all() searches the executable directory for CPU backend plugins.
    # Copy them next to the test binaries so they're found at runtime.
    file(GLOB GGML_CPU_PLUGINS "${LLAMA_INSTALL}/lib/libggml-cpu-*.so")
    if(NOT GGML_CPU_PLUGINS)
        message(FATAL_ERROR "No libggml-cpu-*.so plugins found in ${LLAMA_INSTALL}/lib — "
                            "the llama.cpp install is incomplete and runtime backend loading will fail.")
    endif()
    file(COPY ${GGML_CPU_PLUGINS} DESTINATION ${CMAKE_BINARY_DIR})
    file(COPY
        "${LLAMA_INSTALL}/lib/libggml.so"
        "${LLAMA_INSTALL}/lib/libggml-base.so"
        DESTINATION ${CMAKE_BINARY_DIR})
else()
    pkg_check_modules(LLAMA REQUIRED llama)
    pkg_check_modules(GGML REQUIRED ggml)
endif()
# nlohmann/json (header-only, used by trainable_classifier.h)
find_package(nlohmann_json REQUIRED)

# Shared engine library.
add_library(spam_engine SHARED
    spam_engine.cpp
    email_preprocessor.cpp
    pii_scrub.cpp
)

target_include_directories(spam_engine
    PUBLIC
        ${XXHASH_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${LLAMA_INCLUDE_DIRS}
        ${GGML_INCLUDE_DIRS}
)

target_link_libraries(spam_engine
    PUBLIC
        PkgConfig::GMIME
    PRIVATE
        ${LLAMA_LIBRARIES}
        ${GGML_LIBRARIES}
        nlohmann_json::nlohmann_json
)
# xxhash is used header-only (XXH_INLINE_ALL) — no library link needed

target_link_directories(spam_engine
    PRIVATE
        ${LLAMA_LIBRARY_DIRS}
        ${GGML_LIBRARY_DIRS}
)

# C ABI surface for Swift and other FFI consumers.
add_library(spam_engine_c_api SHARED
    spam_engine_c_api.cpp
)

target_include_directories(spam_engine_c_api
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(spam_engine_c_api
    PRIVATE
        spam_engine
)

# Training C ABI (premium feature, separate library). Closed-source: its source
# is not part of the open-core (klar-im/engine) repo, so only build it when present.
set(KLAR_HAVE_TRAINING OFF)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/spam_engine_training_c_api.cpp")
    set(KLAR_HAVE_TRAINING ON)
    add_library(spam_engine_training_c_api SHARED
        spam_engine_training_c_api.cpp
    )
    target_include_directories(spam_engine_training_c_api
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(spam_engine_training_c_api
        PRIVATE
            spam_engine
    )
endif()

# Main executable
add_executable(spam_classifier
    main.cpp
)

target_link_libraries(spam_classifier
    PRIVATE
        spam_engine
)

# Benchmark harness for engine speed experiments.
add_executable(spam_benchmark
    benchmark.cpp
)

target_link_libraries(spam_benchmark
    PRIVATE
        spam_engine
)

# Minimal API-level validation for the engine core. Some test sources are not
# part of the open-core repo (they reference closed surfaces); build each only
# when its source is present.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/spam_engine_tests.cpp")
    add_executable(spam_engine_tests
        tests/spam_engine_tests.cpp
    )
    target_compile_definitions(spam_engine_tests
        PRIVATE
            SPAM_ENGINE_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
    )
    target_link_libraries(spam_engine_tests
        PRIVATE
            spam_engine
    )
    add_test(NAME spam_engine_tests COMMAND spam_engine_tests)
    if(DEFINED LLAMA_INSTALL)
        set_tests_properties(spam_engine_tests PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${LLAMA_INSTALL}/lib")
    endif()
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/spam_engine_c_api_tests.cpp")
    add_executable(spam_engine_c_api_tests
        tests/spam_engine_c_api_tests.cpp
    )
    target_compile_definitions(spam_engine_c_api_tests
        PRIVATE
            SPAM_ENGINE_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
    )
    target_link_libraries(spam_engine_c_api_tests
        PRIVATE
            spam_engine
            spam_engine_c_api
    )
    if(KLAR_HAVE_TRAINING)
        target_link_libraries(spam_engine_c_api_tests PRIVATE spam_engine_training_c_api)
        target_compile_definitions(spam_engine_c_api_tests PRIVATE KLAR_HAVE_TRAINING)
    endif()
    add_test(NAME spam_engine_c_api_tests COMMAND spam_engine_c_api_tests)
    if(DEFINED LLAMA_INSTALL)
        set_tests_properties(spam_engine_c_api_tests PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${LLAMA_INSTALL}/lib")
    endif()
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/decision_layer_tests.cpp")
    # decision_layer.h is header-only and dependency-free (no model/llama/GMime),
    # so this test links nothing and runs in milliseconds (TASK-179).
    add_executable(decision_layer_tests
        tests/decision_layer_tests.cpp
    )
    add_test(NAME decision_layer_tests COMMAND decision_layer_tests)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/url_blocklist_tests.cpp")
    # url_blocklist.h is header-only + dependency-free (TASK-201) — links nothing.
    add_executable(url_blocklist_tests
        tests/url_blocklist_tests.cpp
    )
    add_test(NAME url_blocklist_tests COMMAND url_blocklist_tests)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/pii_scrub_tests.cpp")
    # pii_scrub.cpp depends only on the C++ <regex> (no model/llama/GMime), so
    # this compiles it directly and runs in milliseconds (TASK-206).
    add_executable(pii_scrub_tests
        tests/pii_scrub_tests.cpp
        pii_scrub.cpp
    )
    add_test(NAME pii_scrub_tests COMMAND pii_scrub_tests)
endif()

# Optional Swift smoke test for C ABI integration boundary.
find_program(BASH_EXECUTABLE bash)
find_program(SWIFTC_EXECUTABLE swiftc)

if(BASH_EXECUTABLE AND SWIFTC_EXECUTABLE)
    add_test(
        NAME spam_engine_swift_c_api_smoke
        COMMAND ${BASH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_swift_c_api_smoke.sh ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()
