cmake_minimum_required(VERSION 3.14)
project(spam_classifier LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_testing()

find_package(PkgConfig REQUIRED)
pkg_check_modules(GMIME REQUIRED IMPORTED_TARGET gmime-3.0)
pkg_check_modules(XXHASH REQUIRED libxxhash)
# Homebrew keeps libarchive keg-only because macOS ships a system copy. Its
# pkg-config file is therefore not on the default path, and CMake's stock
# FindLibArchive does not search the opt keg. Prefer pkg-config on Linux, then
# use the two conventional Homebrew opt roots on macOS.
pkg_check_modules(LIBARCHIVE QUIET libarchive)
if(NOT LIBARCHIVE_FOUND)
    find_path(LIBARCHIVE_INCLUDE_DIR archive.h
        HINTS /opt/homebrew/opt/libarchive/include /usr/local/opt/libarchive/include)
    if(NOT LIBARCHIVE_INCLUDE_DIR)
        message(FATAL_ERROR "libarchive development headers not found")
    endif()
    set(LIBARCHIVE_INCLUDE_DIRS "${LIBARCHIVE_INCLUDE_DIR}")
    # Link the libarchive shipped by the macOS SDK (`-larchive`), not the
    # Homebrew keg's dylib. The keg is headers-only for us: its current bottle
    # may target a newer macOS than Klar supports, while every API used below is
    # in the system library. A full path here would also force app packaging to
    # bundle a dependency macOS already owns.
    set(LIBARCHIVE_LIBRARIES archive)
endif()
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
    # Homebrew's ggml ships its backends as dynamic plugins in <prefix>/libexec and
    # compiles that ABSOLUTE path into libggml as GGML_BACKEND_DIR. The app bundler
    # stages those plugins into Contents/Frameworks, so the shipped Mail extension
    # loads OUR copies by path and never reads the Homebrew tree (which it cannot:
    # the appex sandbox denies it, and the enumeration THROWS rather than skipping,
    # which is how the extension silently classified nothing). Staging them here too
    # makes the build tree mirror the bundle, so tests exercise the shipped path.
    pkg_get_variable(GGML_LIBDIR ggml libdir)
    get_filename_component(GGML_PREFIX "${GGML_LIBDIR}" DIRECTORY)
    set(GGML_BACKEND_DIR "${GGML_PREFIX}/libexec")
    file(GLOB GGML_BACKEND_PLUGINS "${GGML_BACKEND_DIR}/libggml-*.so")
    if(GGML_BACKEND_PLUGINS)
        file(COPY ${GGML_BACKEND_PLUGINS} DESTINATION ${CMAKE_BINARY_DIR})
    else()
        message(WARNING "No ggml backend plugins in ${GGML_BACKEND_DIR}: this build "
                        "resolves backends through libggml's compiled-in path only, and "
                        "the backend_isolation test cannot run.")
    endif()
endif()
# nlohmann/json (header-only, used by trainable_classifier.h)
find_package(nlohmann_json REQUIRED)

# brand_kb_data.h (TASK-232) is generated from in-repo committed inputs only: the curated
# registry inline in gen_brand_kb.py, the auto-resolved brand_authdomains.json, and the
# shared FNV-1a in gen_brand_names.py. Wire it into the build graph so editing any of those
# regenerates the header and recompiles dependents -- no separate `make engine/brand-kb`
# step to forget (the stale-data hazard). Unlike brand_names_data.h / brand_reputation_data.h,
# this has NO external Tranco CSV input, so it is safe to regenerate at build time. The output
# stays committed (reviewable); CMake re-runs the command only when an input is newer. The
# regen rule is wired only when the generator is present: a source-only checkout (the /demo
# server ships engine/ but not model-lab/) builds from the committed header instead.
set(SCRIPTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../model-lab/scripts)
if(EXISTS ${SCRIPTS_DIR}/gen_brand_kb.py)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/brand_kb_data.h
        COMMAND python3 ${SCRIPTS_DIR}/gen_brand_kb.py
        DEPENDS ${SCRIPTS_DIR}/gen_brand_kb.py
                ${SCRIPTS_DIR}/brand_authdomains.json
                ${SCRIPTS_DIR}/gen_brand_names.py
        COMMENT "Regenerating brand_kb_data.h from gen_brand_kb.py + brand_authdomains.json"
        VERBATIM
    )
    add_custom_target(brand_kb_data DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/brand_kb_data.h)
else()
    # Source-only checkouts (the /demo server gets engine/ but not model-lab/)
    # build from the committed brand_kb_data.h, exactly like the sibling
    # brand_names_data.h / brand_reputation_data.h headers. CI builds with the
    # scripts present, so a stale committed header is caught upstream, not here.
    add_custom_target(brand_kb_data)
endif()

# Shared engine library.
add_library(spam_engine SHARED
    spam_engine.cpp
    email_preprocessor.cpp
    attachment_features.cpp
    pii_scrub.cpp
)
add_dependencies(spam_engine brand_kb_data)

target_include_directories(spam_engine
    PUBLIC
        ${XXHASH_INCLUDE_DIRS}
        ${LIBARCHIVE_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${LLAMA_INCLUDE_DIRS}
        ${GGML_INCLUDE_DIRS}
)

target_link_libraries(spam_engine
    PUBLIC
        PkgConfig::GMIME
        ${LIBARCHIVE_LIBRARIES}
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

# On-device training C ABI (learn from corrections), a separate library so a
# consumer that never trains can leave it out of its bundle. Open since
# 2026-07-04; every checkout has it.
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
# One engine test binary that loads a model: the executable, the source-dir
# define its fixtures resolve through, its ctest entry, and the llama library
# path (CMAKE_BUILD_RPATH covers the executable but not the libggml-cpu-*.so
# plugins dlopen'd at runtime, which resolve libggml-base.so through their
# own rpath). Link libraries with target_link_libraries afterwards.
function(klar_engine_test name source)
    add_executable(${name} ${source})
    target_compile_definitions(${name}
        PRIVATE
            SPAM_ENGINE_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
    )
    add_test(NAME ${name} COMMAND ${name})
    if(DEFINED LLAMA_INSTALL)
        set_tests_properties(${name} PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${LLAMA_INSTALL}/lib")
    endif()
endfunction()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/spam_engine_tests.cpp")
    klar_engine_test(spam_engine_tests tests/spam_engine_tests.cpp)
    # nlohmann is PRIVATE on spam_engine, so the test target links it directly.
    # The marker test authors a classifier_config.json fixture; it previously did
    # that by splicing a Gen 3 source_model literal, which made it depend on
    # which model was installed (TASK-428 AC#4).
    target_link_libraries(spam_engine_tests
        PRIVATE
            spam_engine
            nlohmann_json::nlohmann_json
    )
    # Two entries partitioning one binary, not nesting: --qualification-only
    # runs the corpus panels and nothing else. They embed ~880 SpamAssassin
    # messages, which is what put the merge gate over its 900 s ctest timeout
    # (TASK-428 AC#5), so the label lets `make engine/test` exclude them and
    # `make engine/qualify` select them.
    add_test(NAME spam_engine_qualification
             COMMAND spam_engine_tests --qualification-only)
    set_tests_properties(spam_engine_qualification PROPERTIES
        LABELS qualification)
    if(DEFINED LLAMA_INSTALL)
        set_tests_properties(spam_engine_qualification PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${LLAMA_INSTALL}/lib")
    endif()
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/spam_engine_c_api_tests.cpp")
    klar_engine_test(spam_engine_c_api_tests tests/spam_engine_c_api_tests.cpp)
    target_link_libraries(spam_engine_c_api_tests
        PRIVATE
            spam_engine
            spam_engine_c_api
    )
    # The test TU #includes brand_kb.h -> brand_kb_data.h directly, so it must also wait
    # for the generator (linking spam_engine is not enough -- the header is compiled into
    # this TU, not just the library). Without this an incremental build can compile the
    # test against a stale committed brand_kb_data.h after an input change.
    add_dependencies(spam_engine_c_api_tests brand_kb_data)
    target_link_libraries(spam_engine_c_api_tests PRIVATE spam_engine_training_c_api)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/decision_layer_tests.cpp")
    # decision_layer.h is header-only and dependency-free (no model/llama/GMime),
    # so this test links nothing and runs in milliseconds (TASK-179).
    add_executable(decision_layer_tests
        tests/decision_layer_tests.cpp
    )
    add_test(NAME decision_layer_tests COMMAND decision_layer_tests)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/attachment_features_tests.cpp")
    add_executable(attachment_features_tests
        tests/attachment_features_tests.cpp
    )
    target_link_libraries(attachment_features_tests PRIVATE spam_engine ${LIBARCHIVE_LIBRARIES})
    add_test(NAME attachment_features_tests COMMAND attachment_features_tests)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/url_blocklist_tests.cpp")
    # url_blocklist.h is header-only + dependency-free (TASK-201) — links nothing.
    add_executable(url_blocklist_tests
        tests/url_blocklist_tests.cpp
    )
    add_test(NAME url_blocklist_tests COMMAND url_blocklist_tests)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/ip_blocklist_tests.cpp")
    # ip_blocklist.h is header-only + dependency-free (TASK-113) — links nothing.
    add_executable(ip_blocklist_tests
        tests/ip_blocklist_tests.cpp
    )
    add_test(NAME ip_blocklist_tests COMMAND ip_blocklist_tests)
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

# Tearing the engine down from an atexit handler must not crash the process,
# whichever order the handler was registered in. Its own binary because the
# failure under test IS the process exit. See tests/atexit_teardown_test.cpp.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/atexit_teardown_test.cpp"
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/model/gguf")
    add_executable(atexit_teardown_test tests/atexit_teardown_test.cpp)
    target_link_libraries(atexit_teardown_test PRIVATE spam_engine_c_api)
    add_test(
        NAME atexit_teardown
        COMMAND atexit_teardown_test ${CMAKE_CURRENT_SOURCE_DIR}/model
    )
    # Same reason as the other llama-linking tests above: CMAKE_BUILD_RPATH
    # covers the executable but not the libggml-cpu-*.so plugins dlopen'd at
    # runtime, which resolve libggml-base.so through their own rpath.
    if(DEFINED LLAMA_INSTALL)
        set_tests_properties(atexit_teardown PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${LLAMA_INSTALL}/lib")
    endif()
endif()

# The engine must resolve backends from the plugins staged next to it, not from
# libggml's compiled-in directory. Runs the classifier with that directory denied
# (the Mail-extension sandbox condition) and fails if the load dies or if any
# backend came from elsewhere. See tests/backend_isolation_test.sh.
if(GGML_BACKEND_PLUGINS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/backend_isolation_test.sh")
    add_test(
        NAME backend_isolation
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/backend_isolation_test.sh
                $<TARGET_FILE:spam_classifier>
                ${CMAKE_CURRENT_SOURCE_DIR}/model
                ${GGML_BACKEND_DIR}
    )
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

# Sources that ship only with the closed distribution. Absent from the public
# mirror by design, and nothing above depends on them. A checkout that has
# the closed publish lists but not this file is a monorepo checkout missing
# it, which must fail here rather than configure a smaller build quietly.
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/closed.cmake" OPTIONAL RESULT_VARIABLE KLAR_CLOSED_INCLUDED)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/publish/closed.txt" AND NOT KLAR_CLOSED_INCLUDED)
    message(FATAL_ERROR "engine/cmake/closed.cmake is missing from a closed checkout")
endif()
