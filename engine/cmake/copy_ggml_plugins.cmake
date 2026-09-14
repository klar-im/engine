# Copies the ggml backend shared libraries (cpu/metal/blas variants, plus the
# core ggml libs) next to a built binary so ggml_backend_load_all() finds them
# via get_executable_path() at runtime.
#
# Single-owned fact: postfix/CMakeLists.txt and spamd/CMakeLists.txt both need
# this, and a copy-pasted glob already drifted once (postfix/'s original copy
# only matched libggml-cpu-*.so, silently missing the metal/blas backends
# spamd/'s copy correctly included — code-review finding, 2026-09-07). Both
# now call klar_copy_ggml_plugins() instead of repeating the glob.
function(klar_copy_ggml_plugins target_output_dir engine_build_dir)
    file(GLOB _klar_ggml_plugins
        "${engine_build_dir}/libggml-cpu-*.so"
        "${engine_build_dir}/libggml-metal.so"
        "${engine_build_dir}/libggml-blas.so"
    )
    if(_klar_ggml_plugins)
        file(COPY ${_klar_ggml_plugins} DESTINATION "${target_output_dir}")
        foreach(_lib libggml.so libggml-base.so)
            if(EXISTS "${engine_build_dir}/${_lib}")
                file(COPY "${engine_build_dir}/${_lib}" DESTINATION "${target_output_dir}")
            endif()
        endforeach()
    endif()
endfunction()
