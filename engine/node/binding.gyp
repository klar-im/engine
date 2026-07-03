{
  "variables": {
    # Repo root relative to this binding.gyp (engine/node/).
    "repo_root": "<!(node -e \"console.log(require('path').resolve(process.cwd(), '../..'))\")"
  },
  "targets": [
    {
      "target_name": "klar_engine",
      "sources": [ "addon.cc" ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<(repo_root)/engine"
      ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "conditions": [
        [ "OS=='mac'", {
          "libraries": [
            "-L<(repo_root)/engine/build",
            "-lspam_engine_c_api",
            "-Wl,-rpath,<(repo_root)/engine/build"
          ],
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LIBRARY": "libc++",
            "MACOSX_DEPLOYMENT_TARGET": "12.0"
          }
        } ],
        [ "OS=='linux'", {
          "libraries": [
            "-L<(repo_root)/engine/build",
            "-lspam_engine_c_api",
            "-Wl,-rpath,<(repo_root)/engine/build",
            "-Wl,-rpath,$$ORIGIN"
          ],
          "cflags_cc": [ "-fexceptions", "-std=c++17" ]
        } ]
      ]
    }
  ]
}
