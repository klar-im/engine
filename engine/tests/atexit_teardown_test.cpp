// Regression test for the KlarPlus night-training crash of 2026-08-18 02:02.
//
// The headless run tore the engine down from an atexit handler. Handlers run in
// reverse registration order, and ggml's backend plugins are dlopen'd lazily on
// the first load — so a handler registered at startup, which is where every
// binding naturally registers one, ran AFTER ggml had already destroyed its own
// statics. spam_engine_unload then freed a llama_context whose backend was gone
// and jumped through a dangling function pointer:
//
//   llama_context::~llama_context() + 136
//   llama_free + 16
//   spam_engine::SpamEngine::Impl::~Impl() + 112
//   spam_engine::SpamEngine::unload() + 52
//   spam_engine_unload + 60
//   __cxa_finalize_ranges + 448
//
// This exercises the ordering that crashed — handler registered BEFORE the load
// — and passes only if the process still exits 0. The fix is the exit-teardown
// guard in ggml_encoder.h; without it this test dies with SIGBUS/SIGSEGV.
//
// It has to be its own binary because the failure is the process exit itself:
// there is no point after exit() at which an assertion could run.

#include <cstdio>
#include <cstdlib>

#include "spam_engine_c_api.h"

namespace {

spam_engine_handle_t* g_handle = nullptr;

// Deliberately the pattern that used to crash: teardown deferred to exit.
void teardown_at_exit() {
  spam_engine_unload(g_handle);
  spam_engine_destroy(g_handle);
  g_handle = nullptr;
}

}  // namespace

int main(int argc, char* const* argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: atexit_teardown_test <model_dir>\n");
    return 2;
  }

  // Registered before the load, exactly as SpamTrainer/SpamEngineClient did.
  if (std::atexit(teardown_at_exit) != 0) {
    std::fprintf(stderr, "atexit registration failed\n");
    return 2;
  }

  g_handle = spam_engine_create();
  if (g_handle == nullptr) {
    std::fprintf(stderr, "spam_engine_create failed\n");
    return 2;
  }
  if (spam_engine_load(g_handle, argv[1], 0.0001F, nullptr) != SPAM_ENGINE_STATUS_OK) {
    std::fprintf(stderr, "spam_engine_load failed: %s\n",
                 spam_engine_get_last_error(g_handle));
    return 2;
  }

  std::fprintf(stderr, "[atexit_teardown_test] exiting with a live handle\n");
  return 0;  // -> exit() -> __cxa_finalize_ranges -> teardown_at_exit
}
