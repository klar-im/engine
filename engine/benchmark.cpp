#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

#include "spam_engine.h"

static double median(std::vector<double>& v) {
  std::sort(v.begin(), v.end());
  auto n = v.size();
  return (n % 2 == 0) ? (v[n / 2 - 1] + v[n / 2]) / 2.0 : v[n / 2];
}

int main(int argc, char* argv[]) {
  std::string model_path = "./model";
  int warmup = 2;
  int iters = 10;

  if (argc > 1) model_path = argv[1];
  if (argc > 2) warmup = std::atoi(argv[2]);
  if (argc > 3) iters = std::atoi(argv[3]);

  // Texts of varying length.
  // `very_long` is the worst-case input the encoder cap clips: 500+ tokens
  // pre-cap, so it exercises the full ms/email cost of the previous 512-cap.
  const std::string long_body =
      "Hi John, I wanted to follow up on our conversation from yesterday's "
      "meeting about the Q3 roadmap. The team has been making great progress "
      "on the new authentication module and we should have a working prototype "
      "by end of next week. Sarah mentioned she needs the API spec finalized "
      "before she can start on the frontend integration. Can you review the "
      "draft I shared in the Google Doc and leave comments by Thursday? Also, "
      "reminder that we have the all-hands on Friday at 2pm where we'll be "
      "presenting the updated timeline to leadership. Let me know if you need "
      "anything else. Best regards, Mike";
  std::string very_long_body;
  for (int i = 0; i < 6; ++i) very_long_body += long_body + "\n\n";

  std::vector<std::pair<std::string, std::string>> samples = {
      {"short", "Buy cheap viagra now!"},
      {"medium",
       "Dear customer, we are pleased to inform you that your account has been "
       "selected for a special promotional offer. Click the link below to claim "
       "your reward of $10,000. This is a limited time offer available only to "
       "select customers. Act now before it expires!"},
      {"long", long_body},
      {"very_long", very_long_body},
  };

  // --- Load ---
  spam_engine::EngineConfig config;
  config.model_path = model_path;

  auto t0 = std::chrono::high_resolution_clock::now();
  spam_engine::SpamEngine engine;
  engine.load(config);
  auto t1 = std::chrono::high_resolution_clock::now();
  double load_ms =
      std::chrono::duration<double, std::milli>(t1 - t0).count();

  std::cout << std::fixed << std::setprecision(1);
  std::cout << "load: " << load_ms << "ms\n";

  // --- Classify ---
  for (const auto& [name, text] : samples) {
    // warmup
    for (int i = 0; i < warmup; ++i) {
      engine.classify(text, "", "", spam_engine::ClassifyOptions{"ensemble"});
    }

    std::vector<double> times;
    times.reserve(iters);
    std::string last_class;
    for (int i = 0; i < iters; ++i) {
      auto s = std::chrono::high_resolution_clock::now();
      auto result = engine.classify(text, "", "", spam_engine::ClassifyOptions{"ensemble"});
      auto e = std::chrono::high_resolution_clock::now();
      times.push_back(
          std::chrono::duration<double, std::milli>(e - s).count());
      last_class = result.class_name;
    }

    double med = median(times);
    double avg =
        std::accumulate(times.begin(), times.end(), 0.0) / times.size();
    std::cout << "classify_" << name << ": median=" << med
              << "ms avg=" << avg << "ms class=" << last_class << "\n";
  }

  // --- Train (embed + backprop) ---
  {
    const std::string text = samples[1].first == "medium" ? samples[1].second : samples[0].second;
    // Wrap once via the canonical builder; engine.train requires a
    // CalibratedInputText so the head sees the same shape as production.
    const auto calibrated = spam_engine::build_input_text(
        {{"user", text, "email"}}, spam_engine::CustomerInfo{});
    // warmup
    for (int i = 0; i < warmup; ++i) {
      engine.train(calibrated, 3);
    }

    std::vector<double> times;
    times.reserve(iters);
    for (int i = 0; i < iters; ++i) {
      auto s = std::chrono::high_resolution_clock::now();
      engine.train(calibrated, 3);  // train as spam
      auto e = std::chrono::high_resolution_clock::now();
      times.push_back(
          std::chrono::duration<double, std::milli>(e - s).count());
    }

    double med = median(times);
    std::cout << "train: median=" << med << "ms (embed + backprop)\n";
  }

  return 0;
}
