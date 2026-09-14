#include <iostream>
#include <string>
#include <vector>

#include "spam_engine.h"

namespace {
void print_result(const spam_engine::ClassificationResult& result) {
  std::cout << "{\n";
  std::cout << R"(  "class": ")" << result.class_name << "\",\n";
  std::cout << "  \"confidence\": " << result.confidence << ",\n";
  std::cout << "  \"scores\": {\n";
  std::cout << "    \"gibberish\": " << result.scores.gibberish << ",\n";
  std::cout << "    \"marketing\": " << result.scores.marketing << ",\n";
  std::cout << "    \"regular\": " << result.scores.regular << ",\n";
  std::cout << "    \"spam\": " << result.scores.spam << "\n";
  std::cout << "  }\n";
  std::cout << "}\n";
}
}  // namespace

int main(int argc, char* argv[]) {
  std::string model_path = "./model";

  if (argc > 1) {
    model_path = argv[1];
  }

  std::cout << "Loading spam engine..." << '\n';

  try {
    spam_engine::SpamEngine engine;
    engine.load(spam_engine::EngineConfig{model_path, 0.001F});

    std::cout << "Model loaded successfully!" << '\n';

    std::vector<spam_engine::TranscriptMessage> const transcript = {
        {"user", "Buy cheap viagra now! Best prices online!", "chat"},
    };

    const auto result = engine.classify_transcript(
        transcript,
        spam_engine::CustomerInfo{"Spammer", "spam@example.com", false},
        spam_engine::ClassifyOptions{"ensemble"});
    print_result(result);
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << '\n';
    return 1;
  }

  return 0;
}
