#include "config_utils.h"
#include "common.h"
#include "types.h"
#include <fstream>

namespace ConfigUtils {

std::string GetFileContents(const std::string& file_path) {
  std::ifstream fin(file_path, std::ios::in | std::ios::binary);

  if (!fin.is_open()) {
    Logger::log(string_format("Could not open file: %s!\n", file_path.c_str()));
    return "";
  }

  // Get file size and pre-allocate string to avoid reallocations
  fin.seekg(0, std::ios::end);
  const std::streamsize file_size = fin.tellg();
  fin.seekg(0, std::ios::beg);

  std::string contents;
  contents.reserve(static_cast<size_t>(file_size));

  // Read file directly into string buffer (more efficient than stringstream)
  contents.assign((std::istreambuf_iterator<char>(fin)),
                   std::istreambuf_iterator<char>());

  return contents;
}

void* LoadRustModule(const std::string& config_path) {
  // Pre-allocate with known sizes to avoid reallocations
  std::string policy_path, rule_path, apis_path;
  policy_path.reserve(config_path.size() + 32);
  rule_path.reserve(config_path.size() + 32);
  apis_path.reserve(config_path.size() + 32);
  
  policy_path = config_path + "\\" + POLICY_JSON;
  rule_path = config_path + "\\" + RULE_JSON;
  apis_path = config_path + "\\" + APIS_JSON;

  const std::string policy = GetFileContents(policy_path);
  const std::string rule = GetFileContents(rule_path);
  const std::string apis = GetFileContents(apis_path);

  if (policy.empty() || rule.empty() || apis.empty()) {
    Logger::log("Failed to load one or more configuration files!\n");
    return nullptr;
  }

  void* rust_instance = on_init(policy.c_str(), rule.c_str(), apis.c_str());
  if (rust_instance == nullptr) {
    Logger::log("Could not initialize rust side!\n");
    return nullptr;
  }

  return rust_instance;
}

} // namespace ConfigUtils

