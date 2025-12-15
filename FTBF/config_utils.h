#ifndef CONFIG_UTILS_H
#define CONFIG_UTILS_H

#include <string>

namespace ConfigUtils {

// Read the entire contents of a file into a string
std::string GetFileContents(const std::string& file_path);

// Load the Rust module with configuration files from the specified path
// Returns pointer to Rust instance on success, nullptr on failure
void* LoadRustModule(const std::string& config_path);

} // namespace ConfigUtils

#endif // CONFIG_UTILS_H

