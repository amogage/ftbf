#ifndef IMAGE_UTILS_H
#define IMAGE_UTILS_H

#include "common.h"
#include <string_view>

namespace ImageUtils {

// Initialize image cache locks (must be called before using image functions)
void InitializeLocks();

// Extract the filename from a full path (returns string_view to avoid allocation)
std::string_view ExtractFilename(std::string_view full_path);

// Check if an address belongs to an external library (not main executable)
// Uses caching to avoid repeated PIN_LockClient calls
bool IsExternalLibrary(ADDRINT address);

// Check if an address belongs to the main executable
// Uses caching to avoid repeated PIN_LockClient calls
bool IsMainExecutable(ADDRINT address);

} // namespace ImageUtils

#endif // IMAGE_UTILS_H

