#ifndef CACHE_UTILS_H
#define CACHE_UTILS_H

#include "common.h"
#include <string>

namespace CacheUtils {

// Initialize cache locks (must be called before using cache functions)
void InitializeLocks();

// Get a persistent pointer to the instruction string from the bounded cache
// Limits memory usage while ensuring valid pointers
const char* GetCachedInstrString(const std::string& instr_str);

} // namespace CacheUtils

#endif // CACHE_UTILS_H

