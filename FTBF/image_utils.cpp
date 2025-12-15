#include "image_utils.h"
#include <unordered_map>

namespace ImageUtils {

namespace {
// Cache for image lookups to avoid repeated PIN_LockClient calls
std::unordered_map<ADDRINT, bool> is_external_cache;
std::unordered_map<ADDRINT, bool> is_main_exec_cache;
PIN_LOCK cache_lock;
} // anonymous namespace

void InitializeLocks() {
  PIN_InitLock(&cache_lock);
}

std::string_view ExtractFilename(std::string_view full_path) {
  const size_t pos = full_path.find_last_of('\\');
  return (pos != std::string_view::npos) ? full_path.substr(pos + 1) : full_path;
}

bool IsExternalLibrary(ADDRINT address) {
  PIN_GetLock(&cache_lock, 1);
  auto it = is_external_cache.find(address);
  if (it != is_external_cache.end()) {
    PIN_ReleaseLock(&cache_lock);
    return it->second;
  }
  PIN_ReleaseLock(&cache_lock);

  PIN_LockClient();
  const IMG image = IMG_FindByAddress(address);
  const bool result = IMG_Valid(image) && !IMG_IsMainExecutable(image);
  PIN_UnlockClient();

  PIN_GetLock(&cache_lock, 1);
  is_external_cache[address] = result;
  PIN_ReleaseLock(&cache_lock);

  return result;
}

bool IsMainExecutable(ADDRINT address) {
  PIN_GetLock(&cache_lock, 1);
  auto it = is_main_exec_cache.find(address);
  if (it != is_main_exec_cache.end()) {
    PIN_ReleaseLock(&cache_lock);
    return it->second;
  }
  PIN_ReleaseLock(&cache_lock);

  PIN_LockClient();
  const IMG image = IMG_FindByAddress(address);
  const bool result = IMG_Valid(image) && IMG_IsMainExecutable(image);
  PIN_UnlockClient();

  PIN_GetLock(&cache_lock, 1);
  is_main_exec_cache[address] = result;
  PIN_ReleaseLock(&cache_lock);

  return result;
}

} // namespace ImageUtils

