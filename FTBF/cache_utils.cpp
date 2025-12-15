#include "cache_utils.h"
#include <unordered_map>
#include <deque>

namespace CacheUtils {

namespace {
// Bounded string cache for instruction disassembly
// Limits memory usage while ensuring valid pointers
constexpr size_t MAX_INSTR_CACHE_SIZE = 10000; // ~500KB for typical instructions
std::unordered_map<std::string, std::string> instr_string_cache; // Key and value are same
std::deque<std::string> instr_cache_lru; // Track insertion order for LRU eviction
PIN_LOCK instr_cache_lock;
} // anonymous namespace

void InitializeLocks() {
  PIN_InitLock(&instr_cache_lock);
}

const char* GetCachedInstrString(const std::string& instr_str) {
  PIN_GetLock(&instr_cache_lock, 1);
  
  // Check if already in cache
  auto it = instr_string_cache.find(instr_str);
  if (it != instr_string_cache.end()) {
    PIN_ReleaseLock(&instr_cache_lock);
    return it->second.c_str();
  }
  
  // Not in cache - need to add it
  // If cache is full, evict oldest entry (LRU)
  if (instr_string_cache.size() >= MAX_INSTR_CACHE_SIZE) {
    const std::string& oldest = instr_cache_lru.front();
    instr_string_cache.erase(oldest);
    instr_cache_lru.pop_front();
  }
  
  // Insert new string and track in LRU
  auto insert_result = instr_string_cache.insert({instr_str, instr_str});
  instr_cache_lru.push_back(instr_str);
  const char* cached_ptr = insert_result.first->second.c_str();
  
  PIN_ReleaseLock(&instr_cache_lock);
  return cached_ptr;
}

} // namespace CacheUtils

