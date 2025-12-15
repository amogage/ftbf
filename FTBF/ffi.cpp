#include "ffi.h"
#include "pin.H"
#include <cstdio>
#include <map>

map<string, REG> regNameMap;

// Thread-local storage for register string conversion
// Uses a thread-safe map keyed by native thread ID to avoid memory leaks
// and work without Microsoft CRT
constexpr size_t REG_STRING_BUFFER_SIZE = 64;
static std::map<NATIVE_TID, char*> thread_buffers;
static PIN_LOCK buffer_lock;

// Initialize the lock (call this once, e.g., in main or initialization)
void InitBufferLock() {
  PIN_InitLock(&buffer_lock);
}

// Get or create a thread-local buffer
static char* get_thread_buffer() {
  NATIVE_TID tid;
  OS_GetTid(&tid);
  
  // Use native thread ID for lock debugging (cast to INT32)
  // PIN_GetLock's second parameter is for debugging purposes
  PIN_GetLock(&buffer_lock, static_cast<INT32>(tid));
  auto it = thread_buffers.find(tid);
  char* buffer;
  if (it == thread_buffers.end()) {
    buffer = new char[REG_STRING_BUFFER_SIZE];
    thread_buffers[tid] = buffer;
  } else {
    buffer = it->second;
  }
  PIN_ReleaseLock(&buffer_lock);
  
  return buffer;
}

void InitRegisterMap() {
  for (REG reg = REG_FIRST; reg < REG_LAST; reg++) {
    string name = REG_StringShort(reg);
    transform(name.begin(), name.end(), name.begin(), ::tolower);
    regNameMap[name] = reg;
  }
  regNameMap["gax"] = REG::REG_GAX;
}

extern "C" UINT32 dbi_get_tid() {
  NATIVE_TID current_tid;

  OS_GetTid(&current_tid);

  return current_tid;
}
extern "C" const char *dbi_reg_to_string(UINT32 reg) {
  char* reg_string_buffer = get_thread_buffer();
  string reg_string = REG_StringShort((REG)reg);
  size_t len = reg_string.length();
  if (len >= REG_STRING_BUFFER_SIZE - 1) {
    len = REG_STRING_BUFFER_SIZE - 1;
  }
  memcpy(reg_string_buffer, reg_string.c_str(), len);
  reg_string_buffer[len] = '\0';
  return reg_string_buffer;
}

extern "C" REG dbi_string_to_reg(const char *reg_ptr) {
  const std::string regName = reg_ptr;
  string lower = regName;
  transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
  if (regNameMap.empty())
    InitRegisterMap();

  auto it = regNameMap.find(lower);
  if (it != regNameMap.end()) {
    return it->second;
  }
  return REG_INVALID();
}

extern "C" void dbi_force_exit() { PIN_ExitProcess(0); }

extern "C" size_t dbi_get_context_regval(CONTEXT *context, REG reg) {
  size_t reg_val = 0;
  PIN_GetContextRegval(context, reg, (UINT8 *)(&reg_val));
  return reg_val;
}

extern "C" void dbi_log(const char *message) {
  if (message != nullptr) {
    Logger::log(string(message));
  }
}