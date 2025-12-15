#include "common.h"

extern map<string, REG> regNameMap;

extern "C" UINT32 dbi_get_tid();
extern "C" const char *dbi_reg_to_string(UINT32 reg);
extern "C" REG dbi_string_to_reg(const char *reg_ptr);

// Initialize thread-local buffer lock (call once at startup)
void InitBufferLock();