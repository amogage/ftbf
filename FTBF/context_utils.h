#ifndef CONTEXT_UTILS_H
#define CONTEXT_UTILS_H

#include "common.h"
#include "types.h"

namespace ContextUtils {

// Get current instruction pointer based on architecture
size_t GetInstructionPointer(CONTEXT *ctxt);

// Get current stack pointer based on architecture
size_t* GetStackPointer(CONTEXT *ctxt);

// Extract API call parameters based on calling convention
void ExtractApiParameters(CONTEXT *ctxt, size_t params[MAX_API_PARAM_COUNT]);

} // namespace ContextUtils

#endif // CONTEXT_UTILS_H

