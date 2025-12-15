#include "context_utils.h"

namespace ContextUtils {

namespace {
constexpr size_t MAX_STACK_PARAMS = 16; // Additional stack params for x64
} // anonymous namespace

size_t GetInstructionPointer(CONTEXT *ctxt) {
#ifdef _M_X64
  return PIN_GetContextReg(ctxt, LEVEL_BASE::REG_RIP);
#else
  return PIN_GetContextReg(ctxt, LEVEL_BASE::REG_EIP);
#endif
}

size_t* GetStackPointer(CONTEXT *ctxt) {
#ifdef _M_X64
  return reinterpret_cast<size_t*>(
      PIN_GetContextReg(ctxt, LEVEL_BASE::REG_RSP));
#else
  return reinterpret_cast<size_t*>(
      PIN_GetContextReg(ctxt, LEVEL_BASE::REG_ESP));
#endif
}

void ExtractApiParameters(CONTEXT *ctxt, size_t params[MAX_API_PARAM_COUNT]) {
#ifdef _M_X64
  // x64 Windows calling convention: RCX, RDX, R8, R9, then stack
  const size_t *stack =
      reinterpret_cast<const size_t*>(PIN_GetContextReg(ctxt, LEVEL_BASE::REG_RSP));
  params[0] = PIN_GetContextReg(ctxt, LEVEL_BASE::REG_RCX);
  params[1] = PIN_GetContextReg(ctxt, LEVEL_BASE::REG_RDX);
  params[2] = PIN_GetContextReg(ctxt, LEVEL_BASE::REG_R8);
  params[3] = PIN_GetContextReg(ctxt, LEVEL_BASE::REG_R9);
  // Only copy what we need, avoid unnecessary memcpy
  constexpr size_t stack_param_count = MAX_API_PARAM_COUNT - 4;
  for (size_t i = 0; i < stack_param_count && i < MAX_STACK_PARAMS; ++i) {
    params[4 + i] = stack[i];
  }
#else
  // x86 calling convention: all parameters on stack
  const size_t *stack =
      reinterpret_cast<const size_t*>(PIN_GetContextReg(ctxt, LEVEL_BASE::REG_ESP));
  for (size_t i = 0; i < MAX_API_PARAM_COUNT; ++i) {
    params[i] = stack[i];
  }
#endif
}

} // namespace ContextUtils

