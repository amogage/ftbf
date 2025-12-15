#ifndef TAINT_WRAPPERS_H
#define TAINT_WRAPPERS_H

#include "common.h"

namespace TaintWrappers {

// Set the Rust instance pointer used by taint wrappers
void SetRustInstance(void* instance);

// Taint propagation wrappers
void RegToReg(REG reg_dest, REG reg_source);
void RegToMem(size_t addr_dest, UINT32 sz_dest, REG reg_source);
void MemToReg(REG reg_dest, size_t addr_source, size_t sz_source);
void MemToMem(size_t addr_dest, UINT32 sz_dest, size_t addr_source, size_t sz_source);
void ImmediateToReg(REG reg_dest, size_t immediate_source);
void ImmediateToMem(size_t addr_dest, size_t sz_dest, size_t immediate_source);

} // namespace TaintWrappers

#endif // TAINT_WRAPPERS_H

