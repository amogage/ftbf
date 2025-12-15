#include "taint_wrappers.h"
#include "types.h"

namespace TaintWrappers {

namespace {
void* rust_instance = nullptr;
} // anonymous namespace

void SetRustInstance(void* instance) {
  rust_instance = instance;
}

void RegToReg(REG reg_dest, REG reg_source) {
  reg_to_reg(rust_instance, reg_dest, reg_source);
}

void RegToMem(size_t addr_dest, UINT32 sz_dest, REG reg_source) {
  reg_to_mem(rust_instance, addr_dest, sz_dest, reg_source);
}

void MemToReg(REG reg_dest, size_t addr_source, size_t sz_source) {
  mem_to_reg(rust_instance, reg_dest, addr_source, sz_source);
}

void MemToMem(size_t addr_dest, UINT32 sz_dest, size_t addr_source, size_t sz_source) {
  mem_to_mem(rust_instance, addr_dest, sz_dest, addr_source, sz_source);
}

void ImmediateToReg(REG reg_dest, size_t immediate_source) {
  immediate_to_reg(rust_instance, reg_dest, immediate_source);
}

void ImmediateToMem(size_t addr_dest, size_t sz_dest, size_t immediate_source) {
  immediate_to_mem(rust_instance, addr_dest, sz_dest, immediate_source);
}

} // namespace TaintWrappers

