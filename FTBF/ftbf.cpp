#include "common.h"
#include "types.h"
#include "cache_utils.h"
#include "image_utils.h"
#include "context_utils.h"
#include "taint_wrappers.h"
#include "config_utils.h"
#include "ffi.h"

namespace {
constexpr size_t MAX_OPCODE_SIZE = 128;

void *rust_instance = nullptr;
} // anonymous namespace

void OnApiCall(ADDRINT target, CONTEXT *ctxt) {
  if (!ImageUtils::IsExternalLibrary(target)) {
    return;
  }

  const string api_name = RTN_FindNameByAddress(target);
  if (api_name.empty()) {
    return;
  }
  
  size_t params[MAX_API_PARAM_COUNT] = {0};
  ContextUtils::ExtractApiParameters(ctxt, params);

  on_api_call(rust_instance, api_name.c_str(), params);
}

inline void OnCallOrJump(ADDRINT target) { 
  on_call_or_jump(rust_instance, target); 
}

void OnApiReturn(ADDRINT return_value, CONTEXT *ctxt) {
  const size_t *stack = ContextUtils::GetStackPointer(ctxt);
  const size_t current_ip = ContextUtils::GetInstructionPointer(ctxt);

  const string api_name = RTN_FindNameByAddress(current_ip);
  if (api_name.empty()) {
    return;
  }

  // Verify return address is in main module and current IP is in an API
  const size_t return_address = stack[0];
  if (!ImageUtils::IsMainExecutable(return_address) || !ImageUtils::IsExternalLibrary(current_ip)) {
    return;
  }

  on_api_return(rust_instance, api_name.c_str(), return_value,
                reinterpret_cast<size_t>(stack));
}

// Insert instrumentation for logging API calls at the specified instruction
void InsertApiCallInstrumentation(INS ins, ADDRINT target_addr,
                                  bool is_direct_call) {
  if (is_direct_call) {
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(OnApiCall),
                             IARG_ADDRINT, target_addr, IARG_CONTEXT, IARG_END);
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(OnCallOrJump),
                             IARG_ADDRINT, target_addr, IARG_END);
  } else {
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(OnApiCall),
                             IARG_BRANCH_TARGET_ADDR, IARG_CONTEXT, IARG_END);
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(OnCallOrJump),
                             IARG_BRANCH_TARGET_ADDR, IARG_END);
  }
}

// Instrument a single instruction for API call tracking
void InstrumentInstruction(TRACE trace, INS ins) {
  // Only instrument instructions from the main executable
  if (!ImageUtils::IsMainExecutable(INS_Address(ins))) {
    return;
  }

  // Handle direct call instructions
  if (INS_IsCall(ins) && INS_IsDirectControlFlow(ins)) {
    const ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
    InsertApiCallInstrumentation(ins, target, true);
  }
  // Handle indirect calls and jumps
  else if (INS_IsCall(ins) || INS_IsIndirectControlFlow(ins)) {
    const RTN rtn = TRACE_Rtn(trace);
    if (RTN_Valid(rtn)) {
      InsertApiCallInstrumentation(ins, 0, false);
    }
  }
}

// Fixed: Uses cached strings with valid lifetimes
void CheckInstrRegex(CONTEXT *ctxt, const char *instr_line) {
  check_instr_regex(rust_instance, ctxt, instr_line);
}

void OnInstruction(INS ins) {
  // Handle LEA instruction taint propagation
  // Note: If both base and index registers are present, taint is propagated
  // from both
  if (INS_IsLea(ins)) {
    const REG dest_reg = INS_OperandReg(ins, 0);

    // Propagate taint from index register if present
    const REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
    if (index_reg != REG_INVALID_) {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TaintWrappers::RegToReg, IARG_UINT32,
                     dest_reg, IARG_UINT32, index_reg, IARG_END);
    }

    // Propagate taint from base register if present
    const REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
    if (base_reg != REG_INVALID_) {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TaintWrappers::RegToReg, IARG_UINT32,
                     dest_reg, IARG_UINT32, base_reg, IARG_END);
    }
  }

  // Special case: XOR reg, reg (same register) should untaint the destination
  // because the result is always zero regardless of the input value.
  // This is a common idiom for zeroing registers.
  const xed_iclass_enum_t iclass = static_cast<xed_iclass_enum_t>(INS_Opcode(ins));
  if ((iclass == XED_ICLASS_XOR || iclass == XED_ICLASS_PXOR || 
       iclass == XED_ICLASS_XORPS || iclass == XED_ICLASS_XORPD ||
       iclass == XED_ICLASS_SUB || iclass == XED_ICLASS_PSUBB ||
       iclass == XED_ICLASS_PSUBW || iclass == XED_ICLASS_PSUBD) &&
      INS_OperandCount(ins) >= 2 &&
      INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1) &&
      INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1)) {
    // XOR/SUB reg, reg -> result is always 0, untaint the register
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TaintWrappers::ImmediateToReg,
                   IARG_UINT32, INS_OperandReg(ins, 0), IARG_UINT64, 0, IARG_END);
    // Skip normal taint propagation for this instruction
    goto skip_taint_propagation;
  }

  // Process all operands for taint propagation
  {
  const UINT32 operand_count = INS_OperandCount(ins);
  UINT32 mem_op_index = 0;

  for (UINT32 op = 0; op < operand_count; ++op) {
    if (!INS_OperandWritten(ins, op)) {
      continue;
    }

    // Check if this is an interesting destination operand
    bool is_dest_interesting = false;

    if (INS_OperandIsReg(ins, op)) {
      const REG dest_reg = INS_OperandReg(ins, op);
#ifdef _M_X64
      is_dest_interesting =
          (dest_reg != REG::REG_RFLAGS && dest_reg != REG::REG_INVALID_);
#else
      is_dest_interesting =
          (dest_reg != REG::REG_EFLAGS && dest_reg != REG::REG_INVALID_);
#endif
    } else if (INS_OperandIsMemory(ins, op)) {
      mem_op_index++;
      is_dest_interesting = true;
    }

    if (!is_dest_interesting) {
      continue;
    }

    // Look for source operands to propagate taint from
    UINT32 mem_op_2_index = 0;
    for (UINT32 op_2 = 0; op_2 < operand_count; ++op_2) {
      if (op == op_2 || !INS_OperandRead(ins, op_2)) {
        continue;
      }

      // Handle register source operands
      if (INS_OperandIsReg(ins, op_2)) {
        const REG src_reg = INS_OperandReg(ins, op_2);
        bool is_valid_src_reg = false;

#ifdef _M_X64
        is_valid_src_reg =
            (src_reg != REG::REG_RIP && src_reg != REG::REG_RFLAGS &&
             src_reg != REG::REG_INVALID_);
#else
        is_valid_src_reg =
            (src_reg != REG::REG_EIP && src_reg != REG::REG_EFLAGS &&
             src_reg != REG::REG_INVALID_);
#endif

        if (is_valid_src_reg) {
          if (INS_OperandIsReg(ins, op)) {
            // Reg-to-reg: skip if it's the same register
            if (!INS_IsMovFullRegRegSame(ins)) {
              INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TaintWrappers::RegToReg, IARG_UINT32,
                             INS_OperandReg(ins, op), IARG_UINT32, src_reg,
                             IARG_END);
            }
          } else {
            // Reg-to-mem
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TaintWrappers::RegToMem,
                           IARG_MEMORYOP_EA, mem_op_index - 1,
                           IARG_MEMORYOP_SIZE, mem_op_index - 1, IARG_UINT32,
                           src_reg, IARG_END);
          }
        }
      }

      // Handle memory source operands
      if (INS_OperandIsMemory(ins, op_2)) {
        mem_op_2_index++;

        if (INS_OperandIsReg(ins, op)) {
          // Mem-to-reg
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TaintWrappers::MemToReg, IARG_UINT32,
                         INS_OperandReg(ins, op), IARG_MEMORYOP_EA,
                         mem_op_2_index - 1, IARG_MEMORYOP_SIZE,
                         mem_op_2_index - 1, IARG_END);
        } else if (INS_OperandIsMemory(ins, op)) {
          // Mem-to-mem (Note: memory operand indexing may need verification)
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TaintWrappers::MemToMem,
                         IARG_MEMORYOP_EA, 1, IARG_MEMORYOP_SIZE, 1,
                         IARG_MEMORYOP_EA, 0, IARG_MEMORYOP_SIZE, 0, IARG_END);
        }
      }

      // Handle immediate source operands
      if (INS_OperandIsImmediate(ins, op_2)) {
        if (INS_OperandIsReg(ins, op)) {
          // Imm-to-reg
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TaintWrappers::ImmediateToReg,
                         IARG_UINT32, INS_OperandReg(ins, op), IARG_UINT64,
                         INS_OperandImmediate(ins, op_2), IARG_END);
        } else {
          // Imm-to-mem
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TaintWrappers::ImmediateToMem,
                         IARG_MEMORYOP_EA, mem_op_index - 1, IARG_MEMORYOP_SIZE,
                         mem_op_index - 1, IARG_UINT64,
                         INS_OperandImmediate(ins, op_2), IARG_END);
        }
      }
    }
  }
  }
  skip_taint_propagation:
  
  if (!is_regex_enabled(rust_instance))
    return;

  // Cache the instruction string to ensure valid pointer lifetime
  // The cache stores unique strings, so memory usage is bounded
  if (INS_IsValidForIpointAfter(ins)) {
    const char* cached_instr = CacheUtils::GetCachedInstrString(INS_Disassemble(ins));
    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)CheckInstrRegex, IARG_CONTEXT,
                   IARG_PTR, cached_instr, IARG_END);
  }
}

// Trace instrumentation callback: analyze each basic block in the trace
void OnTrace(TRACE trace, void *v) {
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    const INS head = BBL_InsHead(bbl);

    for (INS ins = head; INS_Valid(ins); ins = INS_Next(ins)) {

      const IMG image = IMG_FindByAddress(INS_Address(ins));

      if (IMG_Valid(image) && IMG_IsMainExecutable(image)) {
        OnInstruction(ins);
      }
    }
    // Instrument the last instruction of each basic block
    InstrumentInstruction(trace, BBL_InsTail(bbl));
  }
}

// Cleanup callback to properly close log files when the program exits
void OnFini(INT32 code, void *v) {
  on_exit(rust_instance);
  Logger::close_all();
}

// Instrumentation callback for routine returns
void OnReturn(RTN rtn, void *v) {
  RTN_Open(rtn);
  RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)OnApiReturn,
                 IARG_FUNCRET_EXITPOINT_VALUE, IARG_CONTEXT, IARG_END);
  RTN_Close(rtn);
}

int main(int argc, char *argv[]) {
  // Initialize PIN symbol processing (required to resolve function names)
  PIN_InitSymbols();

  // Initialize PIN
  if (PIN_Init(argc, argv)) {
    return -1;
  }

  // Extract working directory from argv[0]
  const string working_dir = GetWorkingDirectory(argv[0]);

  // Initialize logger with working directory
  Logger::initialize(working_dir.c_str());

  // Initialize locks for thread-safe operations
  ImageUtils::InitializeLocks();
  CacheUtils::InitializeLocks();
  InitBufferLock();

  // Initialize Rust backend from same directory as executable
  rust_instance = ConfigUtils::LoadRustModule(working_dir);
  if (rust_instance == nullptr) {
    return -1;
  }

  // Set the Rust instance for taint wrappers
  TaintWrappers::SetRustInstance(rust_instance);

  // Register instrumentation callbacks
  TRACE_AddInstrumentFunction(OnTrace, nullptr);
  RTN_AddInstrumentFunction(OnReturn, nullptr);
  PIN_AddFiniFunction(OnFini, nullptr);
  
  // Start the instrumented program
  Logger::log("Starting analyzed program!\n");
  PIN_StartProgram();

  return 0;
}
