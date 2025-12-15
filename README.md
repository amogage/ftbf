# FTBF - Formal Tainting-Based Framework

A framework for **formal analysis of application behavior** that combines dynamic binary instrumentation, taint analysis, and runtime verification to detect malware capabilities.

## Overview

Malware analysis represents a difficult task due to its ever-changing nature, where attackers invent new techniques for evading analysis and prevention mechanisms. During fast-response investigations, a vital element is extracting or checking information to take proper action. Rather than generating exhaustive behavioral reports, FTBF provides **rapid verification of potential capabilities** with formal guarantees.

FTBF answers questions like: *Does it steal data? Is it ransomware? Does it perform code injection?* — and provides the **semantic reasoning chain** that led to each verdict, unlike statistical ML-based approaches.

### Key Contributions

The framework uses:

1. **Binary Instrumentation** (Intel PIN) — to control and monitor application execution
2. **Taint Analysis** — to extract relevant behavioral properties into a trace
3. **Runtime Verification** — with a specialized temporal logic called **Tainting-Based Logic (TBL)** to analyze the tainted trace
4. **Formal Behavior Specification** — user-defined capabilities expressed as temporal logic formulas

This combination enables **sound confirmation** of whether an application exhibits specific capabilities (e.g., code injection, encryption, deobfuscation, privilege escalation), ensured through formal checking.

> **Academic Foundation**: The core concepts of this framework - taint-based logic, formal behavior specification, and capability verification - are described in academic publications listed in the [References](#references) section. The framework has been used in real cyber forensics investigations, reducing the time and effort of security researchers.

### How It Works

1. **Define taint sources** — APIs whose return values or output parameters should be marked as tainted
2. **Track taint propagation** — Follow tainted data through registers, memory operations, and function calls  
3. **Detect behavioral patterns** — Match sequences of taint events against user-defined rules using temporal logic formulas

## Architecture

### Overall System Architecture

The system follows a layered approach where the target application runs under Intel PIN's control, with our custom Pintool receiving callbacks for specific events during execution.

```
                      ┌─────────────────────────┐
                      │    Target Application   │
                      │        (Binary)         │
                      └────────────┬────────────┘
                                   │
                                   ▼
                      ┌─────────────────────────┐
                      │      Intel Pin DBI      │
                      │        (Monolith)       │
                      └────────────┬────────────┘
                                   │
                      ┌────────────┴────────────┐
                      ▼                         ▼
              ┌──────────────┐          ┌──────────────┐
              │     JIT      │          │    Code      │
              │   Compiler   │          │    Cache     │
              └──────┬───────┘          └───────┬──────┘
                     │                          │
                     └────────────┬─────────────┘
                                  ▼
  ┌──────────────┐    ┌─────────────────────────┐    ┌──────────────┐
  │  TBL Rules   │───▶│     Custom Pintool      │◀───│ Taint Policy │
  │    (JSON)    │    │     (Taint + TBL)       │    │    (JSON)    │
  └──────────────┘    └────────────┬────────────┘    └──────────────┘
                                   │
          ┌────────────┬───────────┴───────────┬────────────┐
          ▼            ▼                       ▼            ▼
   ┌────────────┐ ┌────────────┐       ┌────────────┐ ┌────────────┐
   │    API     │ │   Instr    │       │   Taint    │ │    TBL     │
   │  Monitor   │ │  Monitor   │       │  Analysis  │ │   Engine   │
   └─────┬──────┘ └──────┬─────┘       └──────┬─────┘ └──────┬─────┘
         │               │                    │              │
         └───────────────┴─────────┬──────────┘              │
                                   ▼                         │
                      ┌─────────────────────┐                │
                      │    Tainted Trace    │────────────────┘
                      │       (Facts)       │
                      └──────────┬──────────┘
                                 │
                                 ▼
                      ┌─────────────────────┐
                      │    Verification     │
                      │       Results       │
                      └─────────────────────┘
```

**Components:**
- **API Monitor** — monitors executed APIs to selectively install callbacks before/after function calls
- **Instruction Monitor** — equivalent for CPU instructions
- **Taint Analysis** — handles tainting, tracking, and propagating information along execution flow
- **TBL Engine** — handles formalization and rule verification

### FFI-Based Implementation Architecture

A key architectural innovation is the separation between instrumentation (C++) and analysis logic (Rust) through a Foreign Function Interface (FFI):

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Intel Pin    │    │   C++ Plugin    │    │  FFI Interface  │    │  Rust Library   │
│ (C++ Framework) │───▶│ (Binding Layer) │◀──▶│  (C++ ↔ Rust)   │◀──▶│ (Core Analysis) │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └────────┬────────┘
                                                                              │
                    ┌─────────────────┬─────────────────┬─────────────────────┤
                    │                 │                 │                     │
                    ▼                 ▼                 ▼                     ▼
           ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
           │    Taint     │  │Formalization │  │    Rule      │  │     TBL      │
           │   Analysis   │  │              │  │   Checking   │  │    Engine    │
           └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
```

**Rust Bindings for Intel PIN:**

Intel PIN is a C++ framework that only exposes a C++ SDK for developing Pintools. This project constructs a **binding layer** that enables writing the core analysis logic in Rust while maintaining full access to PIN's instrumentation capabilities. The binding works through:

- A thin C++ plugin (`ffi.cpp`) that interfaces with PIN's SDK and handles instrumentation callbacks
- FFI function exports (`extern "C"`) that allow bidirectional data exchange between C++ and Rust
- Callback bridges for events like `dbi_get_tid()`, `dbi_reg_to_string()`, `dbi_get_context_regval()`

This approach allows leveraging Rust's safety guarantees and modern tooling for the complex analysis logic, while still benefiting from PIN's mature instrumentation infrastructure.

**Advantages of this architecture:**

1. **Framework Independence** — The Rust library is completely independent of the DBI framework and OS. It can be integrated with different DBI frameworks beyond Intel PIN without code modifications.

2. **Safety & Performance** — Rust's ownership system provides compile-time guarantees eliminating use-after-free, null pointer dereferences, and data races — critical for security analysis tools.

3. **Exhaustive Pattern Matching** — Rust's type system enforces handling all cases in AST node processing and rule verification at compile time.

4. **`no_std` Compatibility** — The Rust library uses only the `alloc` crate, enabling deployment in embedded systems, kernel modules, and WebAssembly platforms.

5. **Minimal FFI Overhead** — The C++ ↔ Rust interfacing introduces minimal overhead without impacting analysis time.

6. **Reusable Binding Pattern** — The same binding approach can be adapted for other DBI frameworks (DynamoRIO, Frida) by implementing the same FFI interface.

## Features

### Taint Tracking
- **Register propagation**: Tracks taint through all x86/x64 registers including sub-registers (RAX→EAX→AX→AH/AL)
- **Memory propagation**: Monitors memory reads/writes for taint spread
- **API monitoring**: Hooks Windows API calls to detect taint entering/leaving through parameters
- **Zeroing idioms**: Properly handles `XOR reg, reg` and `SUB reg, reg` patterns

### Behavioral Pattern Detection
- **Temporal logic operators**: `andThen` (sequence), `and`, `or`, `not`, `Next`
- **Predicate types**: `TaintedAPI`, `PropToAPI`, `PropToMem`, `TaintedCodeExecute`, `TaintedMemAccess`
- **Conditional predicates**: `TaintedAPICond`, `PropToAPICond` for parameter-based filtering

### Code Pattern Matching (Regex)
- Match instruction sequences using regex patterns
- Capture groups with backreferences for deobfuscation detection
- Constraint modes: `consecutive` or `intermittent`

## Prerequisites

- **Windows 10/11** (x86 or x64)
- **Visual Studio 2019/2022** with C++ build tools
- **Rust toolchain** (stable, with MSVC targets)
- **Intel PIN 3.31** (included in parent directory)

### Directory Structure

The build scripts expect FTBF to be placed in the PIN tools folder following this structure:

```
pin-3.31/                          # Intel PIN root directory
├── pin.exe
├── build_x64.bat                  # Build script (64-bit)
├── build_x86.bat                  # Build script (32-bit)
├── intel64/
│   └── bin/
│       ├── ftbf_policy.json       # Configuration files go here
│       ├── ftbf_rule.json
│       └── apis.json
└── source/
    └── tools/
        └── FTBF/                  # This module
            ├── ftbf.cpp
            ├── ftbf_rust/
            └── ...
```

The build scripts reference `source\tools\FTBF` relative to the PIN root directory.

### Rust Targets Setup
```bash
rustup target add x86_64-pc-windows-msvc
rustup target add i686-pc-windows-msvc
```

## Building

### 64-bit Build
From the repository root:
```cmd
build_x64.bat
```
Output: `source/tools/FTBF/obj-intel64/FTBF.dll`

### 32-bit Build
```cmd
build_x86.bat
```
Output: `source/tools/FTBF/obj-ia32/FTBF.dll`

### Visual Studio Paths

The build scripts automatically detect Visual Studio installations by checking these paths in order:

1. `C:\Program Files\Microsoft Visual Studio\18\Community\`
2. `C:\Program Files\Microsoft Visual Studio\2022\Community\`
3. `C:\Program Files\Microsoft Visual Studio\2019\Community\`
4. `C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\`

If your Visual Studio is installed in a different location (e.g., Enterprise or Professional edition), edit the build scripts to add your path:

```batch
REM Add your custom VS path before the existing checks:
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else if exist ...
```

Alternatively, run the build from a **Visual Studio Developer Command Prompt** which already has the environment configured.

## Configuration Files

Place these three files in the **same directory as `pin.exe`** before running:

1. `ftbf_policy.json` - Taint source configuration
2. `ftbf_rule.json` - Detection pattern/capability rules  
3. `apis.json` - Windows API parameter counts

> **Important:** All three configuration files must be present in the `pin.exe` directory at runtime, or the tool will fail to initialize.

### 1. `ftbf_policy.json` - Taint Source Configuration

```json
{
    "taint_sources": {
        "api_params": {
            "ReadFile": [
                {
                    "type": "ptr",
                    "index": 1,
                    "ptr_length": {
                        "len_param_index": 2,
                        "len_param_type": "size_t"
                    }
                }
            ],
            "GetEnvironmentVariable": [
                {
                    "type": "ptr",
                    "index": 2,
                    "ptr_length": {
                        "len_param_index": 3,
                        "len_param_type": "size_t"
                    }
                }
            ],
            "recv": [
                {
                    "type": "ptr",
                    "index": 1,
                    "ptr_length": {
                        "len_param_index": -1,
                        "len_param_type": "int"
                    }
                }
            ]
        }
    }
}
```

**Parameter Types:**
- `ptr` - Pointer to tainted memory region
  - `index`: Parameter index (0-based, -1 for return value)
  - `ptr_length.abs_val`: Fixed byte size
  - `ptr_length.len_param_index`: Index of size parameter
  - `ptr_length.len_param_type`: `"int"` or `"size_t"`
- `reg` - Register taint source (e.g., `"gax"` for return register)

### 2. `ftbf_rule.json` - Detection Pattern

```json
{
    "capability": {
        "Data Exfiltration": ["A", "B", "X"]
    },
    "metadata": {
        "explanation": "Detect network transmission of file contents",
        "constants": {
            "A": "ReadFile",
            "B": "send"
        }
    },
    "pattern": {
        "andThen": [
            {
                "and": [
                    { "TaintedAPI": ["A"] },
                    { "Next": { "Tainted": ["X"] } }
                ]
            },
            {
                "PropToAPI": ["B", "X"]
            }
        ]
    }
}
```

**Pattern Operators:**
| Operator | Description |
|----------|-------------|
| `andThen` | Sequential match (A then eventually B) |
| `and` | Both conditions at same event |
| `or` | Either condition |
| `not` | Negation |
| `Next` | Immediately following event |

**Predicates:**
| Predicate | Arguments | Description |
|-----------|-----------|-------------|
| `Tainted` | `[symbol]` | Taint source created |
| `TaintedAPI` | `[api_name]` | API is a taint source |
| `PropToAPI` | `[api_name, symbol]` | Taint flows to API parameter |
| `PropToMem` | `[addr, size, symbol]` | Taint flows to memory |
| `TaintedMemAccess` | `[addr, offset, symbol]` | Tainted memory read |
| `TaintedCodeExecute` | `[addr, symbol]` | Execution of tainted code |
| `TaintedAPICond` | `[api, conditions]` | Conditional API match |

### 3. `apis.json` - API Parameter Counts

```json
{
    "ReadFile": 5,
    "WriteFile": 5,
    "send": 4,
    "recv": 4,
    "CreateFileA": 7,
    "CreateFileW": 7
}
```

## Usage

```cmd
pin.exe -t FTBF.dll -- target_application.exe [args...]
```

### Output
- Per-thread log files: `pin_trace_PID-{pid}_TID-{tid}.log`
- Capability detection triggers process termination with exit code 0

## Included Rules

The `rules/` folder contains ready-to-use detection rules for common malware capabilities, as described in the academic publications:

| Folder | Description |
|--------|-------------|
| `Bypass UAC` | User Account Control bypass techniques |
| `Code Injection` | Process injection patterns |
| `Command and Control (C2) Communication` | Network-based C2 communication |
| `Debugger Detection API` | Anti-debugging via API calls |
| `Debugger Detection Code` | Anti-debugging via code patterns |
| `Deobfuscation` | Runtime code deobfuscation loops |
| `Disable Winevt` | Windows Event Log tampering |
| `Privilege escalation` | Elevation of privileges |
| `RansomwareEncryption` | File encryption patterns |

Each folder contains a `ftbf_policy.json` and `ftbf_rule.json` pair that can be copied to the `pin.exe` directory.

## Example: Debugger Detection

Included policy detects anti-debugging techniques:

**Policy (`ftbf_policy.json`):**
```json
{
    "taint_sources": {
        "api_params": {
            "IsDebuggerPresent": [],
            "GetCurrentProcess": [{ "type": "reg", "reg": "gax" }],
            "CheckRemoteDebuggerPresent": [],
            "ZwQueryInformationProcess": []
        }
    }
}
```

**Rule (`ftbf_rule.json`):**
```json
{
    "capability": { "Debugger Evasion": [] },
    "pattern": {
        "or": [
            { "TaintedAPI": ["IsDebuggerPresent"] },
            {
                "andThen": [
                    {
                        "and": [
                            { "TaintedAPI": ["GetCurrentProcess"] },
                            { "Next": { "Tainted": ["X_0"] } }
                        ]
                    },
                    { "PropToAPI": ["CheckRemoteDebuggerPresent", "X_0"] }
                ]
            }
        ]
    }
}
```

## Advanced: Regex Code Matching

Detect code patterns (e.g., deobfuscation loops):

```json
{
    "taint_sources": {
        "regex_code": {
            "code": [
                "xor (.+), .+",
                "mov byte ptr \\[(.+)\\+.+\\], \\1"
            ],
            "actions": {
                "predicates": [
                    { "Tainted": ["X"] },
                    { "PropToMem": ["\\2", "1", "X"] }
                ],
                "message": "Deobfuscation loop detected",
                "options": {
                    "constraint": "consecutive"
                }
            }
        }
    }
}
```

## Project Structure

```
ftbf/
├── build_x64.bat         # 64-bit build script
├── build_x86.bat         # 32-bit build script
├── rules/                # Pre-built detection rules (see Included Rules)
│   ├── Bypass UAC/
│   ├── Code Injection/
│   ├── Command and Control (C2) Communication/
│   ├── Debugger Detection API/
│   ├── Debugger Detection Code/
│   ├── Deobfuscation/
│   ├── Disable Winevt/
│   ├── Privilege escalation/
│   └── RansomwareEncryption/
└── FTBF/                 # PIN tool source
    ├── ftbf.cpp              # Main entry point
    ├── common.h              # Shared declarations, Logger class
    ├── types.h               # Common type definitions
    ├── cache_utils.*         # LRU cache for instruction strings
    ├── config_utils.*        # Configuration file loading
    ├── context_utils.*       # CPU context helpers
    ├── ffi.*                 # C++/Rust FFI bridge
    ├── image_utils.*         # Image/module identification
    ├── taint_wrappers.*      # Taint propagation callbacks
    ├── makefile              # PIN build system
    ├── makefile.rules        # Build rules
    └── ftbf_rust/            # Rust analysis engine
        ├── Cargo.toml
        ├── build.rs
        └── src/
            ├── lib.rs            # Crate root
            ├── allocator.rs      # Custom heap allocator
            ├── analyzer.rs       # Main analysis logic
            ├── checker.rs        # Rule pattern matching
            ├── ffi.rs            # FFI exports
            ├── logger.rs         # Logging bridge
            ├── policy_structures.rs  # Policy JSON types
            ├── registers.rs      # Register aliasing maps
            ├── taint_events.rs   # Event types
            ├── utils.rs          # Utility functions
            └── apis.json         # Windows API database
```

## Performance Considerations

- **Instruction caching**: LRU cache (10K entries) for disassembled strings
- **Image lookup caching**: Memoized checks for main executable/external libraries
- **Regex pre-compilation**: Patterns compiled once at initialization
- **no_std Rust**: 100MB custom heap, no runtime dependencies

## Troubleshooting

### Build Errors
- Ensure Visual Studio C++ tools are installed
- Run from VS Developer Command Prompt
- Verify Rust MSVC targets are installed

### Runtime Errors
- Check configuration files exist in `pin.exe` directory
- Verify JSON syntax in policy/rule files
- Check log files for detailed error messages

### Missing Detections
- Ensure API names match exactly (case-sensitive, with/without W/A suffix)
- Verify parameter indices are correct
- Check rule pattern logic

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## References

### Academic Publications
- Mogage, A., & Lucanu, D. (2024). *A Formal Tainting-Based Framework for Malware Analysis*. IFM 2024. [DOI](https://doi.org/10.1007/978-3-031-76554-4_1)
- Mogage, A. (2025). *Exposing Malware with Enriched Taint Analysis*. PhD Thesis, Alexandru Ioan Cuza University.
- Mogage, A. (2024). *A.I. Assisted Malware Capabilities Capturing*. KES 2024. [DOI](https://doi.org/10.1016/j.procs.2024.09.505)
- Mogage, A., & Lucanu, D. (2025). *Malware Analysis through Behavior Formalization*. (submitted)

### External Resources
- [Intel PIN Downloads & Documentation](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html)

