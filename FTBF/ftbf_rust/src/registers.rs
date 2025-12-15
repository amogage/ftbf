/// Register hierarchy management for x86/x86_64 architectures
/// 
/// This module handles register aliasing (e.g., RAX/EAX/AX/AH/AL all refer to parts
/// of the same physical register) by maintaining lookup tables for efficient untainting.

const EMPTY_REGS: &[u32] = &[];

// x86_64 (Intel64/TARGET_IA32E) register enum values
#[cfg(target_arch = "x86_64")]
mod x64_regs {
    // RAX family
    pub const RAX_SUBS: &[u32] = &[10, 56, 29, 28, 27]; // RAX, EAX, AX, AH, AL
    pub const EAX_SUBS: &[u32] = &[56, 29, 28, 27]; // EAX, AX, AH, AL
    pub const AX_SUBS: &[u32] = &[29, 28, 27]; // AX, AH, AL
    pub const AH_SUBS: &[u32] = &[28]; // AH
    pub const AL_SUBS: &[u32] = &[27]; // AL

    // RBX family
    pub const RBX_SUBS: &[u32] = &[7, 53, 38, 37, 36]; // RBX, EBX, BX, BH, BL
    pub const EBX_SUBS: &[u32] = &[53, 38, 37, 36]; // EBX, BX, BH, BL
    pub const BX_SUBS: &[u32] = &[38, 37, 36]; // BX, BH, BL
    pub const BH_SUBS: &[u32] = &[37]; // BH
    pub const BL_SUBS: &[u32] = &[36]; // BL

    // RCX family
    pub const RCX_SUBS: &[u32] = &[9, 55, 32, 31, 30]; // RCX, ECX, CX, CH, CL
    pub const ECX_SUBS: &[u32] = &[55, 32, 31, 30]; // ECX, CX, CH, CL
    pub const CX_SUBS: &[u32] = &[32, 31, 30]; // CX, CH, CL
    pub const CH_SUBS: &[u32] = &[31]; // CH
    pub const CL_SUBS: &[u32] = &[30]; // CL

    // RDX family
    pub const RDX_SUBS: &[u32] = &[8, 54, 35, 34, 33]; // RDX, EDX, DX, DH, DL
    pub const EDX_SUBS: &[u32] = &[54, 35, 34, 33]; // EDX, DX, DH, DL
    pub const DX_SUBS: &[u32] = &[35, 34, 33]; // DX, DH, DL
    pub const DH_SUBS: &[u32] = &[34]; // DH
    pub const DL_SUBS: &[u32] = &[33]; // DL

    // RDI family
    pub const RDI_SUBS: &[u32] = &[3, 45, 41, 46]; // RDI, EDI, DI, DIL
    pub const EDI_SUBS: &[u32] = &[45, 41, 46]; // EDI, DI, DIL
    pub const DI_SUBS: &[u32] = &[41, 46]; // DI, DIL
    pub const DIL_SUBS: &[u32] = &[46]; // DIL

    // RSI family
    pub const RSI_SUBS: &[u32] = &[4, 47, 40, 48]; // RSI, ESI, SI, SIL
    pub const ESI_SUBS: &[u32] = &[47, 40, 48]; // ESI, SI, SIL
    pub const SI_SUBS: &[u32] = &[40, 48]; // SI, SIL
    pub const SIL_SUBS: &[u32] = &[48]; // SIL

    // RBP family
    pub const RBP_SUBS: &[u32] = &[5, 49, 39, 50]; // RBP, EBP, BP, BPL
    pub const EBP_SUBS: &[u32] = &[49, 39, 50]; // EBP, BP, BPL
    pub const BP_SUBS: &[u32] = &[39, 50]; // BP, BPL
    pub const BPL_SUBS: &[u32] = &[50]; // BPL

    // RSP family
    pub const RSP_SUBS: &[u32] = &[6, 51, 42, 52]; // RSP, ESP, SP, SPL
    pub const ESP_SUBS: &[u32] = &[51, 42, 52]; // ESP, SP, SPL
    pub const SP_SUBS: &[u32] = &[42, 52]; // SP, SPL
    pub const SPL_SUBS: &[u32] = &[52]; // SPL

    // R8 family
    pub const R8_SUBS: &[u32] = &[11, 61, 60, 59]; // R8, R8D, R8W, R8B
    pub const R8D_SUBS: &[u32] = &[61, 60, 59]; // R8D, R8W, R8B
    pub const R8W_SUBS: &[u32] = &[60, 59]; // R8W, R8B
    pub const R8B_SUBS: &[u32] = &[59]; // R8B

    // R9 family
    pub const R9_SUBS: &[u32] = &[12, 64, 63, 62]; // R9, R9D, R9W, R9B
    pub const R9D_SUBS: &[u32] = &[64, 63, 62]; // R9D, R9W, R9B
    pub const R9W_SUBS: &[u32] = &[63, 62]; // R9W, R9B
    pub const R9B_SUBS: &[u32] = &[62]; // R9B

    // R10 family
    pub const R10_SUBS: &[u32] = &[13, 67, 66, 65]; // R10, R10D, R10W, R10B
    pub const R10D_SUBS: &[u32] = &[67, 66, 65]; // R10D, R10W, R10B
    pub const R10W_SUBS: &[u32] = &[66, 65]; // R10W, R10B
    pub const R10B_SUBS: &[u32] = &[65]; // R10B

    // R11 family
    pub const R11_SUBS: &[u32] = &[14, 70, 69, 68]; // R11, R11D, R11W, R11B
    pub const R11D_SUBS: &[u32] = &[70, 69, 68]; // R11D, R11W, R11B
    pub const R11W_SUBS: &[u32] = &[69, 68]; // R11W, R11B
    pub const R11B_SUBS: &[u32] = &[68]; // R11B

    // R12 family
    pub const R12_SUBS: &[u32] = &[15, 73, 72, 71]; // R12, R12D, R12W, R12B
    pub const R12D_SUBS: &[u32] = &[73, 72, 71]; // R12D, R12W, R12B
    pub const R12W_SUBS: &[u32] = &[72, 71]; // R12W, R12B
    pub const R12B_SUBS: &[u32] = &[71]; // R12B

    // R13 family
    pub const R13_SUBS: &[u32] = &[16, 76, 75, 74]; // R13, R13D, R13W, R13B
    pub const R13D_SUBS: &[u32] = &[76, 75, 74]; // R13D, R13W, R13B
    pub const R13W_SUBS: &[u32] = &[75, 74]; // R13W, R13B
    pub const R13B_SUBS: &[u32] = &[74]; // R13B

    // R14 family
    pub const R14_SUBS: &[u32] = &[17, 79, 78, 77]; // R14, R14D, R14W, R14B
    pub const R14D_SUBS: &[u32] = &[79, 78, 77]; // R14D, R14W, R14B
    pub const R14W_SUBS: &[u32] = &[78, 77]; // R14W, R14B
    pub const R14B_SUBS: &[u32] = &[77]; // R14B

    // R15 family
    pub const R15_SUBS: &[u32] = &[18, 82, 81, 80]; // R15, R15D, R15W, R15B
    pub const R15D_SUBS: &[u32] = &[82, 81, 80]; // R15D, R15W, R15B
    pub const R15W_SUBS: &[u32] = &[81, 80]; // R15W, R15B
    pub const R15B_SUBS: &[u32] = &[80]; // R15B
}

// x86 (IA-32) register enum values
#[cfg(target_arch = "x86")]
mod x86_regs {
    // EAX family (EAX is the main register in 32-bit, not RAX)
    pub const EAX_SUBS: &[u32] = &[10, 21, 20, 19]; // EAX, AX, AH, AL
    pub const AX_SUBS: &[u32] = &[21, 20, 19]; // AX, AH, AL
    pub const AH_SUBS: &[u32] = &[20]; // AH
    pub const AL_SUBS: &[u32] = &[19]; // AL

    // EBX family
    pub const EBX_SUBS: &[u32] = &[7, 30, 29, 28]; // EBX, BX, BH, BL
    pub const BX_SUBS: &[u32] = &[30, 29, 28]; // BX, BH, BL
    pub const BH_SUBS: &[u32] = &[29]; // BH
    pub const BL_SUBS: &[u32] = &[28]; // BL

    // ECX family
    pub const ECX_SUBS: &[u32] = &[9, 24, 23, 22]; // ECX, CX, CH, CL
    pub const CX_SUBS: &[u32] = &[24, 23, 22]; // CX, CH, CL
    pub const CH_SUBS: &[u32] = &[23]; // CH
    pub const CL_SUBS: &[u32] = &[22]; // CL

    // EDX family
    pub const EDX_SUBS: &[u32] = &[8, 27, 26, 25]; // EDX, DX, DH, DL
    pub const DX_SUBS: &[u32] = &[27, 26, 25]; // DX, DH, DL
    pub const DH_SUBS: &[u32] = &[26]; // DH
    pub const DL_SUBS: &[u32] = &[25]; // DL

    // EDI family
    pub const EDI_SUBS: &[u32] = &[3, 33]; // EDI, DI
    pub const DI_SUBS: &[u32] = &[33]; // DI

    // ESI family
    pub const ESI_SUBS: &[u32] = &[4, 32]; // ESI, SI
    pub const SI_SUBS: &[u32] = &[32]; // SI

    // EBP family
    pub const EBP_SUBS: &[u32] = &[5, 31]; // EBP, BP
    pub const BP_SUBS: &[u32] = &[31]; // BP

    // ESP family
    pub const ESP_SUBS: &[u32] = &[6, 34]; // ESP, SP
    pub const SP_SUBS: &[u32] = &[34]; // SP
}

#[cfg(target_arch = "x86_64")]
use x64_regs::*;

#[cfg(target_arch = "x86")]
use x86_regs::*;

/// Get all sub-registers for a given register (O(1) lookup)
/// Returns a slice containing the register and all its sub-registers
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub fn get_sub_registers(reg: u32) -> &'static [u32] {
    match reg {
        // RAX family
        10 => RAX_SUBS,
        56 => EAX_SUBS,
        29 => AX_SUBS,
        28 => AH_SUBS,
        27 => AL_SUBS,
        // RBX family
        7 => RBX_SUBS,
        53 => EBX_SUBS,
        38 => BX_SUBS,
        37 => BH_SUBS,
        36 => BL_SUBS,
        // RCX family
        9 => RCX_SUBS,
        55 => ECX_SUBS,
        32 => CX_SUBS,
        31 => CH_SUBS,
        30 => CL_SUBS,
        // RDX family
        8 => RDX_SUBS,
        54 => EDX_SUBS,
        35 => DX_SUBS,
        34 => DH_SUBS,
        33 => DL_SUBS,
        // RDI family
        3 => RDI_SUBS,
        45 => EDI_SUBS,
        41 => DI_SUBS,
        46 => DIL_SUBS,
        // RSI family
        4 => RSI_SUBS,
        47 => ESI_SUBS,
        40 => SI_SUBS,
        48 => SIL_SUBS,
        // RBP family
        5 => RBP_SUBS,
        49 => EBP_SUBS,
        39 => BP_SUBS,
        50 => BPL_SUBS,
        // RSP family
        6 => RSP_SUBS,
        51 => ESP_SUBS,
        42 => SP_SUBS,
        52 => SPL_SUBS,
        // R8 family
        11 => R8_SUBS,
        61 => R8D_SUBS,
        60 => R8W_SUBS,
        59 => R8B_SUBS,
        // R9 family
        12 => R9_SUBS,
        64 => R9D_SUBS,
        63 => R9W_SUBS,
        62 => R9B_SUBS,
        // R10 family
        13 => R10_SUBS,
        67 => R10D_SUBS,
        66 => R10W_SUBS,
        65 => R10B_SUBS,
        // R11 family
        14 => R11_SUBS,
        70 => R11D_SUBS,
        69 => R11W_SUBS,
        68 => R11B_SUBS,
        // R12 family
        15 => R12_SUBS,
        73 => R12D_SUBS,
        72 => R12W_SUBS,
        71 => R12B_SUBS,
        // R13 family
        16 => R13_SUBS,
        76 => R13D_SUBS,
        75 => R13W_SUBS,
        74 => R13B_SUBS,
        // R14 family
        17 => R14_SUBS,
        79 => R14D_SUBS,
        78 => R14W_SUBS,
        77 => R14B_SUBS,
        // R15 family
        18 => R15_SUBS,
        82 => R15D_SUBS,
        81 => R15W_SUBS,
        80 => R15B_SUBS,
        // Unknown register
        _ => EMPTY_REGS,
    }
}

#[inline(always)]
#[cfg(target_arch = "x86")]
pub fn get_sub_registers(reg: u32) -> &'static [u32] {
    match reg {
        // EAX family
        10 => EAX_SUBS,
        21 => AX_SUBS,
        20 => AH_SUBS,
        19 => AL_SUBS,
        // EBX family
        7 => EBX_SUBS,
        30 => BX_SUBS,
        29 => BH_SUBS,
        28 => BL_SUBS,
        // ECX family
        9 => ECX_SUBS,
        24 => CX_SUBS,
        23 => CH_SUBS,
        22 => CL_SUBS,
        // EDX family
        8 => EDX_SUBS,
        27 => DX_SUBS,
        26 => DH_SUBS,
        25 => DL_SUBS,
        // EDI family
        3 => EDI_SUBS,
        33 => DI_SUBS,
        // ESI family
        4 => ESI_SUBS,
        32 => SI_SUBS,
        // EBP family
        5 => EBP_SUBS,
        31 => BP_SUBS,
        // ESP family
        6 => ESP_SUBS,
        34 => SP_SUBS,
        // Unknown register
        _ => EMPTY_REGS,
    }
}

/// "Volatile" registers: their value is overwritten upon API return
#[cfg(target_arch = "x86_64")]
pub const VOLATILE_REGS: &[u32] = &[10, 9, 8, 11, 12, 13, 14, 95, 96]; // RAX, RCX, RDX, R8, R9, R10, R11, XMM4, XMM5

/// Registers used to pass parameters on x64 API calls
#[cfg(target_arch = "x86_64")]
pub const PARAMETER_REGS: &[u32] = &[9, 8, 11, 12]; // RCX, RDX, R8, R9

/// "Volatile" registers on x86 (32-bit)
#[cfg(target_arch = "x86")]
pub const VOLATILE_REGS: &[u32] = &[10]; // EAX

/// x86 uses the stack only to pass parameters for API calls
#[cfg(target_arch = "x86")]
pub const PARAMETER_REGS: &[u32] = &[];

/// Fallback for non-x86 architectures (for compilation only, not runtime use)
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub const VOLATILE_REGS: &[u32] = &[];

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub const PARAMETER_REGS: &[u32] = &[];

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn get_sub_registers(_reg: u32) -> &'static [u32] {
    EMPTY_REGS
}

