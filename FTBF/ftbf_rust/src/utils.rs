use crate::{alloc::string::ToString, checker::Checker, policy_structures::TaintPolicyConfig};
use alloc::collections::BTreeMap;
use alloc::string::String;
use anyhow::Result;
use core::ffi::{CStr, c_char};
use widestring::U16CStr;

/// Convert a C string pointer to a Rust String
#[inline]
pub fn c_to_rust_string(ptr: *const c_char) -> Result<String> {
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let rust_str = c_str.to_str()?;
    Ok(rust_str.to_string())
}

/// Convert a wide string (wchar_t*) pointer to a Rust String
/// On Windows, wchar_t is 16-bit (UTF-16)
#[inline]
pub fn wchar_to_rust_string(ptr: *const u16) -> Result<String> {
    let wide_str = unsafe { U16CStr::from_ptr_str(ptr) };
    wide_str.to_string().map_err(|e| anyhow::anyhow!("{}", e))
}

/// Load and parse taint policy configuration from JSON string
#[inline]
pub fn load_policy(policy_str: &str) -> Result<TaintPolicyConfig> {
    serde_json::from_str(policy_str).map_err(Into::into)
}

/// Load and parse checker from rule JSON string
#[inline]
pub fn load_checker(rule_str: &str) -> Result<Checker> {
    let mut checker = Checker::new();
    let _ = checker.load_rule_from_str(rule_str)?;
    Ok(checker)
}

/// Load and parse API parameter count mapping from JSON string
#[inline]
pub fn load_apis(apis_str: &str) -> Result<BTreeMap<String, u32>> {
    serde_json::from_str(apis_str).map_err(Into::into)
}

#[inline]
pub fn parse_number(input: &str) -> Option<usize> {
    let trimmed = input.trim();
    
    // Check for hex prefix (0x or 0X)
    if trimmed.len() > 2 && (trimmed.starts_with("0x") || trimmed.starts_with("0X")) {
        // Parse as hexadecimal (skip the "0x" prefix)
        usize::from_str_radix(&trimmed[2..], 16).ok()
    } else {
        // Parse as decimal
        trimmed.parse::<usize>().ok()
    }
}

unsafe extern "C" {
    pub fn dbi_get_tid() -> u32;
    pub fn dbi_reg_to_string(register: u32) -> *const c_char;
    pub fn dbi_string_to_reg(reg_ptr: *const c_char) -> u32;
    pub fn dbi_force_exit();
    
    /// Get register value from context (equivalent to PIN_GetContextRegval)
    /// Returns the value of the specified register from the given context
    pub fn dbi_get_context_regval(context: *const core::ffi::c_void, reg: u32) -> usize;
}
