use core::ffi::c_char;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use log::error;
use serde::{Deserialize, Serialize};

use crate::taint_events::TaintEvent;
use crate::utils::{c_to_rust_string, wchar_to_rust_string};

// Top-level configuration object
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TaintPolicyConfig {
    pub taint_sources: TaintSources,
    pub extra_info: Option<ExtraInfo>,
}

// The taint sources object can contain either arbitrary API names mapping to ParamInfo lists,
// plus an optional special key "regex_code" with a different structure.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct TaintSources {
    pub api_params: Option<BTreeMap<String, Vec<ParamInfo>>>, // API name -> [ParamInfo]
    pub regex_code: Option<RegexCode>,
}

// ParamInfo for taint sources - tagged enum based on "type" field
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ParamInfo {
    Ptr {
        index: i32, // -1 allowed for return value
        #[serde(rename = "ptr_length")]
        ptr_length: PtrLength,
    },
    Reg {
        reg: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LenParamType {
    #[serde(rename = "int")]
    Int,
    #[serde(rename = "size_t")]
    SizeT,
}

// Pointer length descriptor: either abs_val, or (len_param_index,len_param_type)
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct PtrLength {
    pub abs_val: Option<u64>,
    #[serde(alias = "rel_param_index")]
    pub len_param_index: Option<i32>,
    #[serde(alias = "rel_param_type")]
    pub len_param_type: Option<LenParamType>,
}

// Regex-based code matching
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RegexCode {
    pub code: Vec<String>,
    pub actions: RegexActions,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RegexOptions {
    pub constraint: Option<Constraint>,
    #[serde(rename = "last_X")]
    pub last_x: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    #[serde(rename = "intermittent")]
    Intermittent,
    #[serde(rename = "consecutive")]
    Consecutive,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum Predicate {
    Tainted,
    Untainted,
    TaintedAPI,
    PropToAPI,
    PropToReg,
    PropToMem,
    TaintedMemAccess,
    UntaintedReg,
    TaintedAPICond,
    PropToAPICond,
    TaintedCodeExecute,
    Unknown, //for errors
}

pub type PredicateCall = BTreeMap<Predicate, Vec<String>>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RegexActions {
    // { "PredicateName": ["param1", "param2", ...] }
    #[serde(default)]
    pub predicates: Vec<PredicateCall>,
    pub message: Option<String>,
    pub options: Option<RegexOptions>,
}

// Extra configuration information
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtraInfo {
    #[serde(default)]
    pub sources: BTreeMap<String, Vec<ParamInfoExtended>>, // API name -> list of ParamInfoExtended
    #[serde(default)]
    pub trigger_save: BTreeMap<Predicate, Vec<String>>, // predicate name -> list of API names
    #[serde(default)]
    pub trigger_check: Vec<String>, // list of API or Predicate names
}

impl ExtraInfo {
    pub fn is_trigger_check(&self, potential_trigger: &String) -> bool {
        self.trigger_check.contains(potential_trigger)
    }
    fn is_source(&self, api_name: &String) -> bool {
        self.sources.contains_key(api_name)
    }
    fn is_trigger_save(&self, predicate: Predicate, api_name: &String) -> bool {
        if !self.trigger_save.contains_key(&predicate) {
            return false;
        }
        self.trigger_save[&predicate].contains(api_name)
    }
    pub fn save_extra_info(
        &mut self,
        event: &mut TaintEvent,
        api_name: &String,
        parameters: &Vec<usize>,
        is_wide: bool,
    ) {
        if !self.is_trigger_save(event.get_predicate(), api_name) {
            return;
        }
        if !self.is_source(api_name) {
            return;
        }

        // Helper closure to convert string with unified error handling
        let convert_string = |ptr, is_wide_char: bool| -> Option<String> {
            let result = if is_wide_char {
                wchar_to_rust_string(ptr as *const u16)
            } else {
                c_to_rust_string(ptr as *const c_char)
            };

            match result {
                Ok(s) => Some(s),
                Err(e) => {
                    error!("Failed to convert string for api {}: {}", api_name, e);
                    None
                }
            }
        };

        for source in &self.sources[api_name] {
            let info = match source {
                ParamInfoExtended::Int { index } => {
                    (parameters[*index as usize] as i32).to_string()
                }
                ParamInfoExtended::SizeT { index } => parameters[*index as usize].to_string(),
                ParamInfoExtended::Ptr { index, ptr_length } => {
                    let string_size = ptr_length.abs_val.map(|v| v as usize).unwrap_or_else(|| {
                        let len_param_index = ptr_length.len_param_index.unwrap() as usize;
                        if matches!(ptr_length.len_param_type, Some(LenParamType::Int)) {
                            parameters[len_param_index] as i32 as usize
                        } else {
                            parameters[len_param_index]
                        }
                    });
                    
                    // Validate pointer and size before creating slice
                    let ptr = parameters[*index as usize] as *const u8;
                    if ptr.is_null() || string_size == 0 {
                        error!("Invalid pointer or size for api {}: ptr={:?}, size={}", 
                               api_name, ptr, string_size);
                        return;
                    }
                    
                    // Safety: We've validated ptr is non-null and size > 0.
                    // The caller is responsible for ensuring the memory is valid and readable.
                    let buffer: &[u8] = unsafe {
                        core::slice::from_raw_parts(ptr, string_size)
                    };
                    let mut hex_string = String::with_capacity(string_size * 2);
                    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
                    for &byte in buffer {
                        hex_string.push(HEX_CHARS[(byte >> 4) as usize] as char);
                        hex_string.push(HEX_CHARS[(byte & 0xf) as usize] as char);
                    }
                    hex_string
                }
                ParamInfoExtended::Astr { index } => {
                    match convert_string(parameters[*index as usize], false) {
                        Some(s) => s,
                        None => return,
                    }
                }
                ParamInfoExtended::Wstr { index } => {
                    match convert_string(parameters[*index as usize], true) {
                        Some(s) => s,
                        None => return,
                    }
                }
                ParamInfoExtended::Str { index } => {
                    match convert_string(parameters[*index as usize], is_wide) {
                        Some(s) => s,
                        None => return,
                    }
                }
            };
            event.add_additional_info(info);
        }
    }
}

// Extended ParamInfo accepted by extra_info.sources - tagged enum based on "type" field
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ParamInfoExtended {
    Ptr {
        index: i32,
        #[serde(rename = "ptr_length")]
        ptr_length: PtrLength,
    },
    Int {
        index: i32,
    },
    SizeT {
        index: i32,
    },
    Astr {
        index: i32,
    },
    Wstr {
        index: i32,
    },
    Str {
        index: i32,
    },
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn regex_policy() {
        let json_str = r#"
        {
            "taint_sources": {
                "regex_code": {
                    "code": [
                        "xor (.+), .+",
                        "mov byte ptr \\[(.+)\\+.+\\], \\1"
                    ],
                    "actions": {
                        "predicates": [
                            {
                                "Tainted": [
                                    "X"
                                ]
                            },
                            {
                                "PropToMem": [
                                    "\\2",
                                    "1",
                                    "X"
                                ]
                            }
                        ],
                        "message": "Deobfuscation attempt detected!",
                        "options": {
                            "constraint": "consecutive"
                        }
                    }
                }
            }
        }
        "#;
        let taint_policy_from_json: TaintPolicyConfig = serde_json::from_str(json_str).unwrap();

        let taint_policy_config = TaintPolicyConfig {
            taint_sources: TaintSources {
                regex_code: Some(RegexCode {
                    code: vec![
                        String::from("xor (.+), .+"),
                        String::from("mov byte ptr \\[(.+)\\+.+\\], \\1"),
                    ],
                    actions: RegexActions {
                        predicates: vec![
                            BTreeMap::from([(Predicate::Tainted, vec![String::from("X")])]),
                            BTreeMap::from([(
                                Predicate::PropToMem,
                                vec![String::from("\\2"), String::from("1"), String::from("X")],
                            )]),
                        ],
                        message: Some(String::from("Deobfuscation attempt detected!")),
                        options: Some(RegexOptions {
                            constraint: Some(Constraint::Consecutive),
                            last_x: None,
                        }),
                    },
                }),
                api_params: None,
            },
            extra_info: None,
        };
        assert_eq!(taint_policy_from_json, taint_policy_config);
    }

    #[test]
    fn param_info_deserialization() {
        let ptr_json = r#"{
            "type": "ptr",
            "index": 0,
            "ptr_length": {
                "abs_val": 256
            }
        }"#;
        let ptr_param: ParamInfo = serde_json::from_str(ptr_json).unwrap();
        match ptr_param {
            ParamInfo::Ptr { index, ptr_length } => {
                assert_eq!(index, 0);
                assert_eq!(ptr_length.abs_val, Some(256));
            }
            _ => panic!("Expected Ptr variant"),
        }

        let reg_json = r#"{
            "type": "reg",
            "reg": "rax"
        }"#;
        let reg_param: ParamInfo = serde_json::from_str(reg_json).unwrap();
        match reg_param {
            ParamInfo::Reg { reg } => {
                assert_eq!(reg, "rax");
            }
            _ => panic!("Expected Reg variant"),
        }
    }

    #[test]
    fn param_info_extended_deserialization() {
        let ptr_json = r#"{
            "type": "ptr",
            "index": 1,
            "ptr_length": {
                "len_param_index": 2,
                "len_param_type": "size_t"
            }
        }"#;
        let ptr_param: ParamInfoExtended = serde_json::from_str(ptr_json).unwrap();
        match ptr_param {
            ParamInfoExtended::Ptr { index, ptr_length } => {
                assert_eq!(index, 1);
                assert_eq!(ptr_length.len_param_index, Some(2));
                assert_eq!(ptr_length.len_param_type, Some(LenParamType::SizeT));
            }
            _ => panic!("Expected Ptr variant"),
        }

        let int_json = r#"{
            "type": "int",
            "index": 3
        }"#;
        let int_param: ParamInfoExtended = serde_json::from_str(int_json).unwrap();
        match int_param {
            ParamInfoExtended::Int { index } => {
                assert_eq!(index, 3);
            }
            _ => panic!("Expected Int variant"),
        }
    }
}
