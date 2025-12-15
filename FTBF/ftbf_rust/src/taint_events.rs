#![allow(dead_code)]

use crate::policy_structures::Predicate;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamConditionType {
    Int,
    SizeT,
    Ptr,
    Str,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ApiParamCondition {
    pub index: i32,
    pub param_type: ParamConditionType,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaintedMemory {
    pub start: usize,
    pub sz: usize,
}

impl TaintedMemory {
    #[inline]
    pub fn includes_address(&self, address: usize) -> bool {
        address >= self.start && address < self.start + self.sz
    }
}

/// Main TaintEvent enum representing all possible taint event types
#[derive(Debug, Clone)]
pub enum TaintEvent {
    Tainted(TaintedEvent),
    Untainted(UntaintedEvent),
    TaintedAPI(TaintedAPIEvent),
    PropToAPI(PropToAPIEvent),
    PropToReg(PropToRegEvent),
    PropToMem(PropToMemEvent),
    TaintedMemAccess(TaintedMemAccessEvent),
    TaintedCodeExecute(TaintedCodeExecuteEvent),
    UntaintedReg(UntaintedRegEvent),
}

impl TaintEvent {
    #[inline]
    pub fn get_predicate(&self) -> Predicate {
        match self {
            TaintEvent::Tainted(_) => Predicate::Tainted,
            TaintEvent::Untainted(_) => Predicate::Untainted,
            TaintEvent::TaintedAPI(_) => Predicate::TaintedAPI,
            TaintEvent::PropToAPI(_) => Predicate::PropToAPI,
            TaintEvent::PropToReg(_) => Predicate::PropToReg,
            TaintEvent::PropToMem(_) => Predicate::PropToMem,
            TaintEvent::TaintedMemAccess(_) => Predicate::TaintedMemAccess,
            TaintEvent::TaintedCodeExecute(_) => Predicate::TaintedCodeExecute,
            TaintEvent::UntaintedReg(_) => Predicate::UntaintedReg,
        }
    }

    #[inline]
    pub fn get_additional_info(&self) -> &Vec<String> {
        match self {
            TaintEvent::Tainted(e) => &e.additional_info,
            TaintEvent::Untainted(e) => &e.additional_info,
            TaintEvent::TaintedAPI(e) => &e.additional_info,
            TaintEvent::PropToAPI(e) => &e.additional_info,
            TaintEvent::PropToReg(e) => &e.additional_info,
            TaintEvent::PropToMem(e) => &e.additional_info,
            TaintEvent::TaintedMemAccess(e) => &e.additional_info,
            TaintEvent::TaintedCodeExecute(e) => &e.additional_info,
            TaintEvent::UntaintedReg(e) => &e.additional_info,
        }
    }

    #[inline]
    pub fn add_additional_info(&mut self, info: String) {
        match self {
            TaintEvent::Tainted(e) => e.additional_info.push(info),
            TaintEvent::Untainted(e) => e.additional_info.push(info),
            TaintEvent::TaintedAPI(e) => e.additional_info.push(info),
            TaintEvent::PropToAPI(e) => e.additional_info.push(info),
            TaintEvent::PropToReg(e) => e.additional_info.push(info),
            TaintEvent::PropToMem(e) => e.additional_info.push(info),
            TaintEvent::TaintedMemAccess(e) => e.additional_info.push(info),
            TaintEvent::TaintedCodeExecute(e) => e.additional_info.push(info),
            TaintEvent::UntaintedReg(e) => e.additional_info.push(info),
        }
    }

    #[inline]
    pub fn to_string(&self) -> String {
        match self {
            TaintEvent::Tainted(e) => e.to_string(),
            TaintEvent::Untainted(e) => e.to_string(),
            TaintEvent::TaintedAPI(e) => e.to_string(),
            TaintEvent::PropToAPI(e) => e.to_string(),
            TaintEvent::PropToReg(e) => e.to_string(),
            TaintEvent::PropToMem(e) => e.to_string(),
            TaintEvent::TaintedMemAccess(e) => e.to_string(),
            TaintEvent::TaintedCodeExecute(e) => e.to_string(),
            TaintEvent::UntaintedReg(e) => e.to_string(),
        }
    }
}

// Tainted(T)
#[derive(Debug, Clone)]
pub struct TaintedEvent {
    pub symbol: String,
    pub additional_info: Vec<String>,
}

impl TaintedEvent {
    #[inline]
    pub fn new(symbol: String) -> Self {
        Self {
            symbol,
            additional_info: Vec::new(),
        }
    }

    #[inline]
    pub fn get_symbol(&self) -> &str {
        &self.symbol
    }

    #[inline]
    pub fn to_string(&self) -> String {
        format!("Tainted({})", self.symbol)
    }
}

// Untainted(T)
#[derive(Debug, Clone)]
pub struct UntaintedEvent {
    pub symbol: String,
    pub additional_info: Vec<String>,
}

impl UntaintedEvent {
    #[inline]
    pub fn new(symbol: String) -> Self {
        Self {
            symbol,
            additional_info: Vec::new(),
        }
    }

    #[inline]
    pub fn to_string(&self) -> String {
        format!("Untainted({})", self.symbol)
    }
}

// Tainted(A)
#[derive(Debug, Clone)]
pub struct TaintedAPIEvent {
    pub api_name: String,
    pub additional_info: Vec<String>,
}

impl TaintedAPIEvent {
    #[inline]
    pub fn new(api_name: String) -> Self {
        Self {
            api_name,
            additional_info: Vec::new(),
        }
    }

    #[inline]
    pub fn get_api(&self) -> &str {
        &self.api_name
    }

    #[inline]
    pub fn to_string(&self) -> String {
        format!("TaintedAPI({})", self.api_name)
    }
}

// PropToAPI(A,T)
#[derive(Debug, Clone)]
pub struct PropToAPIEvent {
    pub api_name: String,
    pub symbol: String,
    pub additional_info: Vec<String>,
}

impl PropToAPIEvent {
    #[inline]
    pub fn new(api_name: String, symbol: String) -> Self {
        Self {
            api_name,
            symbol,
            additional_info: Vec::new(),
        }
    }

    #[inline]
    pub fn get_api(&self) -> &str {
        &self.api_name
    }

    #[inline]
    pub fn get_symbol(&self) -> &str {
        &self.symbol
    }

    #[inline]
    pub fn to_string(&self) -> String {
        format!("PropToAPI({}, {})", self.api_name, self.symbol)
    }
}

// PropToReg(R,T)
#[derive(Debug, Clone)]
pub struct PropToRegEvent {
    pub reg: String,
    pub symbol: String,
    pub additional_info: Vec<String>,
}

impl PropToRegEvent {
    #[inline]
    pub fn new(reg: String, symbol: String) -> Self {
        Self {
            reg,
            symbol,
            additional_info: Vec::new(),
        }
    }

    #[inline]
    pub fn to_string(&self) -> String {
        format!("PropToReg({}, {})", self.reg, self.symbol)
    }
}

// PropToMem(M,SZ,T)
#[derive(Debug, Clone)]
pub struct PropToMemEvent {
    pub mem: TaintedMemory,
    pub symbol: String,
    pub additional_info: Vec<String>,
}

impl PropToMemEvent {
    #[inline]
    pub fn new(mem: TaintedMemory, symbol: String) -> Self {
        Self {
            mem,
            symbol,
            additional_info: Vec::new(),
        }
    }

    #[inline]
    pub fn get_tainted_memory(&self) -> TaintedMemory {
        self.mem
    }

    #[inline]
    pub fn get_symbol(&self) -> &str {
        &self.symbol
    }

    #[inline]
    pub fn to_string(&self) -> String {
        format!(
            "PropToMem({:#x}, {}, {})",
            self.mem.start, self.mem.sz, self.symbol
        )
    }
}

// TaintedMemAccess(M,O,T)
#[derive(Debug, Clone)]
pub struct TaintedMemAccessEvent {
    pub addr: usize,
    pub offset: usize,
    pub symbol: String,
    pub additional_info: Vec<String>,
}

impl TaintedMemAccessEvent {
    #[inline]
    pub fn new(addr: usize, offset: usize, symbol: String) -> Self {
        Self {
            addr,
            offset,
            symbol,
            additional_info: Vec::new(),
        }
    }

    #[inline]
    pub fn get_memory_address(&self) -> usize {
        self.addr
    }

    #[inline]
    pub fn get_offset(&self) -> usize {
        self.offset
    }

    #[inline]
    pub fn get_symbol(&self) -> &str {
        &self.symbol
    }

    #[inline]
    pub fn to_string(&self) -> String {
        format!(
            "TaintedMemAccess({:#x}, {}, {})",
            self.addr, self.offset, self.symbol
        )
    }
}

// TaintedCodeExecute(M,T)
#[derive(Debug, Clone)]
pub struct TaintedCodeExecuteEvent {
    pub addr: usize,
    pub symbol: String,
    pub additional_info: Vec<String>,
}

impl TaintedCodeExecuteEvent {
    #[inline]
    pub fn new(addr: usize, symbol: String) -> Self {
        Self {
            addr,
            symbol,
            additional_info: Vec::new(),
        }
    }

    #[inline]
    pub fn get_memory_address(&self) -> usize {
        self.addr
    }

    #[inline]
    pub fn get_symbol(&self) -> &str {
        &self.symbol
    }

    #[inline]
    pub fn to_string(&self) -> String {
        format!("TaintedCodeExecute({:#x}, {})", self.addr, self.symbol)
    }
}

// Untainted(R)
#[derive(Debug, Clone)]
pub struct UntaintedRegEvent {
    pub reg: String,
    pub additional_info: Vec<String>,
}

impl UntaintedRegEvent {
    #[inline]
    pub fn new(reg: String) -> Self {
        Self {
            reg,
            additional_info: Vec::new(),
        }
    }

    #[inline]
    pub fn to_string(&self) -> String {
        format!("UntaintedReg({})", self.reg)
    }
}
