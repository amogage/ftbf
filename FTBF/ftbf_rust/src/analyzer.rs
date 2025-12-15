use crate::checker::Checker;
use crate::policy_structures::{LenParamType, ParamInfo, TaintPolicyConfig};
use crate::registers::{PARAMETER_REGS, VOLATILE_REGS, get_sub_registers};
use crate::taint_events::{
    PropToAPIEvent, PropToMemEvent, PropToRegEvent, TaintEvent, TaintedAPIEvent,
    TaintedCodeExecuteEvent, TaintedEvent, TaintedMemAccessEvent, TaintedMemory, UntaintedRegEvent,
};
use crate::utils::{
    c_to_rust_string, dbi_force_exit, dbi_get_tid, dbi_reg_to_string, dbi_string_to_reg, load_apis,
    load_checker, load_policy, parse_number,
};
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::ffi::CString;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use anyhow::Result;
use core::cmp;
use log::{error, info, warn};
use regex::Regex;

/// Metadata for tracking regex pattern matching progress per thread
#[derive(Debug, Clone)]
struct RegexMetadata {
    offset: usize,
    matches: BTreeMap<String, String>,
}

pub struct Analyzer {
    trace: Vec<TaintEvent>,
    symbol_counter: u32,
    policy: TaintPolicyConfig,
    checker: Checker,
    api_count_map: BTreeMap<String, u32>, //API -> Param count
    api_params_by_tid: BTreeMap<u32, Vec<Vec<usize>>>, //For each TID, we use a stack (using rust vec) where we push a vec of api params on api_call and pop on api_ret
    tainted_registers: BTreeMap<u32, BTreeMap<u32, String>>, //TID -> { REG -> SYMBOL}
    tainted_memory: BTreeMap<TaintedMemory, String>, //[MEMORY START: MEMORY START + LENGTH] -> SYMBOL
    regex_metadata: BTreeMap<u32, Vec<RegexMetadata>>, //TID -> Vec of active regex match states
    compiled_regexes: Vec<Option<Regex>>, // Pre-compiled regex patterns (Some if no backrefs, None otherwise)
    regex_success_once: bool,             // Flag to stop checking after first successful match
}

impl Analyzer {
    pub fn new(policy_str: &str, rule_str: &str, apis_str: &str) -> Result<Analyzer> {
        let policy = load_policy(policy_str)?;

        // Note: Patterns with backreferences (\1, \2) cannot be compiled until runtime
        let compiled_regexes = if let Some(regex_code) = &policy.taint_sources.regex_code {
            regex_code
                .code
                .iter()
                .map(|pattern| {
                    // Try to compile; if it fails (likely due to backreferences), store None
                    // These will be compiled at runtime with backreferences substituted
                    Regex::new(pattern).ok()
                })
                .collect()
        } else {
            Vec::new()
        };

        Ok(Analyzer {
            trace: Vec::with_capacity(1024),
            symbol_counter: 0,
            policy,
            checker: load_checker(rule_str)?,
            api_count_map: load_apis(apis_str)?,
            api_params_by_tid: BTreeMap::new(),
            tainted_registers: BTreeMap::new(),
            tainted_memory: BTreeMap::new(),
            regex_metadata: BTreeMap::new(),
            compiled_regexes,
            regex_success_once: false,
        })
    }

    pub fn on_exit(&mut self) {
        self.check_rule();
        // info!("Trace: ");
        // for event in &self.trace {
        //     info!("{}", event.to_string());
        // }
        info!("Exiting rust side...");
    }

    #[inline]
    fn register_event(&mut self, event: TaintEvent) {
        let should_check = if self.policy.extra_info.is_some() {
            let predicate_name = format!("{:?}", event.get_predicate());
            self.is_trigger_check(&predicate_name)
        } else {
            false
        };

        self.trace.push(event);

        if should_check {
            self.check_rule();
        }
    }

    #[inline]
    fn is_api_source(&self, api_name: &String) -> bool {
        let api_sources = &self.policy.taint_sources.api_params;
        if api_sources.is_none() {
            return false;
        }
        api_sources.as_ref().unwrap().contains_key(api_name)
    }

    #[inline]
    fn is_trigger_check(&self, potential_trigger: &String) -> bool {
        match &self.policy.extra_info {
            None => false,
            Some(extra_info) => extra_info.is_trigger_check(&potential_trigger),
        }
    }

    fn check_rule(&mut self) {
        match self.checker.check_formula(&self.trace) {
            Ok(true) => unsafe { dbi_force_exit() },
            Err(e) => error!("{e}"),
            _ => {}
        }
    }

    #[inline]
    fn get_next_symbol(&mut self) -> String {
        let symbol = format!("T{}", self.symbol_counter);
        self.symbol_counter += 1;
        symbol
    }

    #[inline]
    fn normalize_api_name(&self, api_name: &str) -> String {
        if api_name.ends_with('W') || api_name.ends_with('A') {
            api_name[..api_name.len() - 1].to_string()
        } else {
            api_name.to_string()
        }
    }

    /// Find tainted memory regions that contain the given address
    /// Returns (memory_start, offset, symbol) tuples
    fn find_tainted_memory_at(&self, addr: usize) -> Vec<(usize, usize, String)> {
        self.tainted_memory
            .iter()
            .filter(|(tainted_mem, _)| {
                addr >= tainted_mem.start && addr < tainted_mem.start + tainted_mem.sz
            })
            .map(|(tainted_mem, symbol)| {
                (tainted_mem.start, addr - tainted_mem.start, symbol.clone())
            })
            .collect()
    }

    /// Untaint a memory region by removing it from the tainted memory map
    #[inline]
    fn untaint_memory(&mut self, addr: usize) {
        self.tainted_memory
            .retain(|tainted_mem, _| !tainted_mem.includes_address(addr));
    }
    pub fn get_api_param_count(&mut self, api_name: &String) -> u32 {
        let normalized_api = self.normalize_api_name(api_name);
        *self.api_count_map.get(&normalized_api).unwrap_or(&0)
    }
    fn taint_api_source(
        &mut self,
        api_name: &String,
        parameters: &Vec<usize>,
        is_wide: bool,
    ) -> String {
        let mut tainted_api_event = TaintEvent::TaintedAPI(TaintedAPIEvent::new(api_name.clone()));
        let symbol = self.get_next_symbol();
        let tainted_event = TaintEvent::Tainted(TaintedEvent::new(symbol.clone()));

        if let Some(extra_info) = &mut self.policy.extra_info {
            extra_info.save_extra_info(&mut tainted_api_event, api_name, parameters, is_wide);
        }

        self.register_event(tainted_api_event);
        self.register_event(tainted_event);

        symbol
    }
    fn untaint_registers(&mut self, base_register: u32) -> Result<()> {
        let tid = unsafe { dbi_get_tid() };

        // Check if the register is tainted before we start removing
        let was_tainted = self
            .tainted_registers
            .get(&tid)
            .map(|regs| regs.contains_key(&base_register))
            .unwrap_or(false);

        // Register the untaint event if it was tainted
        if was_tainted {
            let register_string = unsafe { c_to_rust_string(dbi_reg_to_string(base_register))? };
            let untainted_reg_event = UntaintedRegEvent::new(register_string);
            self.register_event(TaintEvent::UntaintedReg(untainted_reg_event));
        }

        if let Some(regs) = self.tainted_registers.get_mut(&tid) {
            let sub_regs = get_sub_registers(base_register);
            if sub_regs.is_empty() {
                regs.remove(&base_register);
            } else {
                for &sub_reg in sub_regs {
                    regs.remove(&sub_reg);
                }
            }
        }

        Ok(())
    }

    fn taint_registers(&mut self, base_register: u32, symbol: String) -> Result<()> {
        let tid = unsafe { dbi_get_tid() };

        // Check if the register is tainted before we start removing
        let tainted_registers = self.tainted_registers.entry(tid).or_insert(BTreeMap::new());

        let register_string = unsafe { c_to_rust_string(dbi_reg_to_string(base_register))? };
        let tainted_reg_event = PropToRegEvent::new(register_string, symbol.clone());

        let sub_regs = get_sub_registers(base_register);
        if sub_regs.is_empty() {
            tainted_registers.insert(base_register, symbol.clone());
        } else {
            for &sub_reg in sub_regs {
                tainted_registers.insert(sub_reg, symbol.clone());
            }
        }

        self.register_event(TaintEvent::PropToReg(tainted_reg_event));

        Ok(())
    }

    fn propagate_taint_to_api(
        &mut self,
        api_name: &String,
        parameters: &Vec<usize>,
        stack_ptr: usize,
        is_wide: bool,
    ) {
        let tid = unsafe { dbi_get_tid() };

        if !self.tainted_registers.contains_key(&tid) && self.tainted_memory.is_empty() {
            return;
        }

        let parameters_count = parameters.len();
        let mut tainted_symbols = BTreeSet::new();

        // Check parameter registers
        if let Some(tainted_registers) = self.tainted_registers.get(&tid) {
            for i in 0..cmp::min(parameters_count, PARAMETER_REGS.len()) {
                // We do this in order to check sub-registers for the parameter regs, e.g. r8/r8d/r8w/r8b for r8
                // This prevents under-tainting
                let registers = get_sub_registers(PARAMETER_REGS[i]);
                for reg in registers {
                    if let Some(symbol) = tainted_registers.get(reg) {
                        tainted_symbols.insert(symbol.clone());
                    }
                }
            }
        }
        if PARAMETER_REGS.len() < parameters_count {
            if !self.tainted_memory.is_empty() {
                // Check memory parameters (on stack)
                for parameter in &parameters[PARAMETER_REGS.len()..] {
                    for (tainted_mem, symbol) in &self.tainted_memory {
                        if tainted_mem.includes_address(*parameter) {
                            tainted_symbols.insert(symbol.clone());
                        }
                    }
                }

                // Check stack frame
                // At API return time, stack_ptr[0] still contains the return address
                // x64 Windows calling convention:
                //   - stack_ptr[0] = return address (8 bytes)
                //   - stack_ptr[1-4] = shadow space (32 bytes = 4 * 8 bytes)
                //   - stack_ptr[5] = first stack parameter (parameter index 4)
                //   - stack_ptr[6] = second stack parameter (parameter index 5)
                // x86 Windows calling convention:
                //   - stack_ptr[0] = return address (4 bytes)
                //   - stack_ptr[1] = first parameter (parameter index 0, since PARAMETER_REGS is empty)
                //   - stack_ptr[2] = second parameter (parameter index 1)
                // For parameter index i (where i >= PARAMETER_REGS.len()):
                //   offset = (i + 1) * size_of::<usize>(), which accounts for return address (1 slot) +
                //   shadow space (x64 only, 4 slots) + parameter offset
                // This works for both x86 (PARAMETER_REGS.len() = 0) and x64 (PARAMETER_REGS.len() = 4)
                for i in PARAMETER_REGS.len()..parameters_count {
                    let stack_offset = (i + 1) * size_of::<usize>();
                    for (tainted_mem, symbol) in &self.tainted_memory {
                        if tainted_mem.includes_address(stack_ptr + stack_offset) {
                            tainted_symbols.insert(symbol.clone());
                        }
                    }
                }
            }
        }

        // Register all events
        if tainted_symbols.is_empty() {
            return;
        }

        let has_extra_info = self.policy.extra_info.is_some();
        for symbol in tainted_symbols {
            let prop_to_api_event = PropToAPIEvent::new(api_name.clone(), symbol);
            let mut registered_event = TaintEvent::PropToAPI(prop_to_api_event);
            if has_extra_info {
                let extra_info = &mut self.policy.extra_info.as_mut().unwrap();
                extra_info.save_extra_info(&mut registered_event, api_name, parameters, is_wide);
            }
            self.register_event(registered_event);
        }
    }
    fn propagate_taint_from_api(
        &mut self,
        api_name: &String,
        symbol: &String,
        parameters: &Vec<usize>,
        return_value: usize,
    ) -> Result<()> {
        if self.policy.taint_sources.api_params.is_none() {
            return Ok(());
        }

        let tid = unsafe { dbi_get_tid() };

        // Untaint volatile registers
        if let Some(regs) = self.tainted_registers.get_mut(&tid) {
            for &reg_u32 in VOLATILE_REGS {
                let sub_regs = get_sub_registers(reg_u32);
                if sub_regs.is_empty() {
                    regs.remove(&reg_u32);
                } else {
                    for &sub_reg in sub_regs {
                        regs.remove(&sub_reg);
                    }
                }
            }
        }

        let param_info_vec = match self
            .policy
            .taint_sources
            .api_params
            .as_ref()
            .and_then(|params| params.get(api_name))
        {
            Some(params) => params.clone(),
            None => {
                // API not found in taint sources - this shouldn't happen if is_api_source
                // was checked, but handle defensively
                error!(
                    "API {} not found in taint sources despite passing is_api_source check",
                    api_name
                );
                return Ok(());
            }
        };

        for param_info in param_info_vec {
            match param_info {
                ParamInfo::Ptr { index, ptr_length } => {
                    let memory_start = if index == -1 {
                        return_value
                    } else {
                        parameters[index as usize]
                    };

                    let memory_size = if let Some(abs_val) = ptr_length.abs_val {
                        abs_val as usize
                    } else {
                        let len_param_index = ptr_length.len_param_index.unwrap();
                        if len_param_index == -1 {
                            return_value
                        } else if matches!(ptr_length.len_param_type, Some(LenParamType::Int)) {
                            parameters[len_param_index as usize] as u32 as usize
                        } else {
                            parameters[len_param_index as usize]
                        }
                    };

                    let tainted_memory = TaintedMemory {
                        start: memory_start,
                        sz: memory_size,
                    };
                    let prop_to_mem_event = PropToMemEvent::new(tainted_memory, symbol.clone());
                    self.tainted_memory.insert(tainted_memory, symbol.clone());
                    self.register_event(TaintEvent::PropToMem(prop_to_mem_event));
                }
                ParamInfo::Reg { reg } => {
                    let reg_u32 =
                        unsafe { dbi_string_to_reg(CString::new(reg.as_str()).unwrap().as_ptr()) };
                    self.untaint_registers(reg_u32)?;
                    self.taint_registers(reg_u32, symbol.clone())?;
                }
            }
        }

        Ok(())
    }
    pub fn on_call_or_jump(&mut self, target_address: usize) {
        let matches = self.find_tainted_memory_at(target_address);
        for (_, _, symbol) in matches {
            let tainted_code_execute = TaintedCodeExecuteEvent::new(target_address, symbol);
            self.register_event(TaintEvent::TaintedCodeExecute(tainted_code_execute));
        }
    }
    pub fn on_api_call(&mut self, _api_name: &String, parameters: Vec<usize>) {
        let tid = unsafe { dbi_get_tid() };
        let params_history = self.api_params_by_tid.entry(tid).or_insert_with(Vec::new);
        params_history.push(parameters);
    }
    /// Handle API return event
    ///
    /// On API return, we perform the following actions:
    /// 1. Propagate taint to parameters (via registers or memory)
    /// 2. If API is included in taint sources, insert TaintedAPI & Tainted events
    pub fn on_api_return(&mut self, api_name: String, return_value: usize, stack_ptr: usize) {
        let tid = unsafe { dbi_get_tid() };
        let parameters = self
            .api_params_by_tid
            .get_mut(&tid)
            .and_then(|stack| stack.pop())
            .unwrap_or_default();

        let normalized_api = self.normalize_api_name(&api_name);
        let is_wide = api_name.ends_with('W');

        let has_taint =
            self.tainted_registers.contains_key(&tid) || !self.tainted_memory.is_empty();
        if !has_taint && !self.is_api_source(&normalized_api) {
            if self.is_trigger_check(&normalized_api) {
                self.check_rule();
            }
            return;
        }

        self.propagate_taint_to_api(&normalized_api, &parameters, stack_ptr, is_wide);

        if !self.is_api_source(&normalized_api) {
            if self.is_trigger_check(&normalized_api) {
                self.check_rule();
            }
            return;
        }

        let symbol = self.taint_api_source(&normalized_api, &parameters, is_wide);
        if let Err(e) =
            self.propagate_taint_from_api(&normalized_api, &symbol, &parameters, return_value)
        {
            error!("Error propagating taint from API {}: {}", normalized_api, e);
        }


        if self.is_trigger_check(&normalized_api) {
            self.check_rule();
        }
    }

    /// Propagate taint from one register to another (e.g., mov reg_dest, reg_source)
    ///
    /// # Arguments
    /// * `reg_dest` - Destination register enum value
    /// * `reg_source` - Source register enum value
    ///
    /// # Note
    /// This handles instructions like "mov edi, esi" but NOT "xor edi, edi"
    /// (which should untaint the register instead)
    pub fn reg_to_reg(&mut self, reg_dest: u32, reg_source: u32) -> Result<()> {
        let tid = unsafe { dbi_get_tid() };

        // Untaint destination register first
        self.untaint_registers(reg_dest)?;

        // If source register is tainted, propagate taint to destination
        if let Some(tainted_regs) = self.tainted_registers.get(&tid) {
            if let Some(symbol) = tainted_regs.get(&reg_source) {
                self.taint_registers(reg_dest, symbol.clone())?;
            }
        }

        Ok(())
    }

    /// Propagate taint from register to memory (e.g., mov [addr_dest], reg_source)
    ///
    /// # Arguments
    /// * `addr_dest` - Destination memory address
    /// * `sz_dest` - Size of destination memory in bytes
    /// * `reg_source` - Source register enum value
    pub fn reg_to_mem(&mut self, addr_dest: usize, sz_dest: u32, reg_source: u32) -> Result<()> {
        let tid = unsafe { dbi_get_tid() };

        // Untaint destination memory first
        self.untaint_memory(addr_dest);

        // Check if source register is tainted and clone the symbol if it is
        let symbol = self
            .tainted_registers
            .get(&tid)
            .and_then(|regs| regs.get(&reg_source))
            .cloned();

        // If source register was tainted, propagate taint to destination memory
        if let Some(symbol) = symbol {
            let tainted_memory = TaintedMemory {
                start: addr_dest,
                sz: sz_dest as usize,
            };

            let prop_to_mem_event = PropToMemEvent::new(tainted_memory, symbol.clone());
            self.register_event(TaintEvent::PropToMem(prop_to_mem_event));
            self.tainted_memory.insert(tainted_memory, symbol);
        }

        Ok(())
    }

    /// Propagate taint from memory to register (e.g., mov reg_dest, [addr_source])
    ///
    /// # Arguments
    /// * `reg_dest` - Destination register enum value
    /// * `addr_source` - Source memory address
    /// * `_sz_source` - Size of source memory in bytes (unused, kept for API consistency)
    pub fn mem_to_reg(
        &mut self,
        reg_dest: u32,
        addr_source: usize,
        _sz_source: usize,
    ) -> Result<()> {
        // Untaint destination register first
        self.untaint_registers(reg_dest)?;

        // Find matching tainted memory regions
        let matches = self.find_tainted_memory_at(addr_source);

        // Process matches
        for (mem_start, offset, symbol) in matches {
            // Propagate taint to destination register
            self.taint_registers(reg_dest, symbol.clone())?;

            // Register the tainted memory access event
            let tainted_mem_access_event = TaintedMemAccessEvent::new(mem_start, offset, symbol);
            self.register_event(TaintEvent::TaintedMemAccess(tainted_mem_access_event));
        }

        Ok(())
    }

    /// Propagate taint from memory to memory (e.g., movs, rep movs)
    ///
    /// # Arguments
    /// * `addr_dest` - Destination memory address
    /// * `sz_dest` - Size of destination memory in bytes
    /// * `addr_source` - Source memory address
    /// * `_sz_source` - Size of source memory in bytes (unused, kept for API consistency)
    pub fn mem_to_mem(
        &mut self,
        addr_dest: usize,
        sz_dest: u32,
        addr_source: usize,
        _sz_source: usize,
    ) -> Result<()> {
        // Untaint destination memory first
        self.untaint_memory(addr_dest);

        // Find matching tainted memory regions
        let matches = self.find_tainted_memory_at(addr_source);

        // Process matches
        for (mem_start, offset, symbol) in matches {
            // Propagate taint to destination memory
            let new_tainted_memory = TaintedMemory {
                start: addr_dest,
                sz: sz_dest as usize,
            };

            let prop_to_mem_event = PropToMemEvent::new(new_tainted_memory, symbol.clone());
            self.register_event(TaintEvent::PropToMem(prop_to_mem_event));
            self.tainted_memory
                .insert(new_tainted_memory, symbol.clone());

            // Register the tainted memory access event
            let tainted_mem_access_event = TaintedMemAccessEvent::new(mem_start, offset, symbol);
            self.register_event(TaintEvent::TaintedMemAccess(tainted_mem_access_event));
        }

        Ok(())
    }

    /// Handle immediate value to register (e.g., mov reg_dest, 0x1234)
    /// Immediate values are never tainted, so this untaints the destination register
    ///
    /// # Arguments
    /// * `reg_dest` - Destination register enum value
    /// * `_immediate_source` - Immediate value (unused, kept for API consistency)
    pub fn immediate_to_reg(&mut self, reg_dest: u32, _immediate_source: usize) -> Result<()> {
        self.untaint_registers(reg_dest)
    }

    /// Handle immediate value to memory (e.g., mov [addr_dest], 0x1234)
    /// Immediate values are never tainted, so this untaints the destination memory
    ///
    /// # Arguments
    /// * `addr_dest` - Destination memory address
    /// * `_sz_dest` - Size of destination memory in bytes (unused, kept for API consistency)
    /// * `_immediate_source` - Immediate value (unused, kept for API consistency)
    pub fn immediate_to_mem(
        &mut self,
        addr_dest: usize,
        _sz_dest: usize,
        _immediate_source: usize,
    ) {
        self.untaint_memory(addr_dest);
    }

    /// Check if regex code is enabled in the policy
    pub fn is_regex_enabled(&self) -> bool {
        self.policy.taint_sources.regex_code.is_some()
    }

    /// Check if an instruction matches the regex pattern sequence
    ///
    /// # Algorithm:
    /// 1. Early exit if regex already matched or no patterns configured
    /// 2. Process existing metadata for current thread
    /// 3. Try matching against appropriate pattern based on offset
    /// 4. Capture groups and store with proper indexing for backreferences
    /// 5. Advance offset on match
    /// 6. Perform actions when all patterns match
    /// 7. Handle constraint modes (consecutive/intermittent)
    /// 8. Try matching first pattern for new sequences
    ///
    /// # Arguments
    /// * `context` - Opaque pointer to execution context (for reading register values)
    /// * `instr_line` - The instruction string to check (e.g., "xor eax, eax")
    ///
    /// # Returns
    /// * `Ok(())` - Successfully processed (match or no match)
    /// * `Err(_)` - Error during regex matching or action execution
    pub fn check_instr_regex(
        &mut self,
        context: *const core::ffi::c_void,
        instr_line: &str,
    ) -> Result<()> {
        // Early exit if regex already matched once (optimization)
        if self.regex_success_once {
            return Ok(());
        }

        // Early exit if no regex patterns configured (optimization)
        if self.compiled_regexes.is_empty() {
            return Ok(());
        }

        let regex_code = match &self.policy.taint_sources.regex_code {
            Some(code) => code,
            None => return Ok(()),
        };

        let current_tid = unsafe { dbi_get_tid() };

        // Get constraint mode and last_x option
        let constraint = regex_code
            .actions
            .options
            .as_ref()
            .and_then(|opts| opts.constraint.as_ref());
        let last_x = regex_code
            .actions
            .options
            .as_ref()
            .and_then(|opts| opts.last_x);

        // Process existing metadata for this thread
        if let Some(metadata_list) = self.regex_metadata.get_mut(&current_tid) {
            let mut i = 0;
            while i < metadata_list.len() {
                let metadata = &mut metadata_list[i];

                // Safety check: ensure offset is within bounds
                if metadata.offset >= self.compiled_regexes.len() {
                    i += 1;
                    continue;
                }

                // Get the base pattern (already compiled!)
                let base_pattern = &regex_code.code[metadata.offset];

                let map_size = metadata.matches.len();

                let captures = if metadata.matches.is_empty() {
                    // No backreferences to substitute - use pre-compiled regex directly
                    if let Some(ref pre_compiled) = self.compiled_regexes[metadata.offset] {
                        pre_compiled.captures(instr_line)
                    } else {
                        let temp_regex = Regex::new(base_pattern)
                            .map_err(|e| anyhow::anyhow!("Regex compilation failed: {}", e))?;
                        temp_regex.captures(instr_line)
                    }
                } else {
                    // Need to apply backreferences
                    let mut pattern = base_pattern.clone();
                    for (key, value) in &metadata.matches {
                        pattern = replace_all_in_string(&pattern, key, value);
                    }

                    // Check if substitution actually changed anything
                    if pattern == *base_pattern {
                        if let Some(ref pre_compiled) = self.compiled_regexes[metadata.offset] {
                            pre_compiled.captures(instr_line)
                        } else {
                            let temp_regex = Regex::new(&pattern)
                                .map_err(|e| anyhow::anyhow!("Regex compilation failed: {}", e))?;
                            temp_regex.captures(instr_line)
                        }
                    } else {
                        // Pattern changed - need to compile with backreferences applied
                        let temp_regex = Regex::new(&pattern)
                            .map_err(|e| anyhow::anyhow!("Regex compilation failed: {}", e))?;
                        temp_regex.captures(instr_line)
                    }
                };

                let captures = match captures {
                    Some(caps) => caps,
                    None => {
                        // No match - handle based on constraint mode
                        if matches!(
                            constraint,
                            Some(crate::policy_structures::Constraint::Consecutive)
                        ) {
                            metadata_list.remove(i);
                            // Don't increment i since we removed an element
                        } else {
                            i += 1;
                        }
                        continue;
                    }
                };

                // Store captured groups with proper indexing
                // Skip index 0 (full match), start from captured groups
                for group_idx in 1..captures.len() {
                    let key = alloc::format!("\\{}", group_idx + map_size);
                    let value = captures
                        .get(group_idx)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default();
                    metadata.matches.insert(key, value);
                }

                // Advance to next pattern
                metadata.offset += 1;

                // Check if we've matched all patterns
                if metadata.offset == self.compiled_regexes.len() {
                    // All patterns matched! Perform actions
                    let matches = metadata.matches.clone();
                    if !self.perform_regex_actions(context, &matches)? {
                        info!("Regex code satisfied, but failed performing actions!");
                    }
                    self.regex_success_once = true;
                    return Ok(());
                }

                // Check if we've exceeded last_x constraint
                if let Some(last_x_val) = last_x {
                    if metadata.offset > last_x_val as usize {
                        metadata_list.remove(i);
                        continue;
                    }
                }

                i += 1;
            }
        }

        // Try to match the first pattern for a new sequence
        let captures = if let Some(ref first_regex) = self.compiled_regexes[0] {
            // Use pre-compiled regex if available
            match first_regex.captures(instr_line) {
                Some(caps) => caps,
                None => return Ok(()), // No match, nothing to do
            }
        } else {
            // First pattern wasn't pre-compiled, compile it now
            let regex_code = self.policy.taint_sources.regex_code.as_ref().unwrap();
            let temp_regex = Regex::new(&regex_code.code[0])
                .map_err(|e| anyhow::anyhow!("Regex compilation failed: {}", e))?;
            match temp_regex.captures(instr_line) {
                Some(caps) => caps,
                None => return Ok(()), // No match, nothing to do
            }
        };

        // Store captured groups
        let mut matches = BTreeMap::new();
        for group_idx in 1..captures.len() {
            let key = alloc::format!("\\{}", group_idx);
            let value = captures
                .get(group_idx)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            matches.insert(key, value);
        }

        // If this is the only pattern, perform actions immediately
        if self.compiled_regexes.len() == 1 {
            if !self.perform_regex_actions(context, &matches)? {
                info!("Regex code satisfied, but failed performing actions!");
            }
            self.regex_success_once = true;
            return Ok(());
        }

        // Otherwise, start tracking this new sequence
        let new_metadata = RegexMetadata { offset: 1, matches };

        self.regex_metadata
            .entry(current_tid)
            .or_insert_with(Vec::new)
            .push(new_metadata);

        Ok(())
    }

    /// Perform actions defined in regex policy when all patterns match
    ///
    /// # Arguments
    /// * `context` - Opaque pointer to execution context (for reading register values)
    /// * `matches` - Map of backreferences to their captured values (e.g., "\\1" -> "eax")
    ///
    /// # Returns
    /// * `Ok(true)` - Actions performed successfully
    /// * `Ok(false)` - Failed to perform actions
    /// * `Err(_)` - Error during action execution
    fn perform_regex_actions(
        &mut self,
        context: *const core::ffi::c_void,
        matches: &BTreeMap<String, String>,
    ) -> Result<bool> {
        // Clone the actions to avoid borrowing issues
        // (We need mutable access to self in execute_predicate_action)
        let (predicates, message) = match &self.policy.taint_sources.regex_code {
            Some(code) => (
                code.actions.predicates.clone(),
                code.actions.message.clone(),
            ),
            None => return Ok(false),
        };

        // Log the message if present
        if let Some(ref msg) = message {
            info!("Regex matched: {}", msg);
        }

        // Process each predicate action
        for predicate_call in &predicates {
            for (predicate, params) in predicate_call {
                let mut resolved_params = Vec::with_capacity(params.len());
                for p in params {
                    // Check if this param needs any replacements
                    let needs_replacement = matches.keys().any(|key| p.contains(key.as_str()));

                    let resolved = if needs_replacement {
                        let mut resolved = p.clone();
                        for (key, value) in matches {
                            resolved = replace_all_in_string(&resolved, key, value);
                        }
                        resolved
                    } else {
                        p.clone()
                    };
                    resolved_params.push(resolved);
                }

                // Execute the predicate action
                self.execute_predicate_action(context, predicate, &resolved_params)?;
            }
        }

        Ok(true)
    }

    /// Execute a predicate action with the given parameters
    ///
    /// Supported predicates:
    /// - `Tainted(symbol)`: Create a tainted event
    /// - `PropToMem(address, size, symbol)`: Propagate taint to memory
    /// - `PropToReg(register, symbol)`: Propagate taint to register
    ///
    /// # Arguments
    /// * `context` - Opaque pointer to execution context (for reading register values)
    /// * `predicate` - The predicate type to execute
    /// * `params` - The resolved parameters (backreferences already replaced)
    ///
    /// # Returns
    /// * `Ok(())` - Action executed successfully
    /// * `Err(_)` - Error during action execution
    fn execute_predicate_action(
        &mut self,
        context: *const core::ffi::c_void,
        predicate: &crate::policy_structures::Predicate,
        params: &[String],
    ) -> Result<()> {
        use crate::policy_structures::Predicate;

        match predicate {
            Predicate::Tainted => {
                // Create a tainted event with the given symbol
                if params.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Tainted predicate requires a symbol parameter"
                    ));
                }
                let symbol = &params[0];
                let tainted_event = TaintEvent::Tainted(TaintedEvent::new(symbol.clone()));
                self.register_event(tainted_event);
                Ok(())
            }
            Predicate::PropToMem => {
                // PropToMem requires: [address, size, symbol]
                // Address can be either a hex value or a register name (e.g., "rax", "\\1" = "rax")
                if params.len() < 3 {
                    return Err(anyhow::anyhow!(
                        "PropToMem requires 3 parameters: address, size, symbol"
                    ));
                }

                // Parse address: try as number first, then as register name
                let addr = if let Ok(num_addr) = params[0].parse::<usize>() {
                    num_addr
                } else {
                    // Try to interpret as register name and read from context
                    let reg_u32 =
                        unsafe { dbi_string_to_reg(CString::new(params[0].as_str())?.as_ptr()) };
                    if reg_u32 == 0 {
                        return Err(anyhow::anyhow!(
                            "Invalid address (not a number or register): {}",
                            params[0]
                        ));
                    }
                    unsafe { crate::utils::dbi_get_context_regval(context, reg_u32) }
                };

                let size = parse_number(&params[1])
                    .ok_or_else(|| anyhow::anyhow!("Invalid size: {}", params[1]))?;
                let symbol = &params[2];

                let tainted_memory = TaintedMemory {
                    start: addr,
                    sz: size,
                };
                let prop_to_mem_event = PropToMemEvent::new(tainted_memory, symbol.clone());
                self.register_event(TaintEvent::PropToMem(prop_to_mem_event));
                self.tainted_memory.insert(tainted_memory, symbol.clone());
                Ok(())
            }
            Predicate::PropToReg => {
                // PropToReg requires: [register, symbol]
                if params.len() < 2 {
                    return Err(anyhow::anyhow!(
                        "PropToReg requires 2 parameters: register, symbol"
                    ));
                }
                let reg_name = &params[0];
                let symbol = &params[1];

                let reg_u32 =
                    unsafe { dbi_string_to_reg(CString::new(reg_name.as_str())?.as_ptr()) };
                self.taint_registers(reg_u32, symbol.clone())?;
                Ok(())
            }
            _ => {
                warn!("Unsupported predicate in regex actions: {:?}", predicate);
                Ok(())
            }
        }
    }
}

/// Replace all occurrences of `from` with `to` in the given string
/// # Arguments
/// * `input` - The input string
/// * `from` - The substring to find
/// * `to` - The replacement substring
///
/// # Returns
/// A new string with all occurrences replaced
#[inline(always)]
fn replace_all_in_string(input: &str, from: &str, to: &str) -> String {
    if from.is_empty() {
        return input.to_string();
    }

    // Count occurrences first
    let occurrences = input.matches(from).count();
    if occurrences == 0 {
        return input.to_string();
    }

    let capacity = input.len() + occurrences * (to.len().saturating_sub(from.len()));
    let mut result = String::with_capacity(capacity);

    let mut last_end = 0;
    for (start, _) in input.match_indices(from) {
        result.push_str(&input[last_end..start]);
        result.push_str(to);
        last_end = start + from.len();
    }
    result.push_str(&input[last_end..]);

    result
}
