use crate::policy_structures::Predicate;
use crate::taint_events::{ApiParamCondition, ParamConditionType, TaintEvent};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use anyhow::{Context, Result, anyhow, bail};
use log::{info, warn};
use serde_json::Value as JsonValue;

// ============================================================================
// Enums for AST Operations
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintBinaryOperator {
    Or,
    And,
    AndThen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintUnaryOperator {
    Not,
    Next,
}

// ============================================================================
// AST Node Types
// ============================================================================

#[derive(Debug, Clone)]
pub enum ASTNode {
    Event(EventNode),
    EventConditional(EventNodeConditional),
    UnaryOp(UnaryOpNode),
    BinaryOp(BinaryOpNode),
}

#[derive(Debug, Clone)]
pub struct EventNode {
    pub predicate: Predicate,
    pub variables: Vec<String>,
}

impl EventNode {
    pub fn new(predicate: Predicate, variables: Vec<String>) -> Self {
        Self {
            predicate,
            variables,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventNodeConditional {
    pub predicate: Predicate,
    pub variables: Vec<String>,
    pub conditions: Vec<ApiParamCondition>,
}

impl EventNodeConditional {
    pub fn new(
        predicate: Predicate,
        variables: Vec<String>,
        conditions: Vec<ApiParamCondition>,
    ) -> Self {
        Self {
            predicate,
            variables,
            conditions,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnaryOpNode {
    pub op: TaintUnaryOperator,
    pub child: Box<ASTNode>,
}

impl UnaryOpNode {
    pub fn new(op: TaintUnaryOperator, child: ASTNode) -> Self {
        Self {
            op,
            child: Box::new(child),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BinaryOpNode {
    pub op: TaintBinaryOperator,
    pub left: Box<ASTNode>,
    pub right: Box<ASTNode>,
}

impl BinaryOpNode {
    pub fn new(op: TaintBinaryOperator, left: ASTNode, right: ASTNode) -> Self {
        Self {
            op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
}

// ============================================================================
// Main Checker Structure
// ============================================================================

pub struct Checker {
    behavioral_pattern: Option<ASTNode>,
    capability: (String, Vec<String>),
    constants: BTreeMap<String, String>,
    explanation: String,
    assignments: BTreeMap<String, String>,
    // Track full key-value pairs before a backtrack point for rollback
    assignment_snapshots: Vec<BTreeMap<String, String>>,
}

impl Checker {
    pub fn new() -> Self {
        Self {
            behavioral_pattern: None,
            capability: (String::new(), Vec::new()),
            constants: BTreeMap::new(),
            explanation: String::new(),
            assignments: BTreeMap::new(),
            assignment_snapshots: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.assignments.clear();
        self.assignment_snapshots.clear();
    }
    
    /// Create a snapshot of current assignment key-value pairs for potential rollback
    #[inline]
    fn snapshot_assignments(&mut self) {
        self.assignment_snapshots.push(self.assignments.clone());
    }
    
    /// Restore assignments to the last snapshot
    #[inline]
    fn restore_snapshot(&mut self) {
        if let Some(snapshot) = self.assignment_snapshots.pop() {
            self.assignments = snapshot;
        }
    }
    
    /// Discard the last snapshot without restoring
    #[inline]
    fn discard_snapshot(&mut self) {
        self.assignment_snapshots.pop();
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    #[inline]
    fn is_valid_rule_object(&self, rule_object: &JsonValue) -> Result<()> {
        if rule_object.get("pattern").is_none() {
            bail!("Missing pattern field in the rule json!");
        }
        if rule_object.get("capability").is_none() {
            bail!("Missing capability field in the rule json!");
        }
        Ok(())
    }

    #[inline]
    fn is_valid_api_condition(&self, condition_object: &JsonValue) -> Result<()> {
        let index = condition_object
            .get("index")
            .ok_or_else(|| anyhow!("Missing index key from the ApiParamCondition object!"))?;
        if !index.is_i64() {
            bail!("ApiParamCondition[\"index\"] is not an integer!");
        }

        let type_field = condition_object
            .get("type")
            .ok_or_else(|| anyhow!("Missing type key from the ApiParamCondition object!"))?;
        if !type_field.is_string() {
            bail!("ApiParamCondition[\"type\"] is not a string!");
        }

        let value = condition_object
            .get("value")
            .ok_or_else(|| anyhow!("Missing value key from the ApiParamCondition object!"))?;
        if !value.is_string() {
            bail!("ApiParamCondition[\"value\"] is not a string!");
        }

        let type_str = type_field.as_str().unwrap();
        if str_to_param_condition_type(type_str) == ParamConditionType::Unknown {
            bail!("Invalid ApiParamCondition[\"type\"]: {}", type_str);
        }

        Ok(())
    }

    #[inline]
    fn is_valid_capability(&self, capability_object: &JsonValue) -> Result<()> {
        let obj = capability_object
            .as_object()
            .ok_or_else(|| anyhow!("Capability is not an object!"))?;

        let (_, value) = obj
            .iter()
            .next()
            .ok_or_else(|| anyhow!("Capability object is empty!"))?;

        let arr = value
            .as_array()
            .ok_or_else(|| anyhow!("Value associated with capability is not a list!"))?;

        if !arr.iter().all(|v| v.is_string()) {
            bail!("List of capability variables contains non-string elements!");
        }

        Ok(())
    }

    // ========================================================================
    // Pattern Collection Methods
    // ========================================================================

    fn expand_binary_sugar(
        &self,
        rule_array: &JsonValue,
        op_type: TaintBinaryOperator,
    ) -> Result<ASTNode> {
        let arr = rule_array
            .as_array()
            .ok_or_else(|| anyhow!("Rule is not an array!"))?;

        if arr.len() < 2 {
            bail!("Insufficient parameters for binary operator!");
        }

        // Build right-associative tree for operators with 3+ operands to match C++ behavior
        // E.g., [A, B, C] => A op (B op C)
        if arr.len() == 2 {
            let left = self.collect_pattern(&arr[0])?;
            let right = self.collect_pattern(&arr[1])?;
            return Ok(ASTNode::BinaryOp(BinaryOpNode::new(op_type, left, right)));
        }

        // For length >= 3, build right-associative tree
        // Create a chain: A op (B op (C op ...))
        let mut current = self.collect_pattern(&arr[arr.len() - 1])?;
        
        for i in (0..arr.len() - 1).rev() {
            let left = self.collect_pattern(&arr[i])?;
            current = ASTNode::BinaryOp(BinaryOpNode::new(op_type, left, current));
        }

        Ok(current)
    }

    fn collect_api_conditions(
        &self,
        condition_array: &JsonValue,
    ) -> Result<Vec<ApiParamCondition>> {
        let arr = condition_array
            .as_array()
            .ok_or_else(|| anyhow!("Conditions is not an array!"))?;

        let mut conditions = Vec::new();
        for condition in arr {
            self.is_valid_api_condition(condition)?;

            let index = condition["index"].as_i64().unwrap() as i32;
            let type_str = condition["type"].as_str().unwrap();
            let value = condition["value"].as_str().unwrap();

            conditions.push(ApiParamCondition {
                index,
                param_type: str_to_param_condition_type(type_str),
                value: value.to_string(),
            });
        }

        Ok(conditions)
    }

    fn collect_capability(&mut self, capability_object: &JsonValue) -> Result<()> {
        self.is_valid_capability(capability_object)?;

        let obj = capability_object.as_object().unwrap();
        let (key, value) = obj.iter().next().unwrap();

        let variables = value
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();

        self.capability = (key.to_string(), variables);
        Ok(())
    }

    fn collect_pattern(&self, pattern_object: &JsonValue) -> Result<ASTNode> {
        let obj = pattern_object
            .as_object()
            .ok_or_else(|| anyhow!("Pattern is not an object!"))?;

        let (key, value) = obj
            .iter()
            .next()
            .ok_or_else(|| anyhow!("Pattern object is empty!"))?;

        // Check for binary operators
        if let Some(op) = get_binary_operator(key) {
            return self.expand_binary_sugar(value, op);
        }

        // Check for unary operators
        if let Some(op) = get_unary_operator(key) {
            let child = self.collect_pattern(value)?;
            return Ok(ASTNode::UnaryOp(UnaryOpNode::new(op, child)));
        }

        // Check for predicates
        let predicate = str_to_predicate(key);
        match predicate {
            Predicate::Tainted
            | Predicate::TaintedAPI
            | Predicate::PropToAPI
            | Predicate::PropToMem
            | Predicate::TaintedCodeExecute
            | Predicate::TaintedMemAccess => {
                let variables = if let Some(arr) = value.as_array() {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                } else {
                    value.as_str()
                        .map(|s| vec![s.to_string()])
                        .unwrap_or_default()
                };

                Ok(ASTNode::Event(EventNode::new(predicate, variables)))
            }
            Predicate::TaintedAPICond | Predicate::PropToAPICond => {
                let arr = value
                    .as_array()
                    .ok_or_else(|| anyhow!("Conditional predicate value is not an array!"))?;

                if arr.is_empty() {
                    bail!("Conditional predicate has no arguments!");
                }

                // N-1 variables, last element is conditions array
                let variables: Vec<String> = arr[..arr.len() - 1]
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();

                let conditions = self.collect_api_conditions(&arr[arr.len() - 1])?;

                Ok(ASTNode::EventConditional(EventNodeConditional::new(
                    predicate, variables, conditions,
                )))
            }
            _ => {
                warn!("Unknown predicate: {}", key);
                bail!("Unknown predicate: {}", key)
            }
        }
    }

    fn collect_metadata(&mut self, metadata_object: &JsonValue) -> Result<()> {
        if let Some(constants_obj) = metadata_object.get("constants") {
            let obj = constants_obj
                .as_object()
                .ok_or_else(|| anyhow!("Constants is not an object!"))?;

            self.constants.extend(
                obj.iter().filter_map(|(key, value)| {
                    value.as_str().map(|s| (key.to_string(), s.to_string()))
                })
            );
        }

        if let Some(explanation) = metadata_object.get("explanation").and_then(|e| e.as_str()) {
            self.explanation = explanation.to_string();
        }

        Ok(())
    }

    // ========================================================================
    // Main Loading Method
    // ========================================================================

    pub fn load_rule_from_str(&mut self, rule_json_str: &str) -> Result<()> {
        info!("Loading rule from JSON string");

        let json_rule: JsonValue = serde_json::from_str(rule_json_str)
            .with_context(|| "Could not parse the rule JSON!".to_string())?;

        self.is_valid_rule_object(&json_rule)?;

        self.behavioral_pattern = Some(self.collect_pattern(&json_rule["pattern"])?);

        self.collect_capability(&json_rule["capability"])?;

        if let Some(metadata) = json_rule.get("metadata") {
            self.collect_metadata(metadata)?;
        }

        info!("Rule successfully loaded!");
        Ok(())
    }

    // ========================================================================
    // Formula Checking Methods
    // ========================================================================

    pub fn check_formula(&mut self, taint_trace: &[TaintEvent]) -> Result<bool> {
        // info!("Trace size: {}", taint_trace.len());

        let pattern = self
            .behavioral_pattern
            .as_ref()
            .ok_or_else(|| anyhow!("No behavioral pattern loaded!"))?
            .clone();

        for i in 0..taint_trace.len() {
            // Initialize assignments with constants
            self.assignments.clear();
            for (key, value) in &self.constants {
                self.assignments.insert(key.clone(), value.clone());
            }

            if let Some(_index) = self.check_formula_rec(&pattern, i, taint_trace)? {
                self.log_success();
                return Ok(true);
            }
        }

        // info!("No rule has been satisfied!");
        self.reset();
        Ok(false)
    }

    #[inline]
    fn check_unary_pattern(
        &mut self,
        node: &UnaryOpNode,
        index: usize,
        taint_trace: &[TaintEvent],
    ) -> Result<Option<usize>> {
        match node.op {
            TaintUnaryOperator::Not => {
                let result = self.check_formula_rec(&node.child, index, taint_trace)?;
                Ok(if result.is_none() { Some(index) } else { None })
            }
            TaintUnaryOperator::Next => {
                if index + 1 >= taint_trace.len() {
                    return Ok(None);
                }
                self.check_formula_rec(&node.child, index + 1, taint_trace)
            }
        }
    }

    #[inline]
    fn check_binary_pattern(
        &mut self,
        node: &BinaryOpNode,
        index: usize,
        taint_trace: &[TaintEvent],
    ) -> Result<Option<usize>> {
        match node.op {
            TaintBinaryOperator::Or => {
                self.snapshot_assignments();
                
                // Try left side
                let left_result = self.check_formula_rec(&node.left, index, taint_trace)?;
                let left_assignments = if left_result.is_some() {
                    Some(self.assignments.clone())
                } else {
                    None
                };
                self.restore_snapshot();
                
                // Try right side
                self.snapshot_assignments();
                let right_result = self.check_formula_rec(&node.right, index, taint_trace)?;
                
                // Return the result with the smallest index, or None if both failed
                match (left_result, right_result) {
                    (Some(left_idx), Some(right_idx)) => {
                        if left_idx <= right_idx {
                            // Left has smaller or equal index, use left's assignments
                            self.restore_snapshot();
                            self.assignments = left_assignments.unwrap();
                            Ok(Some(left_idx))
                        } else {
                            // Right has smaller index, keep right's assignments
                            self.discard_snapshot();
                            Ok(Some(right_idx))
                        }
                    }
                    (Some(left_idx), None) => {
                        // Left succeeded, restore to left's state
                        self.restore_snapshot();
                        self.assignments = left_assignments.unwrap();
                        Ok(Some(left_idx))
                    }
                    (None, Some(right_idx)) => {
                        // Right succeeded, keep its assignments
                        self.discard_snapshot();
                        Ok(Some(right_idx))
                    }
                    (None, None) => {
                        // Both failed
                        self.restore_snapshot();
                        Ok(None)
                    }
                }
            }
            TaintBinaryOperator::And => {
                self.snapshot_assignments();

                if self.check_formula_rec(&node.left, index, taint_trace)?.is_none() {
                    self.restore_snapshot();
                    return Ok(None);
                }

                let right_result = self.check_formula_rec(&node.right, index, taint_trace)?;
                if right_result.is_none() {
                    self.restore_snapshot();
                } else {
                    self.discard_snapshot();
                }

                Ok(right_result)
            }
            TaintBinaryOperator::AndThen => {
                self.snapshot_assignments();

                let Some(mut current_index) = 
                    self.check_formula_rec(&node.left, index, taint_trace)? 
                else {
                    self.restore_snapshot();
                    return Ok(None);
                };

                if current_index + 1 >= taint_trace.len() {
                    self.restore_snapshot();
                    return Ok(None);
                }

                // Snapshot after left succeeds, before checking right
                self.snapshot_assignments();
                current_index += 1;

                while current_index < taint_trace.len() {
                    if let Some(result_index) = 
                        self.check_formula_rec(&node.right, current_index, taint_trace)? 
                    {
                        // Success: discard the 2 snapshots we added (original and after-left)
                        // Nested operators in the right side should have cleaned up their own snapshots
                        self.discard_snapshot(); // Discard snapshot after left
                        self.discard_snapshot(); // Discard original snapshot
                        return Ok(Some(result_index));
                    }

                    // Restore to state after left succeeded (before right check)
                    // Nested operators should have cleaned up their own snapshots
                    self.restore_snapshot();
                    // Take new snapshot for next iteration
                    self.snapshot_assignments();
                    current_index += 1;
                }

                // Loop exhausted: restore to original state before AndThen
                // First discard the last snapshot from the loop, then restore to original
                self.discard_snapshot();
                self.restore_snapshot();
                Ok(None)
            }
        }
    }

    #[inline]
    fn check_formula_rec(
        &mut self,
        node: &ASTNode,
        index: usize,
        taint_trace: &[TaintEvent],
    ) -> Result<Option<usize>> {
        if index >= taint_trace.len() {
            return Ok(None);
        }

        match node {
            ASTNode::UnaryOp(unary_node) => {
                self.check_unary_pattern(unary_node, index, taint_trace)
            }
            ASTNode::BinaryOp(binary_node) => {
                self.check_binary_pattern(binary_node, index, taint_trace)
            }
            ASTNode::Event(_) | ASTNode::EventConditional(_) => {
                if self.is_valid_atom(index, node, taint_trace)? {
                    return Ok(Some(index));
                }
                Ok(None)
            }
        }
    }

    // ========================================================================
    // Atom Validation Methods
    // ========================================================================

    #[inline]
    fn check_conditions(&self, trace_event: &TaintEvent, node: &EventNodeConditional) -> bool {
        let additional_info = trace_event.get_additional_info();
        let conditions = &node.conditions;

        if additional_info.len() != conditions.len() {
            return false;
        }

        conditions.iter().zip(additional_info.iter()).all(|(condition, info)| {
            condition.value == *info || 
            self.assignments.get(&condition.value).map_or(false, |v| v == info)
        })
    }

    #[inline(always)]
    fn is_cond_case(trace_predicate: &Predicate, node_predicate: &Predicate) -> bool {
        matches!(
            (node_predicate, trace_predicate),
            (Predicate::TaintedAPICond, Predicate::TaintedAPI)
                | (Predicate::PropToAPICond, Predicate::PropToAPI)
        )
    }

    #[inline]
    fn is_valid_atom(
        &mut self,
        index: usize,
        node: &ASTNode,
        taint_trace: &[TaintEvent],
    ) -> Result<bool> {
        // Get reference to avoid cloning the entire event
        let trace_event = &taint_trace[index];
        let trace_predicate = trace_event.get_predicate();

        let (node_predicate, variables) = match node {
            ASTNode::Event(event_node) => {
                if trace_predicate != event_node.predicate {
                    return Ok(false);
                }
                (event_node.predicate, &event_node.variables)
            }
            ASTNode::EventConditional(event_node) => {
                if trace_predicate != event_node.predicate
                    && !Self::is_cond_case(&trace_predicate, &event_node.predicate)
                {
                    return Ok(false);
                }
                (event_node.predicate, &event_node.variables)
            }
            _ => return Ok(false),
        };

        // Match specific predicates
        match trace_predicate {
            Predicate::Tainted => {
                if let TaintEvent::Tainted(evt) = trace_event {
                    return Ok(self.check_assignment(&variables[0], evt.get_symbol()));
                }
            }
            Predicate::TaintedAPI => {
                if let TaintEvent::TaintedAPI(evt) = trace_event {
                    if !self.check_assignment(&variables[0], evt.get_api()) {
                        return Ok(false);
                    }

                    if node_predicate == Predicate::TaintedAPICond {
                        if let ASTNode::EventConditional(cond_node) = node {
                            return Ok(self.check_conditions(trace_event, cond_node));
                        }
                    }

                    return Ok(true);
                }
            }
            Predicate::PropToAPI => {
                if let TaintEvent::PropToAPI(evt) = trace_event {
                    if !self.check_assignment(&variables[0], evt.get_api()) {
                        return Ok(false);
                    }
                    if !self.check_assignment(&variables[1], evt.get_symbol()) {
                        return Ok(false);
                    }

                    if node_predicate == Predicate::PropToAPICond {
                        if let ASTNode::EventConditional(cond_node) = node {
                            return Ok(self.check_conditions(trace_event, cond_node));
                        }
                    }

                    return Ok(true);
                }
            }
            Predicate::PropToMem => {
                if let TaintEvent::PropToMem(evt) = trace_event {
                    let tainted_memory = evt.get_tainted_memory();
                    let start_hex = format!("{:#x}", tainted_memory.start);
                    let sz_hex = format!("{:#x}", tainted_memory.sz);

                    if !self.check_assignment(&variables[0], &start_hex) {
                        return Ok(false);
                    }
                    if !self.check_assignment(&variables[1], &sz_hex) {
                        return Ok(false);
                    }
                    if !self.check_assignment(&variables[2], evt.get_symbol()) {
                        return Ok(false);
                    }

                    return Ok(true);
                }
            }
            Predicate::TaintedCodeExecute => {
                if let TaintEvent::TaintedCodeExecute(evt) = trace_event {
                    let addr_hex = format!("{:#x}", evt.get_memory_address());

                    if !self.check_assignment(&variables[0], &addr_hex) {
                        return Ok(false);
                    }
                    if !self.check_assignment(&variables[1], evt.get_symbol()) {
                        return Ok(false);
                    }

                    return Ok(true);
                }
            }
            Predicate::TaintedMemAccess => {
                if let TaintEvent::TaintedMemAccess(evt) = trace_event {
                    let addr_hex = format!("{:#x}", evt.get_memory_address());
                    let offset_hex = format!("{:#x}", evt.get_offset());

                    if !self.check_assignment(&variables[0], &addr_hex) {
                        return Ok(false);
                    }
                    if !self.check_assignment(&variables[1], &offset_hex) {
                        return Ok(false);
                    }
                    if !self.check_assignment(&variables[2], evt.get_symbol()) {
                        return Ok(false);
                    }

                    return Ok(true);
                }
            }
            _ => {
                warn!("Unsupported predicate for checking!");
                return Ok(false);
            }
        }

        Ok(false)
    }

    /// Check if a variable can be assigned a value (or if it's already assigned, check if values match)
    #[inline(always)]
    fn check_assignment(&mut self, variable: &str, value: &str) -> bool {
        match self.assignments.get(variable) {
            Some(existing_value) => existing_value == value,
            None => {
                self.assignments.insert(variable.to_string(), value.to_string());
                true
            }
        }
    }

    // ========================================================================
    // Logging Methods
    // ========================================================================

    fn log_success(&self) {
        info!(
            "The program has the following capability: {}",
            self.capability.0
        );

        if !self.capability.1.is_empty() {
            let params = self.capability.1.join(", ");
            info!("Capability parameters: ({})", params);
        }

        if !self.explanation.is_empty() {
            info!("Description: {}", self.explanation);
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

#[inline]
fn str_to_predicate(s: &str) -> Predicate {
    match s {
        "Tainted" => Predicate::Tainted,
        "Untainted" => Predicate::Untainted,
        "TaintedAPI" => Predicate::TaintedAPI,
        "PropToAPI" => Predicate::PropToAPI,
        "PropToReg" => Predicate::PropToReg,
        "PropToMem" => Predicate::PropToMem,
        "TaintedMemAccess" => Predicate::TaintedMemAccess,
        "UntaintedReg" => Predicate::UntaintedReg,
        "TaintedAPICond" => Predicate::TaintedAPICond,
        "PropToAPICond" => Predicate::PropToAPICond,
        "TaintedCodeExecute" => Predicate::TaintedCodeExecute,
        _ => Predicate::Unknown,
    }
}

#[inline]
fn str_to_param_condition_type(s: &str) -> ParamConditionType {
    match s {
        "int" => ParamConditionType::Int,
        "size_t" => ParamConditionType::SizeT,
        "ptr" => ParamConditionType::Ptr,
        "str" => ParamConditionType::Str,
        _ => ParamConditionType::Unknown,
    }
}

#[inline]
fn get_binary_operator(s: &str) -> Option<TaintBinaryOperator> {
    match s {
        "or" | "OR" => Some(TaintBinaryOperator::Or),
        "and" | "AND" => Some(TaintBinaryOperator::And),
        "andthen" | "andThen" => Some(TaintBinaryOperator::AndThen),
        _ => None,
    }
}

#[inline]
fn get_unary_operator(s: &str) -> Option<TaintUnaryOperator> {
    match s {
        "not" | "Not" | "NOT" => Some(TaintUnaryOperator::Not),
        "next" | "Next" | "NEXT" => Some(TaintUnaryOperator::Next),
        _ => None,
    }
}
