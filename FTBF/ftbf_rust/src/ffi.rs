#[cfg(not(test))]
use crate::allocator;
use crate::analyzer::Analyzer;
use crate::utils::c_to_rust_string;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_char;
use core::ptr::null_mut;
use log::{error, info};
use print_no_std::println;

/// Macro to handle analyzer method calls with error logging
macro_rules! call_analyzer_method {
    ($analyzer:expr, $method:ident($($arg:expr),*)) => {
        if let Err(e) = $analyzer.$method($($arg),*) {
            error!("Error in {}: {}", stringify!($method), e);
        }
    };
}

/**
* Workaround because libcore is compiled with unwinding enabled and that ends up making unreachable
* MSVC: https://github.com/rust-lang/rust/issues/101134
* GNU: https://github.com/rust-lang/rust/issues/47493
* It shouldn't even be possible to reach this function, thanks to panic=abort,
* but libcore is compiled with unwinding enabled and that ends up making unreachable
* references to this.
 */

#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn __CxxFrameHandler3() -> ! {
    unreachable!("__CxxFrameHandler3 not supported");
}

#[unsafe(no_mangle)]
pub extern "C" fn on_init(
    policy_ptr: *const c_char,
    rule_ptr: *const c_char,
    apis_ptr: *const c_char,
) -> *mut Analyzer {
    // Initialize the heap allocator
    #[cfg(not(test))]
    allocator::init_heap();

    // Initialize the logger
    if let Err(e) = crate::logger::init() {
        println!("Failed to initialize logger: {:?}", e);
    }

    info!("Analyzer initializing...");

    let policy_str = match c_to_rust_string(policy_ptr) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to convert policy string: {}", e);
            return null_mut();
        }
    };

    let rule_str = match c_to_rust_string(rule_ptr) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to convert rule string: {}", e);
            return null_mut();
        }
    };

    let apis_str = match c_to_rust_string(apis_ptr) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to convert APIs string: {}", e);
            return null_mut();
        }
    };

    let instance = match Analyzer::new(&policy_str, &rule_str, &apis_str) {
        Ok(analyzer) => analyzer,
        Err(e) => {
            error!("Failed to create analyzer: {}", e);
            return null_mut();
        }
    };
    info!("Analyzer initialized successfully!");
    Box::into_raw(Box::new(instance))
}

#[unsafe(no_mangle)]
pub extern "C" fn on_exit(instance_ptr: *mut Analyzer) {
    let analyzer = unsafe { &mut *instance_ptr };
    analyzer.on_exit();
}

#[unsafe(no_mangle)]
pub extern "C" fn on_api_call(
    instance_ptr: *mut Analyzer,
    api_ptr: *const c_char,
    params_ptr: *const usize,
) {
    let analyzer = unsafe { &mut *instance_ptr };
    let api_name = match c_to_rust_string(api_ptr) {
        Ok(name) => name,
        Err(e) => {
            error!("Failed to convert API name string: {}", e);
            return;
        }
    };

    let param_count = analyzer.get_api_param_count(&api_name);
    let parameters: Vec<usize> =
        unsafe { core::slice::from_raw_parts(params_ptr, param_count as usize).to_vec() };

    analyzer.on_api_call(&api_name, parameters);
}

#[unsafe(no_mangle)]
pub extern "C" fn on_api_return(
    instance_ptr: *mut Analyzer,
    api_ptr: *const c_char,
    return_value: usize,
    stack_ptr: usize,
) {
    let analyzer = unsafe { &mut *instance_ptr };
    let api_name = match c_to_rust_string(api_ptr) {
        Ok(name) => name,
        Err(e) => {
            error!("Failed to convert API name string: {}", e);
            return;
        }
    };

    analyzer.on_api_return(api_name, return_value, stack_ptr);
}

#[unsafe(no_mangle)]
pub extern "C" fn on_call_or_jump(instance_ptr: *mut Analyzer, target_address: usize) {
    let analyzer = unsafe { &mut *instance_ptr };
    analyzer.on_call_or_jump(target_address);
}

#[unsafe(no_mangle)]
pub extern "C" fn reg_to_reg(instance_ptr: *mut Analyzer, reg_dest: u32, reg_source: u32) {
    let analyzer = unsafe { &mut *instance_ptr };
    call_analyzer_method!(analyzer, reg_to_reg(reg_dest, reg_source));
}

#[unsafe(no_mangle)]
pub extern "C" fn reg_to_mem(
    instance_ptr: *mut Analyzer,
    addr_dest: usize,
    sz_dest: u32,
    reg_source: u32,
) {
    let analyzer = unsafe { &mut *instance_ptr };
    call_analyzer_method!(analyzer, reg_to_mem(addr_dest, sz_dest, reg_source));
}

#[unsafe(no_mangle)]
pub extern "C" fn mem_to_reg(
    instance_ptr: *mut Analyzer,
    reg_dest: u32,
    addr_source: usize,
    sz_source: usize,
) {
    let analyzer = unsafe { &mut *instance_ptr };
    call_analyzer_method!(analyzer, mem_to_reg(reg_dest, addr_source, sz_source));
}

#[unsafe(no_mangle)]
pub extern "C" fn mem_to_mem(
    instance_ptr: *mut Analyzer,
    addr_dest: usize,
    sz_dest: u32,
    addr_source: usize,
    sz_source: usize,
) {
    let analyzer = unsafe { &mut *instance_ptr };
    call_analyzer_method!(
        analyzer,
        mem_to_mem(addr_dest, sz_dest, addr_source, sz_source)
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn immediate_to_reg(
    instance_ptr: *mut Analyzer,
    reg_dest: u32,
    immediate_source: usize,
) {
    let analyzer = unsafe { &mut *instance_ptr };
    call_analyzer_method!(analyzer, immediate_to_reg(reg_dest, immediate_source));
}

#[unsafe(no_mangle)]
pub extern "C" fn immediate_to_mem(
    instance_ptr: *mut Analyzer,
    addr_dest: usize,
    sz_dest: usize,
    immediate_source: usize,
) {
    let analyzer = unsafe { &mut *instance_ptr };
    analyzer.immediate_to_mem(addr_dest, sz_dest, immediate_source);
}

/// Check if regex functionality is enabled in the policy
///
/// # Safety
/// * `instance_ptr` must be a valid pointer to an Analyzer instance
#[unsafe(no_mangle)]
pub extern "C" fn is_regex_enabled(instance_ptr: *mut Analyzer) -> bool {
    let analyzer = unsafe { &mut *instance_ptr };
    analyzer.is_regex_enabled()
}

/// Check if an instruction matches the regex pattern sequence
///
/// # Note
/// This implementation uses pre-compiled regex patterns for optimal performance.
/// See `Analyzer::check_instr_regex` documentation for implementation details.
///
/// # Safety
/// * `instance_ptr` must be a valid pointer to an Analyzer instance
/// * `context` must be a valid pointer to the execution context (for reading register values)
/// * `instr_line_ptr` must be a valid null-terminated C string
#[unsafe(no_mangle)]
pub extern "C" fn check_instr_regex(
    instance_ptr: *mut Analyzer,
    context: *const core::ffi::c_void,
    instr_line_ptr: *const c_char,
) {
    let analyzer = unsafe { &mut *instance_ptr };
    let instr_line = match c_to_rust_string(instr_line_ptr) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to convert instruction line string: {}", e);
            return;
        }
    };
    
    call_analyzer_method!(analyzer, check_instr_regex(context, &instr_line));
}