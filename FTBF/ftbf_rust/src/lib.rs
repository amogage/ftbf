#![cfg_attr(not(any(test, doctest)), no_std)]
// #![no_builtins]

#[macro_use]
extern crate alloc;
use core::panic::PanicInfo;
use log::error;
use print_no_std::println;

mod allocator;
mod analyzer;
pub mod checker;
mod ffi;
mod logger;
mod policy_structures;
mod registers;
mod taint_events;
mod utils;


#[cfg_attr(not(test), panic_handler)]
fn panic(panic: &PanicInfo<'_>) -> ! {
    println!("Panic: {panic:?}");
    error!("{panic:?}");
    loop {}
}
