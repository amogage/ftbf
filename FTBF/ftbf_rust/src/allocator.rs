//This file is used to initialize the heap allocator.
// It is required because we are in no_std.

extern crate alloc;

use core::ptr::addr_of_mut;
use linked_list_allocator::LockedHeap;

// Heap size: 100 MB
const HEAP_SIZE: usize = 100 * 1024 * 1024;

// Static heap memory
#[cfg(not(test))]
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

// Global allocator using linked list allocator (supports deallocation)
// Only use custom allocator when not testing (tests should use std allocator)
#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(test))]
pub fn init_heap() {
    unsafe {
        let heap_ptr = addr_of_mut!(HEAP).cast::<u8>();
        ALLOCATOR.lock().init(heap_ptr, HEAP_SIZE);
    }
}
