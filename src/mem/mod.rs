use core::alloc::{GlobalAlloc, Layout};

use limine::memory_map;

use crate::mem::bitmap::Bitmap;
use crate::mem::page::Page;
use crate::print;

pub mod bitmap;
pub mod bootstrap_allocator;
pub(crate) mod page;

pub struct KernelAlloc<'a> {
    heap_adr: usize,
    pub bitmap: Bitmap<'a>,
}

impl<'a> KernelAlloc<'a> {
    pub fn new(heap_adr: usize, bitmap: Bitmap<'a>) -> KernelAlloc<'a> {
        KernelAlloc { heap_adr, bitmap }
    }
}
unsafe impl<'a> GlobalAlloc for KernelAlloc<'a> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        todo!()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        todo!()
    }
}

pub trait PageFrameAllocator {
    fn allocate_frame(&mut self) -> Option<Page>;

    fn deallocate_frame(&mut self);
}

fn calc_mem_available(entries: &[&memory_map::Entry]) -> u64 {
    let mut max_base_addr = 0;
    let mut length_of_entry = 0;
    for entry in entries {
        if entry.base > max_base_addr {
            max_base_addr = entry.base;
            length_of_entry = entry.length;
        }
    }
    print!("max addr : {} ", max_base_addr + length_of_entry);
    max_base_addr + length_of_entry
}
