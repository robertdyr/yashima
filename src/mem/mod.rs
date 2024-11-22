use core::alloc::GlobalAlloc;

use limine::memory_map;

use crate::mem::page::Page;
use crate::print;

pub mod bitmap;
pub(crate) mod page;
pub(crate) mod k_alloc;


pub trait PageFrameAllocator {
    fn request_page(&mut self) -> Option<Page>;
    
    fn request_continues_page(&mut self, count: u64) ->  Option<(usize, u64)>;

    fn free_page(&mut self);
    
    fn free_continues_pages(&mut self, count: u64);
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
