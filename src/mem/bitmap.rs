use alloc::vec::Vec;
use core::alloc::Allocator;

use limine::memory_map;
use limine::memory_map::EntryType;

use crate::{bit, println};
use crate::mem::{calc_mem_available, PageFrameAllocator};
use crate::mem::page::{calc_4kb_page_count, Page, PageSize};

pub struct Bitmap<T: Allocator>(pub Vec<u8, T>);

impl<T: Allocator> Bitmap<T> {
    pub fn new(bitmap: Vec<u8, T>) -> Self {
        Bitmap(bitmap)
    }

    pub fn find_free_4kb_page(&self) -> Option<Page> {
        for (i, pagebyte) in self.0.iter().enumerate() {
            if pagebyte != &u8::MAX {
                for bit in 0..8 {
                    if bit!(bit) & pagebyte == 0 {
                        let index = i * 8 + bit;
                        return Some(pagekb4_from_index(index));
                    }
                }
            }
        }
        None
    }
}

impl<T: Allocator> PageFrameAllocator for Bitmap<T> {
    fn allocate_frame(&mut self) -> Option<Page> {
        todo!()
    }

    fn deallocate_frame(&mut self) {
        todo!()
    }
}

pub fn create_bitmap<'a, T: Allocator>(
    entries: &[&memory_map::Entry],
    allocator: &'a T,
) -> Vec<u8, &'a T> {
    let mem_available = calc_mem_available(entries);
    // each byte represents 8 pages.
    let bitmap_size = calc_4kb_page_count(mem_available) / 8;
    println!("bitmap size: {bitmap_size}");
    let mut bitmap_vec = Vec::with_capacity_in(bitmap_size as usize, allocator);
    for _ in 0..bitmap_size {
        bitmap_vec.push(0);
    }

    for pagebyte_index in 0..bitmap_vec.len() {
        bitmap_vec[pagebyte_index] = set_used_page_bits(pagebyte_index, entries);
    }
    bitmap_vec
}

fn set_used_page_bits(pagebyte_index: usize, entries: &[&memory_map::Entry]) -> u8 {
    let mut pagebyte = 0;
    for bit in 0..8 {
        let page = pagekb4_from_index(pagebyte_index * 8 + bit);
        if !is_page_entirely_free(&page, entries) {
            pagebyte |= bit!(bit);
        }
    }
    pagebyte
}

fn pagekb4_from_index(index: usize) -> Page {
    Page {
        start: index * PageSize::KB4 as usize,
        size: PageSize::KB4,
    }
}

pub fn is_page_entirely_free(page: &Page, entries: &[&memory_map::Entry]) -> bool {
    let page_end = match page.size {
        PageSize::KB4 => page.start + PageSize::KB4 as usize,
        PageSize::MB2 => page.start + PageSize::MB2 as usize,
    } as u64;
    for entry in entries {
        if !entry.entry_type.eq(&EntryType::USABLE) {
            let entry_end = entry.base + entry.length;
            if entry.base < page.start as u64 && entry_end > page_end {
                return false;
            } else if entry.base > page.start as u64 && entry.base < page_end {
                return false;
            } else if entry_end > page.start as u64 && entry_end < page_end {
            }
        }
    }
    true
}
