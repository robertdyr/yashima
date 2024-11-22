use crate::bit;
use crate::mem::page::{Page, PageSize};
use crate::mem::page_frame_allocator::PageFrameAllocator;
use limine::memory_map;
use limine::memory_map::EntryType;
use limine::response::HhdmResponse;

/// Finds the highest physical address in the phy memory map.
/// Effectively evaluating the memory size of the system.
fn find_highest_adr(phys_mmap: &[&memory_map::Entry]) -> usize {
    phys_mmap.iter().fold(0, |acc, e| {
        let entry_max_phys_adr = (e.base + e.length) as usize;
        if entry_max_phys_adr >= acc {
            return entry_max_phys_adr;
        }
        acc
    })
}

/// Finds a free physical memory block with size `size`. Returns a pointer to the physical start
/// address of the memblock. The memblock is aligned after `align` input. Method only returns
/// Some(phys_addr) if the aligned memblock has enough space. Otherwise returns None.
fn find_free_phys_memblock(
    size: usize,
    mm_entries: &[&memory_map::Entry],
    align: usize,
) -> Option<*mut u8> {
    for entry in mm_entries.iter() {
        if entry.entry_type.eq(&EntryType::USABLE) {
            let entry_base = entry.base as *const u8;
            let align_offset = entry_base.align_offset(align);
            let kb4_aligned_entry_base = unsafe { entry_base.add(align_offset) };
            let diff = align_offset;
            let space = entry.length - diff as u64;

            if space >= size as u64 {
                return Some(kb4_aligned_entry_base as *mut u8);
            }
        }
    }
    None
}

/// The RawBitmap stores all pages states. This means that the bitmap holds record on if a given
/// page is available or already used. A 0 bit is considered a free page, a 1 bit is considered a
/// used page. The Bitmap exists in Kernel space (Higher half). It reserves its own space outside of
/// the Kernel stack and Kernel Heap. On creation of the Bitmap, the size of the systems memory is
/// evaluated and a Bitmap that is capable to hold all pages is created. This means this Bitmap is
/// variable in length. It will mark all the pages that are required for the bitmap itself as used.
/// The Kernel Heap will start numerically "above" the last Bitmap entry.
///
/// Every bit is guaranteed to map to page. This means that up to 7 pages may be thrown away because
/// they would not fill the entire last Byte. The `start` pointer is guaranteed to be 4KB aligned.
pub struct RawBitmap {
    /// Virtual start address of the Bitmap itself.
    /// Each byte represents 8 pages (4Kb).
    pub start: *const u8,
    /// Size of the bitmap in bytes. Every bit is guaranteed to map to page.
    pub size: usize,
}

impl RawBitmap {
    /// Initializes a new bitmap to track pages.
    /// Sets all pages that are used either by limine, the kernel, or itself to used.
    /// In other words the correct state where free pages are marked as free, and used pages are
    /// marked as used.
    pub unsafe fn new(
        phys_mmap: &[&memory_map::Entry],
        hhdm_offset_response: &HhdmResponse,
    ) -> Self {
        // first we need to find how many pages our system needs. we need to figure out how much
        // memory our system has, and thus how many pages we need to map the physical
        // memory.
        let system_memory = find_highest_adr(phys_mmap);
        // if there is some memory left over that doesnt fit an entire page we throw it away
        let required_pages = system_memory / PageSize::KB4 as usize;
        // one byte can represent the state of 8 pages. throw away left over pages that cant fill an
        // entire page byte.
        let required_bitmap_bytes = required_pages / 8;

        // now we look for physical space thats able to hold all pagebytes. aligned 4KB because
        // thats simpler later on when marking used pages. we can unwrap here since this is
        // required to work.
        let phys_start_addr =
            find_free_phys_memblock(required_bitmap_bytes, phys_mmap, PageSize::KB4 as usize)
                .unwrap();

        // the memblock we just aquired is guaranteed to be free in the physical address space.
        // because limine sets up a higher half direct map we know two things:
        // a) the memblock must also be free in the virtual address space of the higher half kernel
        // b) we can infer the virtual start address of the memblock.
        let virt_start_addr =
            unsafe { phys_start_addr.offset(hhdm_offset_response.offset() as isize) };

        let mut raw_bit_map = RawBitmap {
            start: virt_start_addr,
            size: required_bitmap_bytes,
        };
        raw_bit_map.init_populate_bitmap(phys_mmap, hhdm_offset_response);

        raw_bit_map
    }

    unsafe fn init_populate_bitmap(
        &mut self,
        phys_mmap: &[&memory_map::Entry],
        hhdm_offset_response: &HhdmResponse,
    ) {
        let bitmap_slice: &mut [u8] =
            core::slice::from_raw_parts_mut(self.start as *mut u8, self.size);
        // mark all pages free, we will later set used pagebits to 1
        for byte in bitmap_slice.iter_mut() {
            *byte = 0;
        }

        // mark all pages as used, that the phys_mmap already marks as used
        for (pagebyte_idx, pagebyte) in bitmap_slice.iter_mut().enumerate() {
            *pagebyte = RawBitmap::compute_mmap_used_page_bits(pagebyte_idx, phys_mmap);
        }

        // mark all pages as used, that the bitmap itself requires
        let phys_bitmap_start_adr = self.start.sub(hhdm_offset_response.offset() as usize);
        let phys_bitmap_end_adr = phys_bitmap_start_adr.offset(self.size as isize);
        // which physical page holds the start of the bitmap
        let bitmap_start_bitmap_page_idx = phys_bitmap_start_adr as usize / PageSize::KB4 as usize;
        // which physical page holds the end of the bitmap
        let bitmap_end_bitmap_page_idx = phys_bitmap_end_adr as usize / PageSize::KB4 as usize;
        for idx in bitmap_start_bitmap_page_idx..bitmap_end_bitmap_page_idx {
            self.set_pageidx_used(idx);
        }
    }

    fn compute_mmap_used_page_bits(pagebyte_idx: usize, entries: &[&memory_map::Entry]) -> u8 {
        let mut pagebyte = 0;
        for bit in 0..8 {
            let page = RawBitmap::pagekb4_from_pageidx((pagebyte_idx * 8 + bit) as usize);
            let isfree = is_page_entirely_free(&page, entries);
            if !isfree {
                pagebyte |= bit!(bit);
            }
        }
        pagebyte
    }

    unsafe fn set_pageidx_used(&mut self, pageidx: usize) {
        let pagebyte_idx = pageidx / 8;
        let pagebit = pageidx % 8;
        let pagebyte_adr = self.start.offset(pagebyte_idx as isize) as *mut u8;
        *pagebyte_adr |= bit!(pagebit);
    }

    unsafe fn set_pageidx_free(&mut self, pageidx: usize) {
        let pagebyte_idx = pageidx / 8;
        let pagebit = pageidx % 8;
        let pagebyte_adr = self.start.offset(pagebyte_idx as isize) as *mut u8;
        *pagebyte_adr &= !(bit!(pagebit));
    }

    unsafe fn is_pageidx_free(&self, pageidx: usize) -> bool {
        let pagebyte_idx = pageidx / 8;
        let pagebit = pageidx % 8;
        let pagebyte_adr = self.start.offset(pagebyte_idx as isize) as *mut u8;
        *pagebyte_adr & bit!(pagebit) == 0
    }

    /// computes the 4Kb Page given the index in the bitmap
    fn pagekb4_from_pageidx(pageidx: usize) -> Page {
        Page {
            start: pageidx * PageSize::KB4 as usize,
            size: PageSize::KB4,
        }
    }

    /// Finds a free physical page and returns the
    pub unsafe fn allocate_4kb_page(&mut self) -> Option<Page> {
        let bitmap = unsafe { core::slice::from_raw_parts(self.start, self.size) };

        for (i, &pagebyte) in bitmap.iter().enumerate() {
            // if not all bits are set we have a at least one free physical page
            if pagebyte != u8::MAX {
                for bit in 0..8 {
                    if bit!(bit) & pagebyte == 0 {
                        let index = i * 8 + bit;
                        let mut_pagebyte = self.start.offset(i as isize) as *mut u8;
                        // set the page to used in the bitmap
                        *mut_pagebyte = pagebyte | bit!(bit);
                        // return the page
                        return Some(pagekb4_from_index(index));
                    }
                }
            }
        }
        None
    }

    /// Finds a n free physical page. All pages are continuesly free.
    /// Used for kernel heap because we have a direct memoery map we need continues physical free
    /// pages as well. Returns (start address, 4kb page count).
    pub unsafe fn allocate_continues_4kb_pages(&mut self, count: u64) -> Option<(usize, u64)> {
        let bitmap = unsafe { core::slice::from_raw_parts(self.start, self.size) };

        for bitmap_pageidx in 0..bitmap.len() * 8 {
            if self.is_pageidx_free(bitmap_pageidx) {
                let mut is_continues_pages_free = false;
                for continues_page in 1..count {
                    if self.is_pageidx_free(bitmap_pageidx + continues_page as usize) {
                        is_continues_pages_free = true;
                    }
                }
                if is_continues_pages_free {
                    for allocated_pages in 0..count {
                        self.set_pageidx_used(bitmap_pageidx + allocated_pages as usize);
                    }
                    let first_page = Self::pagekb4_from_pageidx(bitmap_pageidx);
                    return Some((first_page.start, count));
                }
            }
        }
        None
    }

    pub unsafe fn free_page(&mut self, page: Page) {
        let pageidx = page.start / PageSize::KB4 as usize;
        self.set_pageidx_free(pageidx);
    }

    pub unsafe fn free_continues_pages(&mut self, first_page_start_adr: usize, pagescount: u64) {
        for page in 0..pagescount {
            let nth_page_start_adr = first_page_start_adr + (page * PageSize::KB4 as u64) as usize;
            let pageidx = nth_page_start_adr / PageSize::KB4 as usize;
            self.set_pageidx_free(pageidx);
        }
    }
}

impl PageFrameAllocator for RawBitmap {
    fn request_page(&mut self) -> Option<Page> {
        unsafe { self.allocate_4kb_page() }
    }

    fn request_continues_page(&mut self, count: u64) -> Option<(usize, u64)> {
        unsafe { self.allocate_continues_4kb_pages(count) }
    }

    fn free_page(&mut self, page: Page) {
        unsafe { self.free_page(page) }
    }

    fn free_continues_pages(&mut self, first_page_start_adr: usize, count: u64) {
        unsafe {
            self.free_continues_pages(first_page_start_adr, count);
        }
    }
}

fn pagekb4_from_index(index: usize) -> Page {
    Page {
        start: index * PageSize::KB4 as usize,
        size: PageSize::KB4,
    }
}

fn is_page_entirely_free(page: &Page, entries: &[&memory_map::Entry]) -> bool {
    let page_end = match page.size {
        PageSize::KB4 => page.start + PageSize::KB4 as usize,
        PageSize::MB2 => page.start + PageSize::MB2 as usize,
    } as u64;
    for entry in entries {
        if entry.entry_type.eq(&EntryType::USABLE) {
            let entry_end = entry.base + entry.length;

            if entry.base <= page.start as u64 && entry_end >= page_end {
                return true;
            }
        }
    }
    false
}
