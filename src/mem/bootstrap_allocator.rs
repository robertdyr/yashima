use core::alloc::{AllocError, GlobalAlloc, Layout};
use core::ptr::NonNull;

use limine::memory_map;
use limine::response::{HhdmResponse, MemoryMapResponse};

use crate::bit_utils::AlignmentError;

pub fn init_bootstrap_alloc(
    mm: &MemoryMapResponse,
    hhdm_offset_response: &HhdmResponse,
) -> BootstrapAllocator {
    // the goal is to have a variable sized bitmap that tracks the free physical pages, that the sys
    // allocator can reference. since we do not know the size of the bitmap at compile time, we
    // also do not know the amount of pages required to map the bitmap at compile time.
    //
    // so to initialize the real heap, we require the bitmap, however this bitmap requires a "heap"
    // itself due to its variable size nature. there are two ways to work around this. we can
    // use a fixed size memblock on the stack and use it to initialize the paging structures for
    // the bitmap, or we can create a fixed amount of pages that map a fixed sized
    // "initialisation heap" that we can use to set up the bitmap etc.. im opting for the
    // bootstrap heap variant.

    // depending on the requirements the bootstrap heap size can be adjusted, or can be a multi step
    // process, gradually increasing the heaps depedning on the stage. since I am not expecting
    // anything higher than 40 bit physical address, I chose 68Mb heap. The Bitmap required to
    // track 40 Bit Physical address is roughly 34 MB ((2^40 total bytes)/(2^12 per page))/(8 pages
    // per byte). After the bootstrapping the bitmap can be copied/remapped onto the real heap and
    // the bootstrap heap can be repurposed/thrown back into the pool of free pages.

    // limine sets up a 4Gb direct map with the offset of the hhdm_offset_response
    // since it is a direct map we know that free phsyical pages within the 4Gb direct map
    // respond to free addresses in the virtual address space.

    const BOOTSTRAP_HEAP_SIZE: usize = 1 << 26;

    let start_ptr = find_memblock(BOOTSTRAP_HEAP_SIZE, mm.entries(), 1)
        .unwrap_or_else(|| panic!("couldn't find space for bootstrap heap!"));
    let hhdm_start_ptr = unsafe { start_ptr.offset(hhdm_offset_response.offset() as isize) };

    BootstrapAllocator::new(hhdm_start_ptr, BOOTSTRAP_HEAP_SIZE)
}

fn find_memblock(size: usize, mm_entries: &[&memory_map::Entry], align: usize) -> Option<*mut u8> {
    for entry in mm_entries.iter() {
        let entry_base = entry.base as *const u8;

        let align_offset = entry_base.align_offset(align);

        let kb4_aligned_entry_base = unsafe { entry_base.add(align_offset) };
        let diff = align_offset;
        let space = entry.length - diff as u64;

        if space >= size as u64 {
            return Some(kb4_aligned_entry_base as *mut u8);
        }
    }
    None
}

/// Allocator which soles purpose is to allocate byte array for the PageFrameAllocator so we can
/// write the real system allocator.
pub struct BootstrapAllocator {
    start: *mut u8,
    size: usize,
}

impl BootstrapAllocator {
    pub fn new(start: *mut u8, size: usize) -> Self {
        BootstrapAllocator { start, size }
    }
}

unsafe impl core::alloc::Allocator for BootstrapAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let min_req_bytes = layout.size();
        let alignment = layout.align();
        let next_aligned_byte =
            match crate::bit_utils::find_next_aligned_byte(self.start, alignment) {
                Ok(aligned_byte) => aligned_byte,
                Err(AlignmentError::InvalidAlignment) => panic!("invalid alignment!"),
                Err(AlignmentError::AlignmentNotPossible) => panic!("alignment not possible!"),
            };

        unsafe {
            // checking if the there is enough space to hold the bitmap
            let highest_req_byte_addr = next_aligned_byte.offset(min_req_bytes as isize);
            let highest_avail_byte_addr = self.start.offset(self.size as isize);
            if highest_avail_byte_addr.le(&highest_req_byte_addr) {
                return Err(AllocError);
            }
            let ptr = core::ptr::slice_from_raw_parts_mut(next_aligned_byte, min_req_bytes);
            return Ok(NonNull::new(ptr).unwrap());
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // im leaving this empty since we can just overwrite it
    }
}
