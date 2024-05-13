use crate::bit_utils::AlignmentError;
use core::alloc::{AllocError, Layout};
use core::ptr::NonNull;
use limine::memory_map;
use limine::response::{HhdmResponse, MemoryMapResponse};

fn walk_page() {}

fn bootstrap_alloc(mm: &MemoryMapResponse) {
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

    // to map 68Mb we need 16384 PTE Entries. this means we need to allocate 32 PTETables.
    // we also require an additional PDETable for the unlikely event of an overflow of the first
    // PDETable. in total we need 33 additional paging structures for our fixed sized 68Mb Heap.
    // each one is 4Kb physical memory, total memory: 33 * 4096 = 135168.

    // to allocate the paging structurs we first have to find the block of 135168 page aligned
    // bytes. here we can place the paging structures. however in order to even mutate any
    // bytes, these bytes have to be mapped into virtual address space as well.
    // and this is where it gets annyoing. i do not know if this space is already mapped by limine,
    // if its partly mapped or if its not mapped at all. the memory map only tells me free
    // pages, not if they are mapped into addresse space afaik. the document suggests that the 4 GB
    // are direct mapped.
    let start_ptr = find_memblock(33 * PAGE_SIZE, mm, PAGE_SIZE)
        .unwrap_or_else(|| panic!("couldn't find space for bootstrap heap!"));
    const BOOTSTRAP_HEAP_SIZE: usize = 1 << 26;
    const PAGE_SIZE: usize = 4096;

    // first we need to find 68Mb worth of free pages (shouldn't be too hard at this point), and map
    // them into our virtual address space. for convenience im looking for a continues block of
    // memory. this makes it easier to mark the pages that are used up by in the bitmap itself
    // after we created the bitmap.

    // since limine sets up a higher half kernel, with a higher half direct map, we can be sure that
    // the first free 68Mb pages can be mapped with hhdm offset without collision with kernel
    // text,data or stack.
    let start_ptr = find_memblock(BOOTSTRAP_HEAP_SIZE, mm, PAGE_SIZE)
        .unwrap_or_else(|| panic!("couldn't find space for bootstrap heap!"));
}

fn find_memblock(size: usize, mm: &MemoryMapResponse, align: usize) -> Option<*mut u8> {
    for entry in mm.entries().iter() {
        let entry_base = entry.base as *const u8;

        // Calculate the alignment offset to the next 4KB boundary
        let align_offset = unsafe { entry_base.align_offset(align) };

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
struct BootstrapAllocator {
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
            if next_aligned_byte
                .offset(min_req_bytes as isize)
                .le(&self.start.offset(self.size as isize))
            {
                return Err(AllocError);
            }
            let ptr = core::ptr::slice_from_raw_parts_mut(next_aligned_byte, min_req_bytes);
            return Ok(NonNull::new(ptr).unwrap());
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        todo!()
    }
}
