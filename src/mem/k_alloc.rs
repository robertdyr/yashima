use crate::bit_utils::AlignmentError;
use crate::mem::page::PageSize;
use crate::mem::page_frame_allocator::PageFrameAllocator;
use crate::{print, println};
use core::alloc::{GlobalAlloc, Layout};

#[repr(transparent)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
struct MemBlockState(u8);

impl MemBlockState {
    pub const FREE: Self = Self(0);
    pub const USED: Self = Self(1);
}

/// This struct implements a Free List Node approach to manage memory.
/// This means every allocation receives a block of memory, containing space for the aligned memory
/// itself, and space for the MemBlocks metadata, such as reference to the next free MemBlock.
///
/// The allocated memory in the usable memory block is guaranteed to be aligned to the first
/// possible alignment in the usable mem block.
///
/// The Memory block itself is aligned on every byte.
#[repr(align(1))]
#[derive(Debug)]
pub struct MemBlock {
    next: *mut MemBlock,
    /// the virtual start address of the entire block including the `FreeListNode`
    memblock_start_adr: usize,
    /// the size of the entire block including the `FreeListNode`
    memblock_size: usize,
    state: MemBlockState,
}

impl MemBlock {
    /// `start` the virtual address of the entire block including the `FreeListNode`
    /// `size` the size of the entire block including the `FreeListNode`
    ///
    /// Initializes the memblock as Free with no next memblock
    pub fn new(start_adr: usize, size: usize) -> Self {
        Self {
            memblock_start_adr: start_adr,
            memblock_size: size,
            state: MemBlockState::FREE,
            next: core::ptr::null_mut(),
        }
    }

    fn set_state(&mut self, state: MemBlockState) {
        self.state = state;
    }

    fn compute_usable_block_start(&self) -> usize {
        let self_size = core::mem::size_of::<Self>();
        self.memblock_start_adr + self_size
    }

    fn compute_usable_block_size(&self) -> usize {
        self.compute_block_end() - self.compute_usable_block_start()
    }

    fn compute_block_end(&self) -> usize {
        self.memblock_start_adr + self.memblock_size
    }

    fn set_mem_block_size(&mut self, size: usize) {
        self.memblock_size = size;
    }

    fn has_space(&self, size: usize, align: usize) -> bool {
        let required_bytes = size;
        let alignment = align;

        let next_aligned_byte = match crate::bit_utils::find_next_aligned_byte(
            self.compute_usable_block_start() as *const u8,
            alignment,
        ) {
            Ok(aligned_byte) => aligned_byte,
            Err(AlignmentError::InvalidAlignment) => panic!("invalid alignment!"),
            Err(AlignmentError::AlignmentNotPossible) => panic!("alignment not possible!"),
        };

        unsafe {
            let highest_req_byte_addr = next_aligned_byte.offset(required_bytes as isize);
            let highest_avail_byte_addr = (self.compute_usable_block_start() as *const u8)
                .offset(self.compute_usable_block_size() as isize);
            if highest_avail_byte_addr.le(&highest_req_byte_addr) {
                return false;
            }
            true
        }
    }

    fn is_free(&self) -> bool {
        self.state.eq(&MemBlockState::FREE)
    }

    fn contains(&self, adr: usize) -> bool {
        self.compute_usable_block_start() < adr && self.compute_block_end() >= adr
    }
}

pub struct KAlloc<T: PageFrameAllocator> {
    pub heap_start_adr: Option<usize>,
    pub heap_size: usize,
    pub bitmap: Option<T>,
    pub first_mem_block_node: *mut MemBlock,
}

impl<T: PageFrameAllocator> KAlloc<T> {
    pub unsafe fn init_kernel_heap(&mut self) {
        let pages_to_request = ((self.heap_size / PageSize::KB4 as usize) + 1) as u64;
        let (start_adr, _) = match self
            .bitmap
            .as_mut()
            .unwrap()
            .request_continues_page(pages_to_request)
        {
            Some(result) => result,
            None => panic!("not enough space for kernel heap. request smaller heap."),
        };

        let init_block_adr = start_adr as *mut MemBlock;

        let init_block = MemBlock::new(start_adr, self.heap_size);

        core::ptr::write(init_block_adr, init_block);

        self.heap_start_adr = Some(start_adr);
        self.first_mem_block_node = init_block_adr;
    }
}

unsafe impl<T: PageFrameAllocator> GlobalAlloc for KAlloc<T> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let required_bytes = layout.size();
        let alignment = layout.align();

        let mut prev_block = core::ptr::null_mut();
        let mut curr_block = self.first_mem_block_node;
        while !(curr_block
            .read_unaligned()
            .has_space(required_bytes, alignment)
            && curr_block.read_unaligned().is_free())
        {
            // while not free or not enogh space, search for free block
            if curr_block.read_unaligned().next.is_null() {
                return core::ptr::null_mut();
            }
            let next_node = curr_block.read_unaligned().next;
            // println!(" curr mem block {:?} ", (*curr_block));
            prev_block = curr_block;
            curr_block = next_node;
        }

        // we know the block has space for the aligned struct
        let alloc_ptr = (curr_block.read_unaligned().compute_usable_block_start() as *mut u8)
            .offset(alignment as isize);
        curr_block.as_mut().unwrap().set_state(MemBlockState::USED);

        // we cut the current block into two pieces. right after the allocation we create the new
        // block
        let new_block_start = alloc_ptr.offset(required_bytes as isize) as usize;

        // if we are the last block we have to check if there is enough space for a new block in the
        // current block if there is not enough space, dont split the block
        // if there is enough space, create the new block and set curr_block.next to the new block.
        // also update current blocks size

        // if we are not the last block we have to check if there is enough space for a new block in
        // the current block if there is not enough space, dont split the block
        // if there is enough space, create the new block and set new.next to curr.next. also set
        // the curr_block.next to the new block. also update current blocks size
        let space_left_in_curr = curr_block.read_unaligned().compute_block_end() - new_block_start;
        if space_left_in_curr >= core::mem::size_of::<MemBlock>() {
            let new_block_adr = new_block_start as *mut MemBlock;
            // println!("       new_block_adr {}", new_block_adr.addr());
            let new_block = MemBlock::new(new_block_start, space_left_in_curr);
            core::ptr::write_unaligned(new_block_adr, new_block);
            if !curr_block.read_unaligned().next.is_null() {
                new_block_adr.as_mut().unwrap().next = curr_block.read_unaligned().next;
            }
            curr_block.as_mut().unwrap().next = new_block_adr;
            // space_left_in_curr now is the new blocks memory
            curr_block
                .as_mut()
                .unwrap()
                .set_mem_block_size(curr_block.read_unaligned().memblock_size - space_left_in_curr);
        }

        alloc_ptr
    }

    // #[allow(clippy::duplicate_code)]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut prev_block_ptr = core::ptr::null_mut();
        let mut curr_block_ptr = self.first_mem_block_node;
        while !curr_block_ptr.read_unaligned().contains(ptr as usize) {
            let next_node = curr_block_ptr.read_unaligned().next;
            prev_block_ptr = curr_block_ptr;
            curr_block_ptr = next_node;
        }
        // first we free the block
        curr_block_ptr.as_mut().unwrap().set_state(MemBlockState::FREE);
        // then we try to merge blocks
        // first we merge with next block if it exist and free
        // current block can never be null. there will always be a block thats found. or else the allocation has a bug.
        let next_block_ptr = curr_block_ptr.read_unaligned().next;
        if !next_block_ptr.is_null() && next_block_ptr.read_unaligned().is_free() {
            curr_block_ptr.as_mut().unwrap().next = next_block_ptr.read_unaligned().next;
            curr_block_ptr.as_mut().unwrap().memblock_size +=
                next_block_ptr.read_unaligned().memblock_size;
        }
        // then we merge with previous block if exist and free
        if !prev_block_ptr.is_null() && prev_block_ptr.read_unaligned().is_free() {
            prev_block_ptr.as_mut().unwrap().next = curr_block_ptr.read_unaligned().next;
            prev_block_ptr.as_mut().unwrap().memblock_size +=
                curr_block_ptr.read_unaligned().memblock_size;
        }
    }
}
