use crate::mem::bitmap::RawBitmap;
use crate::mem::page::PageSize;
use core::alloc::{GlobalAlloc, Layout};
use crate::bit_utils::AlignmentError;

pub struct KAlloc {
    pub heap_start_adr: Option<usize>,
    pub heap_size: usize,
    pub bitmap: Option<RawBitmap>,
}

impl KAlloc {
    pub unsafe fn init_kernel_heap(&mut self) {
        let (start_adr,_ ) = match  self.bitmap.as_mut().unwrap().allocate_continues_4kb_pages(((self.heap_size / PageSize::KB4 as usize) + 1) as u64) {
            Some(result) => result,
            None => panic!("not enough space for kernel heap. request smaller heap."),
        };

        self.heap_start_adr = Some(start_adr);
    }

}

unsafe impl GlobalAlloc for KAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let required_bytes = layout.size();
        let alignment = layout.align();
        let next_aligned_byte =
            match crate::bit_utils::find_next_aligned_byte(self.heap_start_adr.unwrap() as *const u8, alignment) {
                Ok(aligned_byte) => aligned_byte,
                Err(AlignmentError::InvalidAlignment) => panic!("invalid alignment!"),
                Err(AlignmentError::AlignmentNotPossible) => panic!("alignment not possible!"),
            };

        unsafe {
            // checking if the there is enough space to hold the bitmap
            let highest_req_byte_addr = next_aligned_byte.offset(required_bytes as isize);
            let highest_avail_byte_addr = (self.heap_start_adr.unwrap() as *const u8).offset(self.heap_size as isize);
            if highest_avail_byte_addr.le(&highest_req_byte_addr) {
                return core::ptr::null_mut();
            }
            next_aligned_byte as *mut u8
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        todo!()
    }
}