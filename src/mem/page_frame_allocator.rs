use crate::mem::bitmap::{Bitmap, BitmapOperations};
use crate::mem::page::Page4Kb;

struct PageFrameAllocator {
    bitmap: Bitmap,
}

impl PageFrameAllocator {

    fn allocate_frame(&mut self) -> Option<Page4Kb> {
        self.bitmap.alloc().map(|index| {
            Page4Kb::new(index)
        })
    }

    fn deallocate_frame(&mut self) {
        todo!()
    }
}