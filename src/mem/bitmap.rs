//use alloc::vec::Vec;
use crate::mem::page::Page4Kb;

pub trait BitmapOperations {
    type PageType;
    fn alloc(&mut self) -> Option<usize>;
    fn free(&mut self, index: usize);
}
pub struct Bitmap {
    //map: Vec<u8>,
}

impl BitmapOperations for Bitmap {
    type PageType = Page4Kb;

    fn alloc(&mut self) -> Option<usize> {
        todo!()
    }

    fn free(&mut self, index: usize) {
        todo!()
    }
}