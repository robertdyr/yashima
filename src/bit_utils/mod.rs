use core::ops::Range;

pub(crate) trait BitRange {
    fn bit(&self, i: usize) -> bool;
    fn bit_range(&self, range: Range<usize>) -> Self;
}

impl BitRange for u64 {
    fn bit(&self, i: usize) -> bool {
        self & (1 << i) != 0
    }

    fn bit_range(&self, range: Range<usize>) -> u64 {
        let s = 64;
        let h = self << s - range.end >> s - range.end;
        h >> range.start
    }
}

#[derive(Debug)]
pub enum AlignmentError {
    InvalidAlignment,
    AlignmentNotPossible,
}

pub(crate) fn find_next_aligned_byte(
    ptr: *const u8,
    align: usize,
) -> Result<*const u8, AlignmentError> {
    if align == 0 || (align & (align - 1)) != 0 {
        // Return an error if alignment is not a power of two or is zero
        return Err(AlignmentError::InvalidAlignment);
    }

    let offset = ptr.align_offset(align);
    if offset == usize::MAX {
        // Return an error if alignment is not possible
        return Err(AlignmentError::AlignmentNotPossible);
    }

    // Calculate the new aligned address and return it
    Ok(unsafe { (ptr as usize + offset) as *const u8 })
}

#[macro_export]
macro_rules! bit {
    ($x:expr) => {
        1 << $x
    };
}
