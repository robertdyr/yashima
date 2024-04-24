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

#[macro_export]
macro_rules! bit {
    ($x:expr) => {
        1 << $x
    };
}