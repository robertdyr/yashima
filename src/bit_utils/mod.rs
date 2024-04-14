use core::ops::Range;

trait BitRange {
    fn bit(&self, i: usize) -> bool;
    fn bit_range(&self, range: Range<usize>) -> Self;
}


impl BitRange for u64 {
    fn bit(&self, i: usize) -> bool {
        self & (1 << i) != 0
    }

    fn bit_range(&self, range: Range<usize>) -> u64 {
        let h = self << range.end >> range.end;
        h >> range.start
    }
}

