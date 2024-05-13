use crate::arch::x86_64::paging::{PDPTable, PML4Table, PTable};

pub struct Page4Kb {
    index: usize,
}

impl Page4Kb {
    pub fn new(index: usize) -> Self {
        Page4Kb { index }
    }
}

// fn page_walk
