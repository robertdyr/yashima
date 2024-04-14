const NUM_PAGE_ENTRIES: usize = 512;

/// Page Table Structure for all hierarchy levels.
///
/// For further information on the paging structures refer to [5.3.3 4-Kbyte Page Translation](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=205) and their
/// Field Definitions [5.4.1 Field Definitions](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=215) 
pub struct PageTable {
    entries: [PageTableEntry; NUM_PAGE_ENTRIES],
}

pub struct PageTableEntry {}