use bitflags::bitflags;

use crate::bit;

const NUM_PML4_ENTRIES: usize = 512;

/// Page Table Structure for all hierarchy levels.
///
/// For further information on the paging structures refer to [5.3.3 4-Kbyte Page Translation](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=205) and their
/// Field Definitions [5.4.1 Field Definitions](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=215) 
pub struct PageTable {
    entries: [PML4Entry; NUM_PML4_ENTRIES],
}


/// PML4 Entry
pub struct PML4Entry(u64);

bitflags! {
    pub struct PML4Flags: u64 {
        // Present
        // This bit indicates whether the page-translation table or physical page is loaded
        // in physical memory. This bit should effectively always be 1 (since we rarely work with not loaded tables).
        const P = bit!(0);
        // Read/Write
        // This bit controls read/write access to all physical pages mapped by the
        // table entry. When the R/W bit is cleared to 0, access is restricted to read-only. When the R/W bit is set to 1, both read and write access
        // is allowed.
        const RW = bit!(1);
        // User/Supervisor
        // This bit controls user (CPL 3) access to all physical pages mapped
        // by the table entry. For example, a page-map level-4 U/S bit controls the access allowed to all 128M
        // (512  512  512) physical pages it maps through the lower-level translation tables. When the U/S bit
        // is cleared to 0, access is restricted to supervisor level (CPL 0, 1, 2). When the U/S bit is set to 1, both
        // user and supervisor access is allowed.
        const US = bit!(2);
        // Page-Level Writethrough
        // This bit indicates whether the page-translation table or
        // physical page to which this entry points has a writeback or writethrough caching policy. When the
        // PWT bit is cleared to 0, the table or physical page has a writeback caching policy. When the PWT bit is
        // set to 1, the table or physical page has a writethrough caching policy.
        const PWT = bit!(3);
        // Page-Level Cache Disable
        // This bit indicates whether the page-translation table or
        // physical page to which this entry points is cacheable. When the PCD bit is cleared to 0, the table or
        // physical page is cacheable. When the PCD bit is set to 1, the table or physical page is not cacheable.
        const PCD = bit!(4);
        // Accessed
        // This bit indicates whether the page-translation table or physical page to
        // which this entry points has been accessed. The A bit is set to 1 by the processor the first time the table
        // or physical page is either read from or written to. The A bit is never cleared by the processor. Instead,
        // software must clear this bit to 0 when it needs to track the frequency of table or physical-page accesses.
        const A  = bit!(5);
        // No Execute
        // When the NX bit
        // is cleared to 0, code can be executed from the mapped physical pages. When the NX bit is set to 1,
        // code cannot be executed from the mapped physical pages.
        // The NX bit can only be set when the no-execute page-protection feature is enabled by setting
        // EFER.NXE to 1.
        const NX = bit!(63);
    }
}


/// PML3 Entry
pub struct PDPEntry(u64);


/// PML2 Entry
pub struct PDEntry(u64);


/// PML1 Entry
pub struct PTEntry(u64);

