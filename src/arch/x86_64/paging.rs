use bitflags::bitflags;

use crate::bit_utils::BitRange;
use crate::{bit, print};

const KB4: usize = 0xFFF;
const PAGE_MASK_4KB: u64 = (usize::MAX & !KB4) as u64;

pub struct PhysAddr(pub u64);

impl PhysAddr {
    pub fn new(addr: u64) -> Self {
        Self(addr)
    }

    pub fn raw_mut<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    pub fn raw<T>(&self) -> *const T {
        self.0 as *const T
    }
}

const NUM_PML4_ENTRIES: usize = 512;

/// Page Table Structure for all hierarchy levels.
///
/// For further information on the paging structures refer to [5.3.3 4-Kbyte Page Translation](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=205) and their
/// Field Definitions [5.4.1 Field Definitions](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=215)
#[repr(transparent)]
pub struct PML4Table {
    pub entries: [PML4Entry; NUM_PML4_ENTRIES],
}

/// PML4 Entry
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct PML4Entry(pub u64);

impl PML4Entry {
    pub fn new(phys_addr: PhysAddr, flags: PML4Flags) -> Self {
        PML4Entry((phys_addr.0 & PAGE_MASK_4KB) | flags.bits())
    }

    pub fn get_flags(&self) -> Option<PML4Flags> {
        let flags = self.0.bit_range(0..6) | (self.0 & 1 << 63);
        PML4Flags::from_bits(flags)
    }

    /// Physical Address of the Paging Structure referenced by this Entry
    ///
    /// The Page Walk itself is done outside this Table since it depends on how paging is
    /// implemented. A direct mapping needs to be handled different to a recursive mapping.
    pub fn get_phys_addr(&self) -> PhysAddr {
        PhysAddr(self.0.bit_range(12..52) << 12)
    }

    pub fn is_present(&self) -> bool {
        self.get_flags().unwrap().contains(PML4Flags::P)
    }
}

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

const NUM_PDPE_ENTRIES: usize = 512;

/// Page Table Structure for all hierarchy levels.
///
/// For further information on the paging structures refer to [5.3.3 4-Kbyte Page Translation](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=205) and their
/// Field Definitions [5.4.1 Field Definitions](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=215)
#[repr(transparent)]
pub struct PDPETable {
    pub entries: [PDPEntry; NUM_PDPE_ENTRIES],
}

/// PML3 Entry
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct PDPEntry(pub u64);

impl PDPEntry {
    pub fn new(phys_addr: PhysAddr, flags: PDPFlags) -> Self {
        PDPEntry((phys_addr.0 & PAGE_MASK_4KB) | 0 << 7 | flags.bits())
    }

    pub fn get_flags(&self) -> Option<PDPFlags> {
        let flags = self.0.bit_range(0..6) | (self.0 & 1 << 63);
        PDPFlags::from_bits(flags)
    }

    /// Physical Address of the Paging Structure referenced by this Entry
    ///
    /// The Page Walk itself is done outside this Table since it depends on how paging is
    /// implemented. A direct mapping needs to be handled different to a recursive mapping.
    pub fn get_phys_addr(&self) -> PhysAddr {
        PhysAddr(self.0.bit_range(12..52) << 12)
    }

    pub fn is_present(&self) -> bool {
        self.get_flags().unwrap().contains(PDPFlags::P)
    }
}

bitflags! {
    pub struct PDPFlags: u64 {
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

const NUM_PDE_ENTRIES: usize = 512;

/// Page Table Structure for all hierarchy levels.
///
/// For further information on the paging structures refer to [5.3.3 4-Kbyte Page Translation](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=205) and their
/// Field Definitions [5.4.1 Field Definitions](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=215)
#[repr(transparent)]
pub struct PDETable {
    pub entries: [PDEntry; NUM_PDE_ENTRIES],
}

/// PML2 Entry
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct PDEntry(pub u64);

impl PDEntry {
    pub fn new(phys_addr: PhysAddr, flags: PDFlags) -> Self {
        PDEntry((phys_addr.0 & PAGE_MASK_4KB) | flags.bits())
    }

    pub fn get_flags(&self) -> Option<PDFlags> {
        let flags = self.0.bit_range(0..6) | (self.0 & 1 << 7) | (self.0 & 1 << 63);

        PDFlags::from_bits(flags)
    }

    /// Physical Address of the Paging Structure referenced by this Entry
    pub fn get_phys_addr(&self) -> PhysAddr {
        PhysAddr(self.0.bit_range(12..52) << 12)
    }

    pub fn is_present(&self) -> bool {
        self.get_flags().unwrap().contains(PDFlags::P)
    }

    pub fn maps_large_page(&self) -> bool {
        self.get_flags().unwrap().contains(PDFlags::PS)
    }
}

bitflags! {
    pub struct PDFlags: u64 {
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

        // Page size
        // If set this entry maps a 2-MByte page; otherwise, this entry references a page directory.
        const PS = bit!(7);
        // No Execute
        // When the NX bit
        // is cleared to 0, code can be executed from the mapped physical pages. When the NX bit is set to 1,
        // code cannot be executed from the mapped physical pages.
        // The NX bit can only be set when the no-execute page-protection feature is enabled by setting
        // EFER.NXE to 1.
        const NX = bit!(63);
    }
}

const NUM_PTE_ENTRIES: usize = 512;

/// Page Table Structure for all hierarchy levels.
///
/// For further information on the paging structures refer to [5.3.3 4-Kbyte Page Translation](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=205) and their
/// Field Definitions [5.4.1 Field Definitions](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=215)
#[repr(transparent)]
pub struct PTETable {
    pub entries: [PTEntry; NUM_PTE_ENTRIES],
}

/// PML1 Entry
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct PTEntry(pub u64);

impl PTEntry {
    pub fn new(phys_addr: PhysAddr, flags: PTFlags) -> Self {
        PTEntry((phys_addr.0 & PAGE_MASK_4KB) | flags.bits())
    }

    pub fn get_flags(&self) -> Option<PTFlags> {
        let flags = self.0.bit_range(0..9) | (self.0 & 1 << 63);

        PTFlags::from_bits(flags)
    }

    /// Physical Address of the Paging Structure referenced by this Entry
    ///
    /// The Page Walk itself is done outside this Table since it depends on how paging is
    /// implemented. A direct mapping needs to be handled different to a recursive mapping.
    pub fn get_phys_addr(&self) -> PhysAddr {
        PhysAddr(self.0.bit_range(12..52) << 12)
    }

    pub fn is_present(&self) -> bool {
        self.get_flags().unwrap().contains(PTFlags::P)
    }
}

bitflags! {
    pub struct PTFlags: u64 {
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
        // Dirty
        // y. It
        // indicates whether the physical page to which this entry points has been written. The D bit is set to 1 by
        // the processor the first time there is a write to the physical page. The D bit is never cleared by the
        // processor. Instead, software must clear this bit to 0 when it needs to track the frequency of physicalpage writes.
        const D = bit!(6);
        // Page-Attribute Table
        // This bit is only present in the lowest level of the page-translation
        // hierarchy, as follows:
        // • If the lowest level is a PTE (PDE.PS=0), PAT occupies bit 7.
        // • If the lowest level is a PDE (PDE.PS=1) or PDPE (PDPE.PS=1), PAT occupies bit 12.
        const PAT = bit!(7);
        // Global Page
        // This bit is only present in the lowest level of the page-translation
        // hierarchy. It indicates the physical page is a global page. The TLB entry for a global page (G=1) is not
        // invalidated when CR3 is loaded either explicitly by a MOV CRn instruction or implicitly during a task
        // switch. Use of the G bit requires the page-global enable bit in CR4 to be set to 1 (CR4.PGE=1). See
        // “Global Pages” on page 158 for more information on the global-page mechanism.
        const G = bit!(8);
        // No Execute
        // When the NX bit
        // is cleared to 0, code can be executed from the mapped physical pages. When the NX bit is set to 1,
        // code cannot be executed from the mapped physical pages.
        // The NX bit can only be set when the no-execute page-protection feature is enabled by setting
        // EFER.NXE to 1.
        const NX = bit!(63);
    }
}
