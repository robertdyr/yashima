use core::arch::asm;

/// Raw contents of Cr0 register.
///
/// For further information refer to [3.1.1 Cr0 Register](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=102) in the AMD Manual Volume 2.
pub struct Cr0(pub u64);

impl Cr0 {
    // TODO remove this later for functions that directly query the bits.
    // its no use storing this in main memory since it resides in the registers anyways which is faster
    pub fn new() -> Self {
        let content: u64;
        unsafe {
            asm!("mov {}, cr0", out(reg) content);
        }
        Self(content)
    }
}

/// Raw contents of Cr2 register.
///
/// For further information refer to [3.1.2 Cr2 and Cr3 Registers](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=105) in the AMD Manual Volume 2.
pub struct Cr2(pub u64);

impl Cr2 {
    // TODO remove this later for functions that directly query the bits.
    // its no use storing this in main memory since it resides in the registers anyways which is faster
    pub fn new() -> Self {
        let content: u64;
        unsafe {
            asm!("mov {}, cr2", out(reg) content);
        }
        Self(content)
    }
}

use crate::bit_utils::BitRange;

/// Raw contents of Cr3 register.
///
/// For further information refer to [3.1.2 Cr2 and Cr3 Registers](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=105) in the AMD Manual Volume 2.
pub struct Cr3(pub u64);

impl Cr3 {
    // TODO remove this later for functions that directly query the bits.
    // its no use storing this in main memory since it resides in the registers anyways which is faster
    pub fn read_from() -> Self {
        let content: u64;
        unsafe {
            asm!("mov {}, cr3", out(reg) content);
        }
        Self(content)
    }

    /// Returns the addresse of the PMl4 Table. The addrese omits the last 12 bits since it is 4Kb aligned.
    pub fn get_base_addr(&self) -> u64 {
        self.0.bit_range(12..51)
    }
}

/// Raw contents of Cr4 register.
///
/// For further information refer to [3.1.3 Cr4 Register](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=107) in the AMD Manual Volume 2.
pub struct Cr4(pub u64);

impl Cr4 {
    // TODO remove this later for functions that directly query the bits.
    // its no use storing this in main memory since it resides in the registers anyways which is faster
    pub fn new() -> Self {
        let content: u64;
        unsafe {
            asm!("mov {}, cr4", out(reg) content);
        }
        Self(content)
    }
    pub fn is_pcid(&self) -> bool {
        unimplemented!();
    }
}