use core::arch::asm;

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

pub struct Cr3(pub u64);

impl Cr3 {
    // TODO remove this later for functions that directly query the bits.
    // its no use storing this in main memory since it resides in the registers anyways which is faster
    pub fn new() -> Self {
        let content: u64;
        unsafe {
            asm!("mov {}, cr3", out(reg) content);
        }
        Self(content)
    }
}

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