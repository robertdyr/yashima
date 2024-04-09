use core::arch::asm;

pub struct Cr3(pub u64);

impl Cr3 {
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