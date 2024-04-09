use core::arch::asm;

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