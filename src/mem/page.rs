use crate::arch::x86_64::control::Cr3;
use crate::arch::x86_64::paging::{PDPTable, PDTable, PML4Table, PTable, PhysAddr};
use crate::{bit, resolve_hhdm};

#[derive(Copy, Clone, Debug)]
pub enum PageSize {
    KB4 = 1 << 12,
    MB2 = 1 << 21,
}

#[derive(Copy, Clone, Debug)]
pub struct Page {
    pub start: usize,
    pub size: PageSize,
}

impl Page {
    pub fn new(start: usize, size: PageSize) -> Self {
        Page { start, size }
    }
}

// TODO remove this and make it not arch dependant. this is just a dumping ground rn
unsafe fn page_walk_arch_x86_64(hhdm_offset: u64) {
    let cr3 = Cr3::read_from();

    let phys_base_adr = cr3.get_base_addr();
    let pml4_phys_adr = PhysAddr::new(phys_base_adr);

    let pml4table = resolve_hhdm::<PML4Table>(&pml4_phys_adr, hhdm_offset);

    for entry in pml4table.entries {
        if entry.is_present() {
            let adr = entry.get_phys_addr();
            let pdpe_table = resolve_hhdm::<PDPTable>(&adr, hhdm_offset);

            for entry in pdpe_table.entries {
                if entry.is_present() {
                    let adr = entry.get_phys_addr();
                    let pde_table = resolve_hhdm::<PDTable>(&adr, hhdm_offset);
                    if entry.0 & bit!(7) != 0 {
                        panic!("should always be 0");
                    }

                    for entry in pde_table.entries {
                        if entry.is_present() {
                            if entry.maps_large_page() {
                            } else {
                                let adr = entry.get_phys_addr();
                                let pte_table = resolve_hhdm::<PTable>(&adr, hhdm_offset);
                                for entry in pte_table.entries {
                                    if entry.is_present() {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn calc_4kb_page_count(mem_available: u64) -> u64 {
    let kb4 = PageSize::KB4 as u64;

    // overshoot is the amount of memory at the very "top" of the memory doesnt doesnt fill an
    // entire 4kb page
    let overshoot = mem_available % kb4;
    let highest_aligned_addr = if overshoot == 0 {
        mem_available
    } else {
        // round down to last full page
        mem_available - overshoot
    };

    highest_aligned_addr / kb4
}
