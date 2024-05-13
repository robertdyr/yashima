use crate::arch::x86_64::control::Cr3;
use crate::arch::x86_64::paging::{PDPTable, PDTable, PhysAddr, PML4Table, PTable};
use crate::resolve_hhdm;

pub struct Page4Kb {
    index: usize,
}

impl Page4Kb {
    pub fn new(index: usize) -> Self {
        Page4Kb { index }
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
                    if entry.0 & 1 << 7 != 0 {
                        panic!("should always be 0");
                    }

                    for entry in pde_table.entries {
                        if entry.is_present() {
                            if entry.maps_large_page() {} else {
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