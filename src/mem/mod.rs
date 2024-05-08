pub mod bootstrap_allocator;

use crate::bit_utils::BitRange;

/// Returns the processors supported physical address size and current virtual address size as
/// (phys_range, virt_range)
///
/// [source](https://www.felixcloutier.com/x86/cpuid)
///
/// * EAX Linear/Physical Address size. Bits 07-00: #Physical Address Bits*. Bits 15-08: #Linear
///   Address Bits. Bits 31-16: Reserved = 0.
/// * EBX Bits 08-00: Reserved = 0. Bit 09: WBNOINVD is available if 1. Bits 31-10: Reserved = 0.
/// * ECX Reserved = 0. EDX Reserved = 0.
///
/// NOTES: * IfCPUID.80000008H:EAX[7:0]issupported,themaximumphysicaladdressnumbersupportedshould
/// come from this field. If TME-MK is enabled, the number of bits that can be used to address
/// physical memory is CPUID.80000008H:EAX[7:0] - IA32_TME_ACTIVATE[35:32].
pub fn get_addr_sizes() -> (u64, u64) {
    let cpuid = crate::arch::x86_64::cpuid::CpuId::get_cpuid_eax(0x80000008);
    let phys_range = cpuid.eax.bit_range(0..7);
    let virt_range = cpuid.eax.bit_range(8..15);
    (phys_range, virt_range)
}
