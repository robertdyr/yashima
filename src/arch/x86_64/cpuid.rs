use core::arch::asm;

#[derive(Debug)]
#[repr(C)]
pub struct CpuId {
    pub eax: u64,
    pub ebx: u64,
    pub ecx: u64,
    pub edx: u64,
}


impl CpuId {
    /// - `eax` is the input that we can give to the CpuId Eax register to query for different information.
    pub fn get_cpuid_eax(eax: u64) -> Self {
        let eax_out: u64;
        let ebx_out: u64;
        let ecx_out: u64;
        let edx_out: u64;
        // cpuid writes some info into the rbx register.
        // we are not allowed to clobber the rbx register since LLVM reserves it.
        // we save the rbx, take the value out of it into a 64 bit mode general purpose register, and restore it.
        unsafe {
            asm!(
            "push rbx",
            "cpuid",
            "mov r8, rbx",
            "pop rbx",
            inout("eax") eax => eax_out,
            lateout("r8") ebx_out,
            lateout("ecx") ecx_out,
            lateout("edx") edx_out,
            );
        }
        Self {
            eax: eax_out,
            ebx: ebx_out,
            ecx: ecx_out,
            edx: edx_out,
        }
    }
    pub fn get_cpuid_eax_ecx(eax: u64, ecx: u64) -> Self {
        let eax_out: u64;
        let ebx_out: u64;
        let ecx_out: u64;
        let edx_out: u64;
        // cpuid writes some info into the rbx register.
        // we are not allowed to clobber the rbx register since LLVM reserves it.
        // we save the rbx, take the value out of it into a 64 bit mode general purpose register, and restore it.
        unsafe {
            asm!(
            "push rbx",
            "cpuid",
            "mov r8, rbx",
            "pop rbx",
            inout("eax") eax => eax_out,
            lateout("r8") ebx_out,
            inout("ecx") ecx => ecx_out,
            lateout("edx") edx_out,
            );
        }
        Self {
            eax: eax_out,
            ebx: ebx_out,
            ecx: ecx_out,
            edx: edx_out,
        }
    }
}


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
    let cpuid = CpuId::get_cpuid_eax(0x80000008);
    let phys_range = cpuid.eax.bit_range(0..7);
    let virt_range = cpuid.eax.bit_range(8..15);
    (phys_range, virt_range)
}