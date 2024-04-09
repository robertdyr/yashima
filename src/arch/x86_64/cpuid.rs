use core::arch::asm;

#[derive(Debug)]
#[repr(C, packed)]
pub struct CpuId {
    eax: u64,
    ebx: u64,
    ecx: u64,
    edx: u64,
}


impl CpuId {
    /// - `eax` is the input that we can give to the CpuId Eax register to query for different information.
    pub fn get_cpuid(eax: u64) -> Self {
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
}