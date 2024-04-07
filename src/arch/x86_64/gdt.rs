use core::arch::asm;
use core::u16;

// TODO robert refactor this at some point

/// The GdtPointer represents the visible part required by the GDT-Register (GDTR) to
/// locate the [`Gdt`].
///
/// - `limit` is ignored in 64-Bit Mode
/// - `base_adr` is the 64-Bit address of the [`Gdt`]
///
/// The layout and purpose of the GDT Register are detailed in AMD's x86-64 architecture
/// programming manual. For more information, refer to the AMD64 Architecture Programmer's Manual
/// Volume 2: System Programming (PDF), specifically at:
/// [AMD64 Architecture Programmer's Manual, Volume 2, Page 145](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/24593.pdf#page=145).
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct GdtPointer {
    pub limit: u16,
    // TODO test if i can replace this with &'static mut (probably not tho)
    pub base_adr: *mut Gdt,
}

impl GdtPointer {
    /// Allocates a dummy GdtPointer to read the GDT-Registers content into
    /// The 'base_adr' is a null pointer.
    pub fn dummy() -> GdtPointer {
        // limit is ignored
        Self {
            limit: 0,
            base_adr: core::ptr::null_mut(),
        }
    }
    /// Writes the software visible content of the GDT-Register into `gdt_pointer`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it performs raw pointer operations and
    /// requires the caller to ensure that the `gdt_pointer` is valid and can safely
    /// be written to.
    pub unsafe fn get_from_gdt_r(gdt_pointer: &mut GdtPointer) {
        asm!("sgdt [{0}]", in(reg) gdt_pointer as *mut GdtPointer);
    }
}

/// The Global Descriptor Table (Gdt) stores the CS, DS, ES, GS, FS, SS Segment Descriptors ([`SegmentDescriptor`])
/// In long mode most of the segmentation and its features is disabled/ignored. That's why we only store the null-selector required by the
/// processor at index 0, a singular code segment for the required code segment.
///
/// DS, SS, ES are ignored. I do not currently make use ou of the GS and FS.
///
// TODO add source and make sure we really onlly need a singular data segement for all the data segments
// TODO should be aligned on an 8 byte boundary
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
#[allow(unused)]
pub struct Gdt {
    // we only need the null descriptor (first entry) and the cs and ds
    pub entries: [SegmentDescriptor; 6],
}

/// A Segment Descriptor that exists inside the [`Gdt`].
///
/// We effectively on need a singular CS Segment.
///
/// Most of these attributes are ignored in 64-Bit mode or predefined.
/// For more information, refer to the AMD64 Architecture Programmer's Manual
/// Volume 2: System Programming (PDF), specifically at:
/// [AMD64 Architecture Programmer's Manual, Volume 2, Page 158](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=158).
// TODO Add more indpeth documentatin about what fields are of use. Which are always set to a certain value
// add variable parameters into the new() function, but name them here
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct SegmentDescriptor {
    /// lower 4 bytes
    lower: u32,
    /// upper 4 bytes
    upper: u32,
}

impl SegmentDescriptor {
    // TODO move the comments of the variable stuff into proper docs. reference the rest as:
    // as described in [`SegmentDescriptor`]
    pub fn new_cs(dpl: Ring, c: bool) -> SegmentDescriptor {
        // https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=158
        let mut lower = 0;
        let mut upper = 0;
        // in the amd reference we find this sentence:
        // Only the L (long), D (default size), and DPL (descriptor-privilege level) fields are used by the
        // processor in 64-bit mode. All remaining attributes are ignored.
        // this isnt entirely correct as explained in more detail later

        // (D) = 0. If the processor is running in 64-bit mode (L=1), the only valid setting of the D bit is 0. This setting
        // produces a default operand size of 32 bits and a default address size of 64 bits. The combination L=1
        // and D=1 is reserved for future use.

        // Long (L) Attribute Bit. Bit 21 of byte +4. Long mode introduces a new attribute, the long (L) bit, in
        // code-segment descriptors. This bit specifies that the processor is running in 64-bit mode (L=1) or
        // compatibility mode (L=0). When the processor is running in legacy mode, this bit is reserved
        upper = upper | 1 << 21;

        // Present (P) Bit. Bit 15 of the upper double-word. The segment-present bit indicates that the segment
        // referenced by the descriptor is loaded in memory. If a reference is made to a descriptor entry when
        // P = 0, a segment-not-present exception (#NP) occurs. This bit is set and cleared by system software
        // and is never altered by the processor.
        upper = upper | 1 << 15;

        // Descriptor Privilege-Level (DPL) Field. Bits 14:13 of the upper double-word. The DPL field
        // indicates the descriptor-privilege level of the segment. DPL can be set to any value from 0 to 3, with 0
        // specifying the most privilege and 3 the least privilege.
        upper = upper | (dpl as u32) << 13;

        // Conforming (C) Bit. Bit 10 of the upper double-word. Setting this bit to 1 identifies the code segment
        // as conforming. When control is transferred to a higher-privilege conforming code-segment (C=1) from
        // a lower-privilege code segment, the processor CPL does not change. Transfers to non-conforming
        // code-segments (C = 0) with a higher privilege-level than the CPL can occur only through gate
        // descriptors. See “Control-Transfer Privilege Checks” on page 109 for more information on
        // conforming and non-conforming code-segments
        if c {
            upper = upper | 1 << 10;
        }

        // all other fields are ignored in 64 bit long mode
        Self { lower, upper }
    }

    pub fn get_from_cs_r() -> SegmentDescriptor {
        // TODO load cs segment from the cs register
        // asm!("mov {}"),
        core::unimplemented!("not yet implemented");
    }

    pub fn new_ds() -> SegmentDescriptor {
        // TODO i actually think we dont need this at all
        // https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=159
        let mut lower = 0;
        let mut upper = 0;

        // Present (P) Bit. Bit 15 of the upper double-word. The segment-present bit indicates that the segment
        // referenced by the descriptor is loaded in memory. If a reference is made to a descriptor entry when
        // P = 0, a segment-not-present exception (#NP) occurs. This bit is set and cleared by system software
        // and is never altered by the processor.
        upper = upper | 1 << 15;

        // all other fields are ignored in 64 bit long mode
        Self { lower, upper }
    }
    pub fn get_from_ds_r() -> SegmentDescriptor {
        // TODO load ds segment from the ds register
        core::unimplemented!("not yet implemented");
    }
}

/// A lower privilege level is numerically higher.
/// Ring0 is the highest privilege level and the lowest numerically.
/// User Space is handled in Ring3. The kernel is handled in Ring0.
pub enum Ring {
    Ring0 = 0b00,
    Ring1 = 0b01,
    Ring2 = 0b10,
    Ring3 = 0b11,
}

/// Represents a segment selector into the [`Gdt`].
///
/// This struct encapsulates a 16-bit segment selector, as described in the Intel® 64 and IA-32 Architectures Software Developer's Manual, Combined Volumes 3A, 3B, 3C, and 3D: System Programming Guide, specifically on page 99.
///
/// The segment selector is used to select a segment from the Global Descriptor Table (GDT) or the Local Descriptor Table (LDT). It consists of the following fields:
///
/// - `RPL` (Requested Privilege Level): Bits 0 to 1. Specifies the privilege level of the selector.
/// - `TI` (Table Indicator): Bit 2. Indicates the table from which the segment is selected. A value of 0 selects the GDT, and a value of 1 selects the LDT. The LDT is generally not used in modern systems and is not used in this OS.
/// - `Index`: Bits 3 to 15. Specifies the index into the GDT or LDT, identifying the specific segment as offset into the GDT.
#[derive(Clone, Copy, Debug)]
#[warn(dead_code)]
pub struct SegmentSelector(u16);

impl SegmentSelector {
    pub fn new(index: u16, rpl: Ring) -> SegmentSelector {
        // the TI bit is always 0
        SegmentSelector(index << 3 | rpl as u16)
    }
}
