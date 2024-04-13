use crate::arch::x86_64::gdt::{Ring, SegmentSelector};

// TODO i should be able to align this when allocating since the bootloader im using doesnt allocate it (i think)
// and if it does i can just replace it
#[repr(align(16))]
struct Idt([GateDescriptor]);

/// This struct encapsulates a 64-bit gate descriptor for long mode.
/// Gate Descriptors in Long mode are either Interrupt Gates or trap Gates. Task Gates are not supported.
///
/// TODO add the fields here maybe? or just ascii art for the fields
///
/// For more information refer to the Intel® 64 and IA-32 Architectures Software Developer's Manual, Combined Volumes 3A, 3B, 3C, and 3D: System Programming Guide, specifically on page 233.
/// alternative source: https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=161
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct GateDescriptor {
    // first part of the offset, low bytes 0-15
    offset_low: u16,
    // this should be a code segment which is used in long mode to verify privilege level
    selector: SegmentSelector,
    // contains: IST (interrupt stack table), some set bits, TYPE, DPL, P, etc.
    attributes: GateAttributes,
    // offset in the second word, middle bytes 16-31
    offset_middle: u16,
    // offset in the third word for long mode addresses, high bytes 32-63
    offset_high: u32,
    // explicitly reserved
    reserved: u32,
}

impl GateDescriptor {
    /// The 'offset' is the 64 bit address of the Interrupt Handler.
    /// The 'selector' should be a Code Segment Selector in the GDT.
    pub fn new(offset: u64, selector: SegmentSelector) -> GateDescriptor {
        let offset_low: u16 = (offset & 0xFFFF) as u16;
        let offset_middle: u16 = ((offset >> 16) & 0xFFFF) as u16;
        let offset_high: u32 = ((offset >> 32) & 0xFFFFFFFF) as u32;
        let attributes = GateAttributes::new();

        Self {
            offset_low,
            selector,
            attributes,
            offset_middle,
            offset_high,
            reserved: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct GateAttributes(u16);

impl GateAttributes {
    // amd reference
    // Setting the gate DPL=3 and interrupt-handler code-segment DPL=0 makes the
    // exception handler or interrupt handler reachable from any privilege level.
    pub fn new(ist: Ist, gate_type: GateDescriptorType, dpl: Ring) -> GateAttributes {
        // TODO implement this, figure out what the ist is
        // Bit 0-2 is the IST (interrupt stack table)
        // Bit 3-7 are 0's
        // Bit 8-11 are the TYPE
        // Bit 12 is 0
        // Bit 13-14 is the DPL (descriptor privilege level)
        // Bit P is present bit (probably set by the processor again and not by me)
        Self {}
    }
}


/// TODO Interrupt Stack Table
struct Ist {}

/// https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf#page=160
enum GateDescriptorType {
    Interrupt = 0b1110,
    Trap = 0b1111,
}
