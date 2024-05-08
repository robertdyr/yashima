#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::panic::PanicInfo;

use lazy_static::lazy_static;
use limine::BaseRevision;
use limine::framebuffer::Framebuffer;
use limine::memory_map::EntryType;
use limine::paging::Mode;
use limine::request::{FramebufferRequest, HhdmRequest, MemoryMapRequest, PagingModeRequest};
use limine::request::StackSizeRequest;
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use fontmodule::char_buffer::CharBuffer;
use fontmodule::char_buffer::Color;
use fontmodule::font;

use crate::arch::x86_64::control::{Cr3, Cr4};
use crate::arch::x86_64::cpuid::CpuId;

// extern crate rlibc;

mod arch;
mod fontmodule;
mod bit_utils;
mod mem;

#[used]
static BASE_REVISION: BaseRevision = BaseRevision::new();
#[used]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();
#[used]
static PAGE_MODE_REQUEST: PagingModeRequest = PagingModeRequest::new().with_mode(Mode::FOUR_LEVEL);

#[used]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

// Some reasonable size

pub const STACK_SIZE: u64 = 0x1000000;
// Request a larger stack
#[used]
pub static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new().with_size(STACK_SIZE);

#[used]
pub static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[no_mangle]
pub extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) {
    for i in 0..n {
        unsafe {
            *dst.add(i) = *src.add(i);
        }
    }
}

#[no_mangle]
pub extern "C" fn memcmp(
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
) -> core::cmp::Ordering {
    let a_slice = unsafe { core::slice::from_raw_parts(a, a_len) };
    let b_slice = unsafe { core::slice::from_raw_parts(b, b_len) };
    a_slice.cmp(&b_slice)
}

#[no_mangle]
pub extern "C" fn memset(slice: *mut u8, slice_len: usize, value: u8) {
    let slice = unsafe { core::slice::from_raw_parts_mut(slice, slice_len) };
    for element in slice {
        *element = value;
    }
}

use crate::arch::x86_64::paging::PML4Table;

unsafe fn read_pml4table(hhdm_offset: usize, table_phys_addr: usize) -> &'static PML4Table {
    let ptr = hhdm_offset as *const u8;
    let virt_table_addr = unsafe { ptr.offset((table_phys_addr << 12) as isize) } as *const PML4Table;
    let adr = virt_table_addr as usize;
    println!("virt adr: {adr:x}");
    let virt_table_own = &*virt_table_addr;
    virt_table_own
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    unsafe {
        core::ptr::read_volatile(STACK_SIZE_REQUEST.get_response().unwrap());
        let mmap = MEMORY_MAP_REQUEST.get_response().unwrap();
        let (phys_range, virt_range) = mem::get_addr_sizes();

        println!("phys_range {phys_range}");
        println!("virt_range {virt_range}");
        for (i,el) in mmap.entries().iter().enumerate() {
            let is_usable = el.entry_type.eq(&EntryType::USABLE);
            let is_kernel = el.entry_type.eq(&EntryType::KERNEL_AND_MODULES);

            if is_usable {
                //println!("{i} b: {:x?}  l: {:x}", el.base, el.length);
            }

            if is_kernel {
                //println!("{i} b: {:x?}  l: {:x}", el.base, el.length);
            }

        }
        let mode = PAGE_MODE_REQUEST.get_response().unwrap();
        let hhdm_offset = HHDM_REQUEST.get_response().unwrap().offset();
        //println!("hhdm offset is {hhdm_offset:x}");
        let cr3 = Cr3::read_from();
        let phys_base_adr = cr3.get_base_addr();
        //println!("phys_base_adr {phys_base_adr:x}");
        let pml4table = read_pml4table(hhdm_offset as usize, phys_base_adr as usize);
        for entry in pml4table.entries {
            let e = entry.0;
            if e != 0 {
                //println!("entry {e:064b}");
            }
        }

        if mode.mode() == limine::paging::Mode::FOUR_LEVEL {
            // println!("four level");
        } else {
            // println!("five level");
        }
    }
    let info = CpuId::get_cpuid_eax(0x7);
    let ecx = info.ecx;
    // println!("supports {:064b}", ecx);
    // let info = CpuId::get_cpuid_eax_ecx(0x7, 0x0);
    // let ecx = info.ecx;
    // println!("supports {:064b}", ecx);
    init_idt();
    let cr4 = Cr4::new();
    //println!("cr4: {:064b}", cr4.0);
    let cr3 = Cr3::read_from();
    //println!("cr3: {:064b}", cr3.0);
    // let cr4 = Cr4::new();
    // println!("cr4: {:064b}", cr4.0);
    loop {}
    let cr4 = Cr4::new();
    println!("{:b}", cr4.0);

    // x86_64::instructions::interrupts::int3(); // new

    // unsafe {
    //     let cpuid = CpuId::get_cpuid(0x0);
    //     println!("cpuid {:?}", cpuid);
    // }

    // unsafe {
    //     let start = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as usize;
    //     let header = PsfHeader::new(start);
    //     crate::println!("header:  {:?}", header);
    // }
    loop {}
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{:?}", info);
    loop {}
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    loop {}
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    loop {}
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    loop {}
}

pub fn init_idt() {
    IDT.load();
}

lazy_static! {
    static ref CHARBUFFER: Mutex<CharBuffer<'static, 'static>> = unsafe {
        let font = font::Font::from_file();
        let framebuffer: Framebuffer = FRAMEBUFFER_REQUEST
            .get_response()
            .unwrap()
            .framebuffers()
            .next()
            .unwrap();

        let m = Mutex::new(CharBuffer::new(Color::White, framebuffer, 32, 16, 50, font));
        m
    };
}

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);

        // idt.page_fault.set_handler_fn(page_fault_handler);
        idt.device_not_available.set_handler_fn(breakpoint_handler);
        // idt.double_fault.set_handler_fn(double_fault_handler);
        idt
    };
}
