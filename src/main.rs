#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(allocator_api)]
#![feature(strict_provenance)]

use core::panic::PanicInfo;
use core::slice;

use lazy_static::lazy_static;
use limine::framebuffer::Framebuffer;
use limine::memory_map::EntryType;
use limine::paging::Mode;
use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, PagingModeRequest, StackSizeRequest,
};
use limine::BaseRevision;
use spin::Mutex;
use x86::bits64::paging;
use x86::bits64::paging::{PDEntry, PDPTEntry, PML4Entry, PTEntry, PML4};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use fontmodule::char_buffer::{CharBuffer, Color};
use fontmodule::font;

use crate::arch::x86_64::control::{Cr3, Cr4};
use crate::arch::x86_64::cpuid::CpuId;

// extern crate rlibc;
// extern crate alloc;
mod arch;
mod bit_utils;
mod fontmodule;
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

pub const STACK_SIZE: u64 = 0x2000000;
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

use crate::arch::x86_64::paging::{
    PDETable, PDFlags, PDPETable, PDPFlags, PML4Flags, PML4Table, PTETable, PTFlags, PhysAddr,
};
use crate::bit_utils::BitRange;

unsafe fn read_pml4table(hhdm_offset: usize, table_phys_addr: usize) -> &'static PML4Table {
    let ptr = hhdm_offset as *const u8;
    let virt_table_addr =
        unsafe { ptr.offset((table_phys_addr << 12) as isize) } as *const PML4Table;
    let adr = virt_table_addr as usize;
    println!("virt adr: {adr:064b}   {adr:x}");
    let virt_table_own = &*virt_table_addr;
    virt_table_own
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    unsafe {
        core::ptr::read_volatile(STACK_SIZE_REQUEST.get_response().unwrap());
        let mmap = MEMORY_MAP_REQUEST.get_response().unwrap();
        let (phys_range, virt_range) = arch::x86_64::cpuid::get_addr_sizes();
        // alloc::boxed::Box::new_in()
        // println!("phys_range {phys_range}");
        // println!("virt_range {virt_range}");
        let _mode = PAGE_MODE_REQUEST.get_response().unwrap();
        let hhdm_offset = HHDM_REQUEST.get_response().unwrap().offset();

        let c3 = x86::controlregs::cr3();

        let cr3 = Cr3::read_from();

        let base_adr_pml4_x86 = c3.bit_range(12..52);

        let phys_base_adr = cr3.get_base_addr();
        let pml4_phys_adr = PhysAddr::new(phys_base_adr);

        let mut pages_count: u64 = 0;
        let mut pt_tables_count: u64 = 0;
        let mut pd_tables_count: u64 = 0;
        let mut pdp_tables_count: u64 = 0;

        let mut large_2mb_pages: u64 = 0;
        let mut small_4kb_pages: u64 = 0;

        let mut first_non_p_page = false;

        let mut page_until_first_non_present = 0;

        let pml4table = resolve_hhdm::<PML4Table>(&pml4_phys_adr, hhdm_offset);

        // let o = 0xffff800100000000;
        let o: usize = 0xffff800010000000;
        let ptr = o as *const u8;
        let idk = *ptr;
        let mut phys_adr_last_mapped_page: u64 = 0;

        println!(" idk {idk} ");
        for (i, entry) in pml4table.entries.iter().enumerate() {
            if entry.is_present() && i == 256 {
                println!(" i: {:x} f: {:064b}", 256, entry.0);

                pdp_tables_count = pdp_tables_count + 1;
                let adr = entry.get_phys_addr();
                let pdpe_table = resolve_hhdm::<PDPETable>(&adr, hhdm_offset);

                for entry in pdpe_table.entries {
                    if entry.is_present() {
                        pd_tables_count = pd_tables_count + 1;
                        let adr = entry.get_phys_addr();
                        let pde_table = resolve_hhdm::<PDETable>(&adr, hhdm_offset);
                        if entry.0 & 1 << 7 != 0 {
                            panic!("should always be 0");
                        }

                        for entry in pde_table.entries {
                            if entry.is_present() {
                                pt_tables_count = pt_tables_count + 1;
                                if entry.maps_large_page() {
                                    large_2mb_pages = large_2mb_pages + 1;
                                    println!(" x: {:x}", entry.get_phys_addr().0)
                                } else {
                                    small_4kb_pages = small_4kb_pages + 1;

                                    let adr = entry.get_phys_addr();
                                    let pte_table = resolve_hhdm::<PTETable>(&adr, hhdm_offset);
                                    for entry in pte_table.entries {
                                        if entry.is_present() {
                                            pages_count = pages_count + 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        println!(" total_pde_c: {pt_tables_count}");
        println!(" 2mb_pages_c: {large_2mb_pages}");
        println!(" 4kb_pages_c: {small_4kb_pages}");
        // println!(" pt_tabs_c: {pt_tables_count}");
        // println!(" pages_c: {pages_count}");
    }
    loop {}
}

unsafe fn resolve_hhdm<T>(addr: &PhysAddr, hhdm_offset: u64) -> &T {
    let virt_ptr = addr.raw_mut::<u8>().offset(hhdm_offset as isize);

    let r = virt_ptr as *mut T;
    &(*r)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{:?}", info);
    loop {}
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    loop {}
}
extern "x86-interrupt" fn err_code(stack_frame: InterruptStackFrame, err_code: u64) {
    println!("err");
    loop {}
}
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    println!("pg");
    loop {}
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    println!("df");
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
        idt.general_protection_fault.set_handler_fn(err_code);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.device_not_available.set_handler_fn(breakpoint_handler);
        idt.alignment_check.set_handler_fn(err_code);
        idt.security_exception.set_handler_fn(err_code);
        idt.bound_range_exceeded.set_handler_fn(breakpoint_handler);
        idt.cp_protection_exception.set_handler_fn(err_code);
        idt.double_fault.set_handler_fn(double_fault_handler);
        idt
    };
}
