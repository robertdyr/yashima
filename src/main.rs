#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(allocator_api)]
#![feature(strict_provenance)]

extern crate alloc;

use core::alloc::{Allocator, GlobalAlloc};
use core::panic::PanicInfo;

use lazy_static::lazy_static;
use limine::BaseRevision;
use limine::framebuffer::Framebuffer;
use limine::paging::Mode;
use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, PagingModeRequest, StackSizeRequest,
};
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use fontmodule::char_buffer::{CharBuffer, Color};
use fontmodule::font;

use crate::arch::x86_64::paging::PhysAddr;
use crate::bit_utils::BitRange;
use crate::mem::bitmap::{Bitmap, create_bitmap};
use crate::mem::DummyAlloc;

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

#[global_allocator]
static GLOBAL: DummyAlloc = DummyAlloc;

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

#[no_mangle]
pub extern "C" fn main() -> ! {
    unsafe {
        core::ptr::read_volatile(STACK_SIZE_REQUEST.get_response().unwrap());
        let mmap = MEMORY_MAP_REQUEST.get_response().unwrap();
        let _mode = PAGE_MODE_REQUEST.get_response().unwrap();
        let hhdm_offset = HHDM_REQUEST.get_response().unwrap();

        let entries = mmap.entries();

        for e in entries {
            if e.base == 0 {
                println!("e: {:?} ", entries.first().unwrap().base);
            }
        }

        let b_alloc = mem::bootstrap_allocator::init_bootstrap_alloc(mmap, hhdm_offset);
        // alloc::boxed::Box::new_in()
        // let mut fun: Vec<u64, BootstrapAllocator> = Vec::with_capacity_in(10, b_alloc);
        // let mut fun: Vec<u64, BootstrapAllocator> = Vec::new_in(b_alloc);
        // fun.push(7);

        let mut bitmap_vec = create_bitmap(mmap.entries(), &b_alloc);
        println!("size: {} ", bitmap_vec.len());
        let bitmap = Bitmap::new(bitmap_vec);
        let first = bitmap.0[0];
        println!("first {first} ");
        let page = bitmap.find_free_4kb_page();
        match page {
            None => {
                println!("no page found");
            }
            Some(page) => {
                println!("page: {:?}", page);
            }
        }

        // println!("phys_range {phys_range}");
        // println!("virt_range {virt_range}");
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
        let font = font::from_file();
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
