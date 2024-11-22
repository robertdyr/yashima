#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(allocator_api)]
#![feature(strict_provenance)]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{Allocator, GlobalAlloc};
use core::panic::PanicInfo;

use lazy_static::lazy_static;
use limine::framebuffer::Framebuffer;
use limine::paging::Mode;
use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, PagingModeRequest, StackSizeRequest,
};
use limine::BaseRevision;
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use fontmodule::char_buffer::{CharBuffer, Color};
use fontmodule::font;

use crate::arch::x86_64::paging::PhysAddr;
use crate::bit_utils::BitRange;
use crate::mem::bitmap::RawBitmap;
use crate::mem::k_alloc::KAlloc;

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

// contains the address blocks and their attributes in physical memory addresses
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

// static mut dummy_bitmap: [u8; 0] = [];
// // TODO
// // this is a crime. might as well just use rawpointers for the vec to avoud getting into nasty type
// // issues later on but i just wanna get on at this point
// // this all is just a fugazy, just a trick, to get the Allocator type out of the kernel allocator
// // struct. this way i can allocate the bitmap first via the bootstrap allocator and then have the
// // bitmap managed by the kernel allocator later itself by coping the contents into it.
// const HEAP_START: u64 = 0xfffff80000000000;
// static mut permanentn_bitmap: Option<Vec<u8, BootstrapAllocator>> = None;
// #[global_allocator]
// static mut K_ALLOC: KernelAlloc = unsafe {
//     KernelAlloc {
//         heap_adr: HEAP_START,
//         bitmap: Bitmap(&mut dummy_bitmap),
//     }
// };

const MB2: usize = 1 << 21;

// initial allocator
// will be filled once the page bitmap exists and the kernel heap address is known
#[global_allocator]
static mut K_ALLOC: KAlloc<RawBitmap> = unsafe {
    KAlloc {
        heap_start_adr: None,
        heap_size: MB2,
        bitmap: None,
    }
};

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

        let raw_bitmap = mem::bitmap::RawBitmap::new(entries, hhdm_offset);

        K_ALLOC.bitmap = Some(raw_bitmap);

        // let a = 0;
        // let ptr_a: *const usize = &a;
        // println!(" a1 {:x?} ", ptr_a);
        //
        // let b = 0;
        // let ptr_b: *const usize = &b;
        // println!(" b1 {:x?} ", ptr_b);
        //
        // if ptr_b.cmp(&ptr_a).is_lt() {
        //     println!(" downwards ");
        // } else {
        //     println!(" downwards ");
        // }
        //

        // let page = K_ALLOC.bitmap.allocate_continues_4kb_pages(4);
        //
        // match page {
        //     None => {
        //         println!("no page found");
        //     }
        //     Some(page) => {
        //         println!("page: {:?}", page);
        //     }
        // }
        let page = K_ALLOC.bitmap.as_mut().unwrap().allocate_continues_4kb_pages(4);
        match page {
            None => {
                println!("no page found");
            }
            Some(page) => {
                println!("page: {:?}", page);
            }
        }
        let pageu = page.unwrap();
        let page = K_ALLOC.bitmap.as_mut().unwrap().allocate_continues_4kb_pages(4);
        match page {
            None => {
                println!("no page found");
            }
            Some(page) => {
                println!("page: {:?}", page);
            }
        }
        // K_ALLOC.init_kernel_heap();
    }
    // let mut v = Vec::new();
    // v.push(4);
    // v.push(5);

    // println!("vec {:?}", v);
    loop {}
}

fn stackcheck(ptra: *const usize) {
    let a = 0;

    let ptr_a: *const usize = &a;

    let ptr_x = ptr_a as usize - ptra as usize;

    println!(" a2 {:x?} ", ptr_a);
    println!(" x: {:x?}", ptr_x);
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
