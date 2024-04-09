#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::panic::PanicInfo;

use lazy_static::lazy_static;
use limine::BaseRevision;
use limine::framebuffer::Framebuffer;
use limine::request::FramebufferRequest;
use limine::request::StackSizeRequest;
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use fontmodule::char_buffer::CharBuffer;
use fontmodule::char_buffer::Color;
use fontmodule::font;

use crate::arch::x86_64::cpuid::CpuId;

// extern crate rlibc;

mod arch;
mod fontmodule;

static BASE_REVISION: BaseRevision = BaseRevision::new();
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

// Some reasonable size
pub const STACK_SIZE: u64 = 0x1000000;
// Request a larger stack
pub static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new().with_size(STACK_SIZE);

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

#[no_mangle]
pub extern "C" fn main() -> ! {
    init_idt();
    // x86_64::instructions::interrupts::int3(); // new

    unsafe {
        core::ptr::read_volatile(STACK_SIZE_REQUEST.get_response().unwrap());
        let cpuid = CpuId::get_cpuid(0x0);
        println!("cpuid {:?}", cpuid);
    }

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
