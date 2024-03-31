#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::{char, panic::PanicInfo};

use limine::request::FramebufferRequest;
use limine::BaseRevision;
use limine::{framebuffer::Framebuffer, request::EfiMemoryMapRequest};
mod fontmodule;

// extern crate rlibc;

static BASE_REVISION: BaseRevision = BaseRevision::new();
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

use limine::request::StackSizeRequest;

use font::{_binary_Uni3_TerminusBold32x16_psf_end, _binary_Uni3_TerminusBold32x16_psf_start};
use fontmodule::font;

// Some reasonable size
pub const STACK_SIZE: u64 = 0x1000000;
// Request a larger stack
pub static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new().with_size(STACK_SIZE);

#[no_mangle]
pub extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) {
    // unsafe {
    //     draw_letter_a(fr_addr as *mut u8, 100, 100, fr_pitch);
    // }
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
    }

    unsafe {
        let mut framebuffer: Framebuffer = FRAMEBUFFER_REQUEST
            .get_response()
            .unwrap()
            .framebuffers()
            .next()
            .unwrap();

        let start = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as usize;
        let end = &_binary_Uni3_TerminusBold32x16_psf_end as *const u8 as usize;

        // ========================================================================
        // ========================================================================
        // ========================================================================
        // ========================================================================

        let psf_header = font::PsfHeader::new(start);
        let bitmap_map = font::BitmapTable::new(start + psf_header.headersize as usize);
        let unicode_map_start =
            start + psf_header.headersize as usize + (psf_header.bytesperglyph * 512) as usize;
        let unicode_map = font::UnicodeTable::new(unicode_map_start, end - unicode_map_start);
        let b_font = font::Font::new(psf_header.height, psf_header.width, bitmap_map, unicode_map);
        unsafe {
            let mut cb = CharBuffer::new(Color::White, framebuffer, 32, 16, 50, b_font);

            cb.write("hello, world! hello hello\nhello hello");

            cb.clear_buffer();

            cb.write("cleared");

            // crate::draw_letter_a(framebuffer.addr(), 10, 10, framebuffer.pitch());
        }
    }
    loop {}
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum Color {
    White = 0xFFFFFF,
    Black = 0x0,
}

struct CharBuffer<'a, 'b> {
    framebuffer: Framebuffer<'a>,
    charbuffer: [char; 3000],
    chars_per_row: u32,
    // will be used to calculate line height
    character_height_px: u32,
    character_width_px: u32,
    color: Color,
    caret: u32,
    font: font::Font<'b>,
}

impl<'a, 'b> CharBuffer<'a, 'b> {
    pub fn new(
        color: Color,
        framebuffer: Framebuffer<'a>,
        character_height_px: u32,
        character_width_px: u32,
        chars_per_row: u32,
        font: font::Font<'b>,
    ) -> Self {
        Self {
            color,
            framebuffer,
            character_height_px,
            character_width_px,
            chars_per_row,
            caret: 0,
            // empty glyph
            charbuffer: ['\u{020}'; 3000],
            font,
        }
    }
    pub fn write(&mut self, str: &str) {
        for char in str.chars() {
            match char {
                '\n' => self.new_line(),
                _ => self.add_character(char),
            }
        }
        unsafe {
            self.render();
        }
    }

    pub fn clear_buffer(&mut self) {
        for char in self.charbuffer.iter_mut() {
            // empty char
            *char = '\u{020}';
        }
        self.caret = 0;
    }

    fn add_character(&mut self, char: char) {
        self.charbuffer[self.caret as usize] = char;
        self.caret = self.caret + 1;
    }

    unsafe fn render(&mut self) {
        self.clear_screen();
        for (i, &char) in self.charbuffer.iter().enumerate() {
            let row_index = i as u32 / self.chars_per_row;
            let column_index = i as u32 % self.chars_per_row;

            let g = self.font.get_glyph(char);

            font::draw_letter(
                g.bitmap,
                self.framebuffer.addr(),
                (column_index * self.character_width_px) as u64,
                (row_index * self.character_height_px) as u64,
                self.framebuffer.pitch(),
            );
        }
    }

    fn new_line(&mut self) {
        self.caret = (self.caret / self.chars_per_row) + self.chars_per_row;
    }

    fn clear_screen(&mut self) {
        let empty_char = self.font.get_glyph('\u{020}');

        for i in 0..self.charbuffer.iter().len() {
            let row_index = i as u32 / self.chars_per_row;
            let column_index = i as u32 % self.chars_per_row;

            unsafe {
                font::draw_letter(
                    empty_char.bitmap,
                    self.framebuffer.addr(),
                    (column_index * self.character_width_px) as u64,
                    (row_index * self.character_height_px) as u64,
                    self.framebuffer.pitch(),
                );
            }
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {}
}

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

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

use lazy_static::lazy_static;
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
