#![no_std]
#![no_main]

use core::panic::PanicInfo;

use crate::fontmodule::fontloader::_binary_Uni3_TerminusBold32x16_psf_start;
use fontmodule::fontloader::{Font, PsfHeader};
use limine::framebuffer::Framebuffer;
use limine::request::FramebufferRequest;
use limine::BaseRevision;
mod fontmodule;

static BASE_REVISION: BaseRevision = BaseRevision::new();
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

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

fn n<T>(t: T) {
    let r = t;
}
#[no_mangle]
pub extern "C" fn main() -> ! {
    let mut framebuffer: Framebuffer = FRAMEBUFFER_REQUEST
        .get_response()
        .unwrap()
        .framebuffers()
        .next()
        .unwrap();

    unsafe {
        let mut inputs: [u16; 65535] = [0u16; u16::MAX as usize];

        let header = fontmodule::fontloader::load_file(&mut inputs);
        // let g = fontmodule::fontloader::get_glyph(&header, &inputs, "a".chars().next().unwrap());
        // let glyph = psf_file.get_glyph("a".chars().next().unwrap());
        // draw_letter(&g.bitmap, framebuffer.addr(), 10, 10, framebuffer.pitch());
        // draw_letter_a(framebuffer.addr(), 10, 10, framebuffer.pitch());
        let str = "aaaa";
        // draw_glyph_a(framebuffer.addr(), framebuffer.pitch(), &inputs, header);
        // let fb = framebuffer.addr();
        // let p = framebuffer.pitch();

        // let mut cb = CharBuffer::new(Color::White, framebuffer, 32, 16, 20);

        // cb.draw_glyph_a(fb, p, &inputs, header);
        // cb.write(str, header, &inputs);

        // let psf_start = _binary_Uni3_TerminusBold32x16_psf_start as *const u8 as usize;
        // let font_start_ptr = psf_start + header.headersize as usize;

        // let font = Font::new(font_start_ptr, &inputs);

        let lettera =
            fontmodule::fontloader::get_glyph(&header, &inputs, "a".chars().next().unwrap());
        // let lettera = font.get_glyph2("a".chars().next().unwrap(), header);
        draw_letter(
            Color::White as u32,
            &lettera.bitmap,
            framebuffer.addr(),
            100,
            100,
            framebuffer.pitch(),
        );

        // let mut writer = ScreenWriter::new(Color::White, 0, framebuffer, font);
        // writer.write(str, &header, &inputs);

        // writer.write2("hello world");
        // let mut unicode_table = [0_u16; u16::MAX as usize];
        //
        // fontmodule::fontloader::load_table(&mut unicode_table);
    }
    loop {}
}

fn draw_glyph_a(framebuffer: *mut u8, pitch: u64, table: &[u16], header: PsfHeader) {
    let lettera =
        unsafe { fontmodule::fontloader::get_glyph(&header, table, "a".chars().next().unwrap()) };

    unsafe {
        draw_letter(
            Color::White as u32,
            &lettera.bitmap,
            framebuffer,
            100,
            100,
            pitch,
        );
    }
}

// Function to draw a pixel on the screen
// framebuffer: mutable pointer to the framebuffer base address
// x, y: coordinates of the pixel
// pitch: the number of bytes in a row of pixels
// color: color of the pixel
unsafe fn draw_pixel(framebuffer: *mut u8, x: u64, y: u64, pitch: u64, color: u32) {
    let fb_u32 = framebuffer as *mut u32; // Cast the u8 pointer to a u32 pointer
    let pixel_offset = x + y * (pitch / 4); // Assuming pitch is the number of bytes per row
    fb_u32.offset(pixel_offset as isize).write_volatile(color);
}

// Function to draw the letter "A" on the screen
unsafe fn draw_letter_a(framebuffer: *mut u8, x: u64, y: u64, pitch: u64) {
    // Bitmap representation of the letter "A"
    let letter_a: [u8; 8] = [
        0b00111000, 0b01000100, 0b01000100, 0b01000100, 0b01111100, 0b01000100, 0b01000100,
        0b01000100,
    ];

    // Color of the letter "A" (white)
    let color: u32 = 0xFFFFFF; // RGB color: white

    for (row, &bitmap) in letter_a.iter().enumerate() {
        for col in 0..8 {
            // Check if the bit at the current position is set
            if (bitmap >> (7 - col)) & 1 != 0 {
                draw_pixel(framebuffer, x + col as u64, y + row as u64, pitch, color);
            }
        }
    }
}

unsafe fn draw_letter(
    color: u32,
    letter: &[u16],
    framebuffer: *mut u8,
    x: u64,
    y: u64,
    pitch: u64,
) {
    for (row, &bitmap) in letter.iter().enumerate() {
        for col in 0..16 {
            // Check if the bit at the current position is set
            if (bitmap >> (15 - col)) & 1 != 0 {
                draw_pixel(framebuffer, x + col as u64, y + row as u64, pitch, color);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum Color {
    White = 0xFFFFFF,
}

struct ScreenWriter<'a, 'font_table> {
    background_color: u32,
    color: Color,
    caret: u64,
    framebuffer: Framebuffer<'a>,
    font: Font<'font_table>,
}

impl<'a, 'f> ScreenWriter<'a, 'f> {
    fn new(
        color: Color,
        background_color: u32,
        framebuffer: Framebuffer<'a>,
        font: Font<'f>,
    ) -> Self {
        Self {
            caret: 0,
            color,
            background_color,
            framebuffer,
            font,
        }
    }
    fn clean(&mut self, remove_header: &PsfHeader, remove_table: &[u16]) {}

    fn write(&mut self, str: &str, remove_header: &PsfHeader, remove_table: &[u16]) {
        unsafe {
            for char in str.chars() {
                let g = fontmodule::fontloader::get_glyph(remove_header, remove_table, char);

                draw_letter(
                    self.color as u32,
                    &g.bitmap,
                    self.framebuffer.addr(),
                    self.caret * 16,
                    10,
                    self.framebuffer.pitch(),
                );
                self.caret = self.caret + 1;
            }
        }
    }

    fn write2(&mut self, str: &str) {
        unsafe {
            for char in str.chars() {
                let g = self.font.get_glyph(char);

                draw_letter(
                    self.color as u32,
                    &g.bitmap,
                    self.framebuffer.addr(),
                    self.caret * 16,
                    10,
                    self.framebuffer.pitch(),
                );
                self.caret = self.caret + 1;
            }
        }
    }
}

struct CharBuffer<'a> {
    framebuffer: Framebuffer<'a>,
    charbuffer: [char; 300],
    chars_per_row: u32,
    // will be used to calculate line height
    character_height_px: u32,
    character_width_px: u32,
    color: Color,
    caret: u32,
}

impl<'a> CharBuffer<'a> {
    pub fn new(
        color: Color,
        framebuffer: Framebuffer<'a>,
        character_height_px: u32,
        character_width_px: u32,
        chars_per_row: u32,
    ) -> Self {
        Self {
            color,
            framebuffer,
            character_height_px,
            character_width_px,
            chars_per_row,
            caret: 0,
            charbuffer: [char::from_u32(0x2800).unwrap(); 300],
        }
    }
    pub fn write(&mut self, str: &str, remove_header: PsfHeader, remove_table: &[u16]) {
        for char in str.chars() {
            self.add_character(char, remove_header, remove_table);
        }
    }

    fn add_character(&mut self, char: char, remove_header: PsfHeader, remove_table: &[u16]) {
        self.charbuffer[self.caret as usize] = char;
        self.caret = self.caret + 1;
        unsafe {
            self.render(remove_header, remove_table);
        }
    }

    unsafe fn render(&mut self, remove_header: PsfHeader, remove_table: &[u16]) {
        self.clear_screen();
        for (i, &char) in self.charbuffer.iter().enumerate() {
            let row_index = i as u32 / self.chars_per_row;
            let column_index = i as u32 % self.chars_per_row;

            let g = fontmodule::fontloader::get_glyph(&remove_header, remove_table, char);
            draw_letter(
                self.color as u32,
                &g.bitmap,
                self.framebuffer.addr(),
                (column_index * self.character_width_px) as u64,
                (row_index * self.character_height_px) as u64,
                self.framebuffer.pitch(),
            );
        }
    }

    fn clear_screen(&mut self) {
        for char in self.charbuffer.iter_mut() {
            *char = char::from_u32(0x2800).unwrap();
        }
    }

    pub fn draw_glyph_a(&self, framebuffer: *mut u8, pitch: u64, table: &[u16], header: PsfHeader) {
        let lettera = unsafe {
            fontmodule::fontloader::get_glyph(&header, table, "a".chars().next().unwrap())
        };

        unsafe {
            draw_letter(
                Color::White as u32,
                &lettera.bitmap,
                framebuffer,
                100,
                100,
                pitch,
            );
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {}
}
