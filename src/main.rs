#![no_std]
#![no_main]

use core::panic::PanicInfo;

use limine::BaseRevision;
use limine::framebuffer::Framebuffer;
use limine::request::FramebufferRequest;

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
pub extern "C" fn memset(slice: &mut [u8], value: u8) {
    for elem in slice.iter_mut() {
        *elem = value;
    }
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    let mut framebuffer: Framebuffer = FRAMEBUFFER_REQUEST.get_response().unwrap().framebuffers().next().unwrap();

    unsafe {
        let psf_file = fontmodule::fontloader::load_file();
        let glyph = psf_file.get_glyph("a".chars().next().unwrap());
        draw_letter(&glyph.bitmap, framebuffer.addr(), 10, 10, framebuffer.pitch());
        draw_letter_a(framebuffer.addr(), 10, 10, framebuffer.pitch());
        // let mut unicode_table = [0_u16; u16::MAX as usize];
        //
        // fontmodule::fontloader::load_table(&mut unicode_table);
    }
    loop {}
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
        0b00111000,
        0b01000100,
        0b01000100,
        0b01000100,
        0b01111100,
        0b01000100,
        0b01000100,
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


unsafe fn draw_letter(letter: &[u16], framebuffer: *mut u8, x: u64, y: u64, pitch: u64) {
    // Bitmap representation of the letter "A"
    let letter_a: [u8; 8] = [
        0b00111000,
        0b01000100,
        0b01000100,
        0b01000100,
        0b01111100,
        0b01000100,
        0b01000100,
        0b01000100,
    ];

    // Color of the letter "A" (white)
    let color: u32 = 0xFFFFFF; // RGB color: white

    for (row, &bitmap) in letter.iter().enumerate() {
        for col in 0..16 {
            // Check if the bit at the current position is set
            if (bitmap >> (15 - col)) & 1 != 0 {
                draw_pixel(framebuffer, x + col as u64, y + row as u64, pitch, color);
            }
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {}
}
