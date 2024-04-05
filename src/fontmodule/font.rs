use crate::Color;

extern "C" {
    pub static _binary_Uni3_TerminusBold32x16_psf_start: u8;
    pub static _binary_Uni3_TerminusBold32x16_psf_end: u8;
}

trait ToUnicode {
    fn to_unicode(&self) -> u16;
}

impl ToUnicode for [u8] {
    fn to_unicode(&self) -> u16 {
        if self[0] >> 5 == 0b110 {
            (((self[0] & 0b0011_1111) as u16) << 6) + ((self[1] & 0b0011_1111) as u16)
        } else if self[0] >> 4 == 0b1110 {
            (((self[0] & 0b0000_1111) as u16) << 12)
                + (((self[1] & 0b001_11111) as u16) << 6)
                + ((self[2] & 0b0011_1111) as u16)
        } else if self[0] >> 7 == 0b0 {
            (self[0] & 0b0111_1111) as u16
        } else {
            // TODO implement
            panic!("not a valid UTF-8 or i was too lazy to implement the missing option!");
        }
    }
}

type Bitmap_t = [u8; 64];

#[derive(Debug)]
pub struct Glyph<'a> {
    height_px: u32,
    width_px: u32,
    pub bitmap: &'a Bitmap_t,
}

#[repr(C, packed)]
pub struct BitmapTable<'a> {
    map: &'a [Bitmap_t],
}

impl<'a> BitmapTable<'a> {
    /// ```start``` is the start where the glyph bitmaps in the psf file are stored (psf file start + header size)
    pub unsafe fn new(start: usize) -> Self {
        Self {
            map: core::slice::from_raw_parts(start as *const Bitmap_t, 512),
        }
    }
}

pub struct UnicodeTable {
    table: [u16; u16::MAX as usize],
}

impl UnicodeTable {
    /// - ```start``` is start of the mapping table (psf file start + headersize + glpyhsize * bytes per glypth)
    /// - ```size``` is used to know the end of the table (psf file end - ```start```)
    pub unsafe fn new(start: usize, size: usize) -> Self {
        let mut unicode_table = Self {
            table: [0u16; u16::MAX as usize],
        };
        let psf_unicode_table = core::slice::from_raw_parts(start as *const u8, size);

        for (i, codes) in psf_unicode_table.split(|byte| *byte == 0xFF).enumerate() {
            let mut byte = 0;
            while byte < codes.len() {
                let unicode: u16 = if codes[byte] >> 5 == 0b110 {
                    let unicode = codes[byte..byte + 2].to_unicode();
                    byte = byte + 2;
                    unicode
                } else if codes[byte] >> 4 == 0b1110 {
                    let unicode = codes[byte..byte + 3].to_unicode();
                    byte = byte + 3;
                    unicode
                } else if codes[byte] >> 7 == 0b0 {
                    let unicode = codes[byte..byte + 1].to_unicode();
                    byte = byte + 1;
                    unicode
                } else {
                    // TODO implement
                    panic!("not a valid UTF-8 or i was too lazy to implement the missing option!");
                };
                unicode_table.table[unicode as usize] = i as u16;
            }
        }
        unicode_table
    }
}

pub struct Font<'a> {
    // maps unicode to Bitmap. unicode is index into BitmapTable
    bitmap_table: BitmapTable<'a>,
    // maps unicode to index into `bitmap_table` for the glyph
    unicode_table: UnicodeTable,
    height_px: u32,
    width_px: u32,
}

impl<'a> Font<'a> {
    pub unsafe fn from_file() -> Self {
        let start = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as usize;
        let end = &_binary_Uni3_TerminusBold32x16_psf_end as *const u8 as usize;

        let psf_header = PsfHeader::new(start);
        let bitmap_table = BitmapTable::new(start + psf_header.headersize as usize);
        let unicode_table_start =
            start + psf_header.headersize as usize + (psf_header.bytesperglyph * 512) as usize;
        let unicode_table = UnicodeTable::new(unicode_table_start, end - unicode_table_start);
        Font::new(
            psf_header.height,
            psf_header.width,
            bitmap_table,
            unicode_table,
        )
    }

    pub fn new(
        height_px: u32,
        width_px: u32,
        bitmap_table: BitmapTable<'a>,
        unicode_table: UnicodeTable,
    ) -> Self {
        Font {
            height_px,
            width_px,
            bitmap_table,
            unicode_table,
        }
    }

    pub fn get_glyph(&self, char: char) -> Glyph {
        Glyph {
            height_px: self.height_px,
            width_px: self.height_px,
            bitmap: &self.bitmap_table.map[self.unicode_table.table[char as usize] as usize],
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct PsfHeader {
    magic: u32,
    version: u32,
    pub headersize: u32,
    flags: u32,
    numglpyh: u32,
    pub bytesperglyph: u32,
    pub height: u32,
    pub width: u32,
}

impl PsfHeader {
    /// ```start``` of the psf header (this is also the start of the psf file)
    pub unsafe fn new(start: usize) -> Self {
        let header_ptr = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as *const PsfHeader;
        *header_ptr
    }
}

// TODO robert move to different file
pub unsafe fn draw_letter(bitmap: &Bitmap_t, framebuffer: *mut u8, x: u64, y: u64, pitch: u64) {
    let color = Color::White as u32;
    let background_color = Color::Black as u32;

    for row in 0..32 {
        let first_byte = bitmap[row * 2];
        let second_byte = bitmap[row * 2 + 1];
        for col in 0..8 {
            if (first_byte >> (7 - col)) & 1 != 0 {
                draw_pixel(framebuffer, x + col as u64, y + row as u64, pitch, color);
            } else {
                draw_pixel(
                    framebuffer,
                    x + col as u64,
                    y + row as u64,
                    pitch,
                    background_color,
                );
            }
            if (second_byte >> (7 - col)) & 1 != 0 {
                draw_pixel(
                    framebuffer,
                    x + col + 8u64,
                    y + row as u64,
                    pitch,
                    color,
                );
            } else {
                draw_pixel(
                    framebuffer,
                    x + col + 8 as u64,
                    y + row as u64,
                    pitch,
                    background_color,
                );
            }
        }
    }
}

// TODO robert move to different file
unsafe fn draw_pixel(framebuffer: *mut u8, x: u64, y: u64, pitch: u64, color: u32) {
    let fb_u32 = framebuffer as *mut u32; // Cast the u8 pointer to a u32 pointer
    let pixel_offset = x + y * (pitch / 4); // Assuming pitch is the number of bytes per row
    fb_u32.offset(pixel_offset as isize).write_volatile(color);
}
