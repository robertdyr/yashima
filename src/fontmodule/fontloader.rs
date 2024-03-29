extern "C" {
    pub static _binary_Uni3_TerminusBold32x16_psf_start: u8;
    static _binary_Uni3_TerminusBold32x16_psf_end: u8;
}

pub unsafe fn load_file(input: &mut [u16]) -> PsfHeader {
    let start = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as usize;
    let end = &_binary_Uni3_TerminusBold32x16_psf_end as *const u8 as usize;

    let psf_header = PsfHeader::new(start);

    let table_start =
        (psf_header.bytesperglyph * psf_header.numglpyh + psf_header.headersize) as usize + start;
    PsfTable::new(table_start as usize, end - table_start, input);

    psf_header
}

#[derive(Debug)]
pub struct Glyph {
    pub bitmap: [u16; 32],
}

impl Glyph {
    /// Converts the 64 Byte array in the PSF file into the Glyph.
    /// The PSF stores the Glyphs Bitmap as a continues 64 Byte array.
    fn from_u8_slice(bytes: &[u8]) -> Self {
        let mut bitmap = [0_u16; 32];
        let mut i = 0;
        while i < bitmap.len() {
            let first_byte = bytes[i * 2];
            let second_byte = bytes[i * 2 + 1];
            bitmap[i] = ((first_byte as u16) << 8) + (second_byte as u16);
            i = i + 1;
        }
        Glyph { bitmap }
    }
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
            0
            // TODO panic here
            // panic!("not a valid UTF-8 or i was too lazy to implement the missing option!");
        }
    }
}
pub unsafe fn get_glyph(psf_header: &PsfHeader, psf_table: &[u16], char: char) -> Glyph {
    let start = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8;

    let offset = psf_table[char as usize] as u32 * psf_header.bytesperglyph as u32 as u32
        + psf_header.headersize;
    let bitmap_bytes = *(start.offset(offset as isize) as *const [u8; 64]);
    let mut copy = [0u8; 64];
    for (c, o) in copy.iter_mut().zip(bitmap_bytes) {
        *c = o;
    }
    Glyph::from_u8_slice(&copy)
}

pub struct Font<'a> {
    psf_table: &'a [u16],
    glyph_map_ptr: usize,
}

impl<'a> Font<'a> {
    pub fn new(glyph_map_ptr: usize, psf_table: &'a [u16]) -> Self {
        Font {
            glyph_map_ptr,
            psf_table,
        }
    }
    /// Retrieves the Glyph out of the PSF allocated memory.
    pub unsafe fn get_glyph(&self, char: char) -> Glyph {
        let offset = self.psf_table[char as usize] as usize;
        let glyph_ptr = (self.glyph_map_ptr + offset) as *const u8;
        let bytes = core::slice::from_raw_parts(glyph_ptr, 64);

        Glyph::from_u8_slice(&bytes)
    }
    pub unsafe fn get_glyph2(&self, char: char, header: PsfHeader) -> Glyph {
        let start = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8;

        let offset = self.psf_table[char as usize] as u32 * header.bytesperglyph as u32 as u32
            + header.headersize;
        let bitmap_bytes = &*(start.offset(offset as isize) as *const [u8; 64]);
        Glyph::from_u8_slice(bitmap_bytes)
    }
}

pub struct PsfFile {
    start: *const u8,
    psf_header: &'static PsfHeader,
    // psf_table: PsfTable,
    psf_table: &'static [u16],
}

impl PsfFile {
    // pub unsafe fn new(start: usize, end: usize, psf_table: &[u16]) -> Self {
    //     let psf_header = PsfHeader::new(start);
    //     PsfFile { psf_header }
    // }
    pub unsafe fn get_glyph(&self, char: char) -> Glyph {
        let offset = self.psf_table[char as usize] as u32
            * self.psf_header.bytesperglyph as u32 as u32
            + self.psf_header.headersize;
        let bitmap_bytes = &*(self.start.offset(offset as isize) as *const [u8; 64]);
        Glyph::from_u8_slice(bitmap_bytes)
    }
}

struct PsfTable {
    table: [u16; u16::MAX as usize],
}

impl PsfTable {
    pub unsafe fn new(start: usize, size: usize, itable: &mut [u16]) {
        // let mut table = Self {
        //     table: [0u16; u16::MAX as usize],
        // };
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
                    0
                    // TODO panic here
                    // panic!("shouldn't exist");
                };
                itable[unicode as usize] = i as u16;
            }
        }
        // table
    }

    fn get_glyph_index(self, char: char) -> u16 {
        self.table[char as usize]
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
    bytesperglyph: u32,
    height: u32,
    width: u32,
}

impl PsfHeader {
    pub unsafe fn new(start: usize) -> Self {
        let header_ptr = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as *const PsfHeader;
        *header_ptr
    }
}
