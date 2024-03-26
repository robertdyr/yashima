extern "C" {
    static _binary_Uni3_TerminusBold32x16_psf_start: u8;
    static _binary_Uni3_TerminusBold32x16_psf_end: u8;
}

pub unsafe fn load_file() -> PsfFile {
    let start = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as usize;
    let end = &_binary_Uni3_TerminusBold32x16_psf_end as *const u8 as usize;

    let psf_header = PsfHeader::new(start);

    let psf_table = PsfTable::new(start, end - start);

    let psf_file = PsfFile {
        start: &_binary_Uni3_TerminusBold32x16_psf_start as *const u8,
        psf_header,
        psf_table,
    };

    psf_file
}

pub unsafe fn load_table(unicode_table: &mut [u16]) {
    let start = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as usize;
    let end = &_binary_Uni3_TerminusBold32x16_psf_end as *const u8 as usize;

    let header_ptr = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as *const PsfHeader;
    //let header_ptr = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as *const PsfHeader;
    #[allow(invalid_reference_casting)]
        let header = &*header_ptr;
    // println!("{:?}", header);

    let mut psf_table_start =
        start + header.headersize as usize + (header.bytesperglyph * header.numglpyh) as usize;

    let psf_table_size = end - psf_table_start;

    let psf_unicode_table =
        core::slice::from_raw_parts(psf_table_start as *const u8, psf_table_size);

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
            unicode_table[unicode as usize] = i as u16;
        }
    }
}


pub struct Glyph {
    pub bitmap: [u16; 32],
}

impl Glyph {
    fn from_u8_slice(bytes: &[u8]) -> Self {
        let mut bitmap = [0_u16; 32];
        let i = 0;
        while i < bitmap.len() {
            let first_byte = bytes[i * 2];
            let second_byte = bytes[i * 2 + 1];
            bitmap[i] = first_byte as u16 + (second_byte as u16) << 8;
        }

        Glyph {
            bitmap
        }
    }
}

trait ToUnicode {
    fn to_unicode(self) -> u16;
}

impl ToUnicode for &[u8] {
    fn to_unicode(self) -> u16 {
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

pub struct PsfFile {
    start: *const u8,
    psf_header: &'static PsfHeader,
    psf_table: PsfTable,
}

impl PsfFile {
    pub unsafe fn get_glyph(self, char: char) -> Glyph {
        let offset = (self.psf_table.get_glyph_index(char) as u32 * self.psf_header.bytesperglyph as u32) as u32 + self.psf_header.headersize;
        let bitmap_bytes = &*(self.start.offset(offset as isize) as *const [u8; 64]);
        Glyph::from_u8_slice(bitmap_bytes)
    }
}

struct PsfTable {
    table: [u16; u16::MAX as usize],
}

impl PsfTable {
    pub unsafe fn new(start: usize, size: usize) -> Self {
        let mut table = Self { table: [0u16; u16::MAX as usize] };
        let psf_unicode_table =
            core::slice::from_raw_parts(start as *const u8, size);

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
                table.table[unicode as usize] = i as u16;
            }
        }
        table
    }

    fn get_glyph_index(self, char: char) -> u16 {
        self.table[char as usize]
    }
}

#[derive(Debug)]
#[repr(C, packed)]
struct PsfHeader {
    magic: u32,
    version: u32,
    headersize: u32,
    flags: u32,
    numglpyh: u32,
    bytesperglyph: u32,
    height: u32,
    width: u32,

}


impl PsfHeader {
    pub unsafe fn new(start: usize) -> &'static Self {
        let header_ptr = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as *const PsfHeader;
        //let header_ptr = &_binary_Uni3_TerminusBold32x16_psf_start as *const u8 as *const PsfHeader;
        #[allow(invalid_reference_casting)]
            let header = &*header_ptr;
        header
    }
}