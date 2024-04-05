use core::fmt;

use limine::framebuffer::Framebuffer;

use crate::font;
use crate::font::Font;

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum Color {
    White = 0xFFFFFF,
    Black = 0x0,
}

pub struct CharBuffer<'a, 'b> {
    framebuffer: Framebuffer<'a>,
    charbuffer: [char; 300],
    chars_per_row: u32,
    // will be used to calculate line height
    character_height_px: u32,
    character_width_px: u32,
    color: Color,
    caret: u32,
    font: Font<'b>,
}

unsafe impl<'a, 'b> Sync for CharBuffer<'a, 'b> {}

unsafe impl<'a, 'b> Send for CharBuffer<'a, 'b> {}

impl<'a, 'b> CharBuffer<'a, 'b> {
    pub fn new(
        color: Color,
        framebuffer: Framebuffer<'a>,
        character_height_px: u32,
        character_width_px: u32,
        chars_per_row: u32,
        font: Font<'b>,
    ) -> Self {
        Self {
            color,
            framebuffer,
            character_height_px,
            character_width_px,
            chars_per_row,
            caret: 0,
            // empty glyph
            charbuffer: ['\u{020}'; 300],
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
            // let column_index = i as u32 - (row_index * self.chars_per_row);

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


impl<'a, 'b> fmt::Write for CharBuffer<'a, 'b> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s);
        Ok(())
    }
}