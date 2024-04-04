use core::fmt;
use core::fmt::Write;

pub mod char_buffer;
pub mod font;




#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {{
        $crate::fontmodule::_print(core::format_args!($($arg)*));
    }};
}


#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::fontmodule::_print(core::format_args!($($arg)*));
    }};
}


pub fn _print(args: fmt::Arguments<'_>) {
    crate::CHARBUFFER.lock().write_fmt(args).unwrap();
}