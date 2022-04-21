use std::process;

use cstr::cstr;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::HWND,
        UI::WindowsAndMessaging::{MessageBoxA, MB_OK},
    },
};

#[ctor::ctor]
fn ctor() {
    unsafe {
        MessageBoxA(
            HWND::default(),
            PCSTR(cstr!("Im in your address space :)").as_ptr() as _),
            PCSTR(cstr!("Beware :)))").as_ptr() as _),
            MB_OK,
        );
    }

    process::exit(69);
}
