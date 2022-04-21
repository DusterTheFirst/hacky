use std::{
    ffi::{self, CString},
    mem,
    path::Path,
    ptr,
};

use argh::FromArgs;
use color_eyre::{eyre::eyre, Help, Report};
use windows::{
    core::{PCSTR, PSTR},
    Win32::{
        Foundation::GetLastError,
        System::{
            Diagnostics::Debug::{
                FormatMessageA, ReadProcessMemory, WriteProcessMemory,
                FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
                FORMAT_MESSAGE_IGNORE_INSERTS,
            },
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{VirtualAllocEx, MEM_COMMIT, PAGE_READWRITE},
            ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::{
                CreateRemoteThread, OpenProcess, QueryFullProcessImageNameA, PROCESS_CREATE_THREAD,
                PROCESS_NAME_NATIVE, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
                PROCESS_VM_READ, PROCESS_VM_WRITE,
            },
        },
    },
};

#[derive(FromArgs)]
/// Commit process crimes
struct Args {
    /// pid to attach to
    #[argh(positional)]
    pid: u32,
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let Args { pid } = argh::from_env();

    unsafe { do_crimes(pid) }
}

unsafe fn do_crimes(pid: u32) -> color_eyre::Result<()> {
    let process = OpenProcess(
        PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE,
        false,
        pid,
    )?;
    println!("opened process {process:?}");

    let mut image_name = vec![0u8; 16384];
    let mut image_name_len = image_name.len() as u32;
    let success = QueryFullProcessImageNameA(
        process,
        PROCESS_NAME_NATIVE,
        PSTR(image_name.as_mut_ptr()),
        &mut image_name_len,
    )
    .as_bool();
    if !success {
        return Err(get_last_error().note("caused by QueryFullProcessImageNameA"));
    }
    image_name.truncate(image_name_len as _);
    let image_name = String::from_utf8_lossy(&image_name[..image_name_len as _]);
    println!("process name {image_name}");

    let path = Path::new("./target/debug/payload.dll").canonicalize()?;
    println!("canonicalized DLL: {path:?}");
    let path = CString::new(path.to_string_lossy().as_ref())?;

    let path_bytes = path.as_bytes();
    let target_addr = VirtualAllocEx(
        process,
        ptr::null(),
        path_bytes.len(),
        MEM_COMMIT,
        PAGE_READWRITE,
    );
    if target_addr.is_null() {
        return Err(get_last_error().note("caused by VirtualAllocEx"));
    }
    println!(
        "allocated {} bytes @ {target_addr:p} in {process:?}",
        path_bytes.len()
    );

    let mut bytes_written = 0;
    let success = WriteProcessMemory(
        process,
        target_addr,
        path_bytes.as_ptr() as _,
        path_bytes.len(),
        &mut bytes_written,
    )
    .as_bool();
    if !success {
        return Err(get_last_error().note("caused by WriteProcessMemory"));
    }
    println!("wrote {bytes_written} bytes @ {target_addr:p} in {process:?}");

    let kernel32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr() as _));
    println!("kernel32 handle {kernel32:?}");

    let load_library_a = GetProcAddress(kernel32, PCSTR(b"LoadLibraryA\0".as_ptr()))
        .ok_or(eyre!("LoadLibraryA not found!"))? as *const ();

    println!("Press enter to start thread...");
    std::io::stdin().read_line(&mut String::new())?;

    // let mut tid = 0;
    // let thread = CreateRemoteThread(
    //     process,
    //     ptr::null(),
    //     0,
    //     Some(std::mem::transmute(load_library_a)),
    //     target_addr,
    //     0,
    //     &mut tid,
    // )?;
    // println!("created thread {thread:?}, tid = {tid:?} in process {process:?} starting @ {load_library_a:p}");

    // Read Memory
    let mut memory_counters: PROCESS_MEMORY_COUNTERS = PROCESS_MEMORY_COUNTERS::default();
    let success = K32GetProcessMemoryInfo(
        process,
        &mut memory_counters,
        mem::size_of::<PROCESS_MEMORY_COUNTERS>() as _,
    )
    .as_bool();
    if !success {
        return Err(get_last_error().note("caused by K32GetProcessMemoryInfo"));
    }
    dbg!(memory_counters);

    const HEAP_START: *const ffi::c_void = 0x243_0000_0000_usize as _;

    let mut offset = 0;
    let mut mem = vec![0u8; memory_counters.WorkingSetSize];

    while offset < memory_counters.WorkingSetSize {
        let mut bytes_read = 0;
        let success = ReadProcessMemory(
            process,
            HEAP_START.add(offset),
            mem[offset..].as_mut_ptr() as *mut _,
            100,
            &mut bytes_read,
        )
        .as_bool();
        if success || bytes_read > 0 {
            dbg!(&mem[offset..offset + 100]);
        }

        offset += 100;
    }

    Ok(())
}

unsafe fn get_last_error() -> Report {
    let error_code = GetLastError().0;

    let mut ptr = ptr::null::<u8>();
    let len = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
        ptr::null(),
        error_code,
        0,
        PSTR(std::mem::transmute(&mut ptr as *mut _)),
        0,
        ptr::null(),
    ) as usize;
    let message = std::slice::from_raw_parts(ptr, len);
    let message = String::from_utf8_lossy(message);

    eyre!("win32 error 0x{error_code:x} ({error_code}): {message}")
}
