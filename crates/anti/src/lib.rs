#![deny(unsafe_op_in_unsafe_fn)]

use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::System::Diagnostics::Debug::{
    CheckRemoteDebuggerPresent, IsDebuggerPresent,
};
use windows_sys::Win32::System::ProcessStatus::EnumProcesses;
use windows_sys::Win32::System::SystemInformation::{
    GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use winreg::enums::*;
use winreg::RegKey;

/// Aggregated anti-debug checks.
pub fn anti_debug_triggered() -> bool {
    is_debugger_present() || has_remote_debugger()
}

pub fn is_debugger_present() -> bool {
    unsafe { IsDebuggerPresent() != 0 }
}

pub fn has_remote_debugger() -> bool {
    let mut present: BOOL = 0;
    let h = unsafe { GetCurrentProcess() };
    let ok = unsafe { CheckRemoteDebuggerPresent(h, &mut present) };
    ok != 0 && present != 0
}

// Additional checks like NtQueryInformationProcess can be added if needed.

/// Aggregated anti-VM checks.
pub fn anti_vm_triggered() -> bool {
    let up_ms = uptime_ms();
    let total_phys = total_physical_memory();
    let tmp_count = temp_file_count();
    let proc_count = process_count();
    let wechat_installed = is_wechat_installed();

    let min_up_ms = std::env::var("RS_PACK_MIN_UPTIME_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5 * 60 * 1000);
    let min_phys = std::env::var("RS_PACK_MIN_PHYS_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|mb| mb * 1024 * 1024)
        .unwrap_or(4 * 1024 * 1024 * 1024);
    let min_tmp = std::env::var("RS_PACK_MIN_TEMPFILES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(30);
    let min_procs = std::env::var("RS_PACK_MIN_PROCESSES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50);

    let conds = [
        up_ms < min_up_ms,
        total_phys < min_phys,
        tmp_count < min_tmp,
        proc_count < min_procs,
        !wechat_installed,
    ];
    conds.iter().filter(|&&b| b).count() >= 2
}

pub fn uptime_ms() -> u64 {
    unsafe { GetTickCount64() as u64 }
}

pub fn total_physical_memory() -> u64 {
    let mut s: MEMORYSTATUSEX = unsafe { core::mem::zeroed() };
    s.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
    let ok = unsafe { GlobalMemoryStatusEx(&mut s as *mut MEMORYSTATUSEX) };
    if ok != 0 {
        s.ullTotalPhys
    } else {
        0
    }
}

pub fn temp_file_count() -> usize {
    let d = std::env::temp_dir();
    match std::fs::read_dir(d) {
        Ok(rd) => rd.filter_map(|e| e.ok()).count(),
        Err(_) => 0,
    }
}

pub fn process_count() -> usize {
    let mut pids = [0u32; 1024];
    let mut bytes_returned = 0;
    let ok = unsafe {
        EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * core::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        )
    };
    if ok != 0 {
        bytes_returned as usize / core::mem::size_of::<u32>()
    } else {
        0
    }
}

pub fn is_wechat_installed() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(_) = hkcu.open_subkey("Software\\Tencent\\Weixin") {
        return true;
    }
    false
}
