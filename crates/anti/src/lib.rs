#![deny(unsafe_op_in_unsafe_fn)]

use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::System::Diagnostics::Debug::{CheckRemoteDebuggerPresent, IsDebuggerPresent};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

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
    let bios = std::env::var("RS_PACK_VM_BIOS").ok().as_deref() == Some("1");
    if bios {
        hypervisor_present() || bios_vendor_indicates_vm()
    } else {
        hypervisor_present()
    }
}

pub fn hypervisor_present() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        use core::arch::x86_64::__cpuid;
        // CPUID leaf 0x1: ECX bit 31 indicates hypervisor present
        let r = unsafe { __cpuid(0x1) };
        (r.ecx & (1 << 31)) != 0
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

pub fn bios_vendor_indicates_vm() -> bool {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = "HARDWARE\\DESCRIPTION\\System";
    if let Ok(key) = hklm.open_subkey(path) {
        let candidates = [
            "SystemBiosVersion",
            "SystemBiosDate",
            "VideoBiosVersion",
            "SystemManufacturer",
            "SystemProductName",
        ];
        for name in candidates {
            if let Ok(val) = key.get_value::<String, _>(name) {
                let v = val.to_ascii_lowercase();
                let indicators = [
                    "vmware", "virtualbox", "qemu", "hyper-v", "xen", "kvm", "parallels",
                ];
                if indicators.iter().any(|s| v.contains(s)) {
                    return true;
                }
            }
        }
    }
    false
}
