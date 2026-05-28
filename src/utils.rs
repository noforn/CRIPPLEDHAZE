use anyhow::{bail, Context, Result};

use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;

use crate::device::{phys_read, rd_u64, Device, PHYS_MAX_READ};

const PT_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PA_MAX: u64 = 0x0001_0000_0000_0000;

#[derive(Debug, Clone)]
pub struct KernelMod {
    pub va: u64,
    pub size: u32,
    pub name: String,
}

pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn parse_hex_or_dec(s: &str) -> Result<u64> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).context("invalid hex number")
    } else {
        s.parse::<u64>().context("invalid number")
    }
}

pub fn get_kernel_modules() -> Result<Vec<KernelMod>> {
    let mut buf = vec![0u8; 0x10_0000];
    let mut ret: u32 = 0;
    let status = unsafe {
        NtQuerySystemInformation(11, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut ret)
    };
    if status != 0 { bail!("NtQuerySystemInformation failed: NTSTATUS=0x{status:08X}"); }
    let count = u32::from_le_bytes(buf[0..4].try_into()?) as usize;
    if count == 0 || count > 1000 { bail!("bad module count: {}", count); }
    const ENTRY: usize = 0x128;
    const BASE: usize = 8;
    let mut mods = Vec::new();
    for i in 0..count {
        let off = BASE + i * ENTRY;
        if off + ENTRY > buf.len() { break; }
        let va = u64::from_le_bytes(buf[off + 0x10..off + 0x18].try_into()?);
        let size = u32::from_le_bytes(buf[off + 0x18..off + 0x1C].try_into()?);
        let pb = &buf[off + 0x28..off + 0x28 + 256];
        let nul = pb.iter().position(|&b| b == 0).unwrap_or(256);
        let path = String::from_utf8_lossy(&pb[..nul]).to_string();
        let name = path.split('\\').last().unwrap_or("").to_ascii_lowercase();
        mods.push(KernelMod { va, size, name });
    }
    Ok(mods)
}

pub fn find_mod<'a>(mods: &'a [KernelMod], names: &[&str]) -> Option<&'a KernelMod> {
    mods.iter().find(|m| names.iter().any(|n| m.name == *n))
}

pub fn walk_page_table(dev: &Device, cr3: u64, va: u64) -> Option<u64> {
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

pub fn wpt_buf(dev: &Device, cr3: u64, va: u64, buf: &mut [u8]) -> Option<u64> {
    let pml4e = crate::device::rd_u64_with_buf(dev, (cr3 & PT_MASK) + ((va >> 39) & 0x1FF) * 8, buf)?;
    if pml4e & 1 == 0 { return None; }

    let pdpte = crate::device::rd_u64_with_buf(dev, (pml4e & PT_MASK) + ((va >> 30) & 0x1FF) * 8, buf)?;
    if pdpte & 1 == 0 { return None; }
    if pdpte & 0x80 != 0 {
        return Some((pdpte & 0x000F_FFFF_FFC0_0000) + (va & 0x3FFF_FFFF));
    }

    let pde = crate::device::rd_u64_with_buf(dev, (pdpte & PT_MASK) + ((va >> 21) & 0x1FF) * 8, buf)?;
    if pde & 1 == 0 { return None; }
    if pde & 0x80 != 0 {
        return Some((pde & 0x000F_FFFF_FFE0_0000) + (va & 0x1F_FFFF));
    }

    let pte = crate::device::rd_u64_with_buf(dev, (pde & PT_MASK) + ((va >> 12) & 0x1FF) * 8, buf)?;
    if pte & 1 == 0 { return None; }
    Some((pte & PT_MASK) + (va & 0xFFF))
}


pub fn find_cr3_for_va(dev: &Device, nt_va: u64, nt_size: u32, lstar_va: u64) -> Option<(u64, u64)> {
    let pml4_idx = (nt_va >> 39) & 0x1FF;
    let pml4_off = (pml4_idx * 8) as usize;
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

pub fn resolve_base_fallback(dev: &Device, lstar_va: u64) -> Option<u64> {
    let mut cr3 = 0;
    let lstar_pml4_idx = (lstar_va >> 39) & 0x1FF;
    let lstar_pml4_off = (lstar_pml4_idx * 8) as usize;
    let mut addr = 0x1000u64;
    let mut buf = Vec::with_capacity(crate::device::PHYS_BUF_SIZE);
    unsafe { buf.set_len(crate::device::PHYS_BUF_SIZE); }
    let mut buf2 = Vec::with_capacity(crate::device::PHYS_BUF_SIZE);
    unsafe { buf2.set_len(crate::device::PHYS_BUF_SIZE); }
    
    while addr < 0x2000_0000 {
        if let Some(actual) = crate::device::phys_read_with_buf(dev, addr, crate::device::PHYS_MAX_READ, &mut buf) {
            let mut off = 0usize;
            while off + 0x1000 <= actual {
                if lstar_pml4_off + 8 <= 0x1000 {
                    let e_off = 8 + off + lstar_pml4_off;
                    let e = u64::from_le_bytes(buf[e_off..e_off + 8].try_into().unwrap());
                    if e & 1 != 0 {
                        let page_pa = addr + off as u64;
                        if wpt_buf(dev, page_pa, lstar_va, &mut buf2).is_some() {
                            cr3 = page_pa;
                            break;
                        }
                    }
                }
                off += 0x1000;
            }
            if cr3 != 0 { break; }
        }
        addr += crate::device::PHYS_MAX_READ as u64;
    }
    if cr3 == 0 { return None; }

    let mut current_va = lstar_va & !0xFFF;
    for _ in 0..0x2000 {
        if let Some(pa) = wpt_buf(dev, cr3, current_va, &mut buf2) {
            if let Some(actual) = crate::device::phys_read_with_buf(dev, pa, 2, &mut buf) {
                let mz = &buf[8..8 + actual];
                if mz.len() >= 2 && mz[0] == 0x4D && mz[1] == 0x5A {
                    return Some(current_va);
                }
            }
        }
        current_va -= 0x1000;
    }
    None
}


fn log_debug(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("C:\\Windows\\Temp\\mmdevlib_kernel.log") {
        let _ = writeln!(f, "[resolve] {}", msg);
        let _ = f.sync_all();
    }
}

pub fn resolve_base_fallback_fast(pe: &[u8], lstar_va: u64) -> Option<u64> {
    log_debug(&format!("resolve_base_fallback_fast: lstar_va=0x{:016X}", lstar_va));
    let page_offset = lstar_va & 0xFFF;
    if pe.len() < 0x40 { log_debug("PE too small"); return None; }
    let e_lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap_or([0;4])) as usize;
    if e_lfanew + 28 > pe.len() { log_debug("e_lfanew OOB"); return None; }
    let num_sections = u16::from_le_bytes(pe[e_lfanew + 6..e_lfanew + 8].try_into().unwrap_or([0;2])) as usize;
    let opt_hdr_size = u16::from_le_bytes(pe[e_lfanew + 20..e_lfanew + 22].try_into().unwrap_or([0;2])) as usize;
    let sec_table_off = e_lfanew + 24 + opt_hdr_size;

    let sig = [0x0F, 0x01, 0xF8]; // swapgs

    let mut matches = 0;
    let mut last_match = None;

    for i in 0..num_sections {
        let sh = sec_table_off + i * 40;
        if sh + 40 > pe.len() { break; }
        let virt_addr = u32::from_le_bytes(pe[sh + 12..sh + 16].try_into().unwrap_or([0;4])) as usize;
        let raw_off = u32::from_le_bytes(pe[sh + 20..sh + 24].try_into().unwrap_or([0;4])) as usize;
        let raw_size = u32::from_le_bytes(pe[sh + 16..sh + 20].try_into().unwrap_or([0;4])) as usize;
        
        let chars = u32::from_le_bytes(pe[sh + 36..sh + 40].try_into().unwrap_or([0;4]));
        if chars & 0x2000_0000 == 0 { continue; }

        if raw_off + raw_size > pe.len() { continue; }
        let data = &pe[raw_off..raw_off + raw_size];

        for j in 0..data.len().saturating_sub(sig.len()) {
            if data[j..j+sig.len()] == sig {
                let rva = virt_addr as u64 + j as u64;
                if rva & 0xFFF == page_offset {
                    matches += 1;
                    last_match = Some(lstar_va.wrapping_sub(rva));
                    log_debug(&format!("Match found! section={} rva=0x{:X} base=0x{:016X}", i, rva, last_match.unwrap()));
                }
            }
        }
    }
    
    if matches == 1 {
        return last_match;
    } else if matches > 1 {
        log_debug(&format!("Multiple matches ({}) for swapgs with offset 0x{:X}", matches, page_offset));
    } else {
        log_debug("No match found for swapgs with matching page offset");
    }

    if page_offset == 0x040 {
        let fallback = lstar_va.wrapping_sub(0x6BC040);
        log_debug(&format!("Using hardcoded fallback: 0x{:016X}", fallback));
        return Some(fallback);
    }
    None
}

pub fn resolve_ntoskrnl(dev: &Device, mods: &[KernelMod]) -> Result<KernelMod> {
    let mut nt = find_mod(mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not found in module list")?
        .clone();
    if nt.va == 0 {
        let lstar = crate::device::msr_read(dev, crate::device::MSR_LSTAR)?;
        log_debug(&format!("resolve_ntoskrnl: nt.va=0, read LSTAR=0x{:016X}", lstar));
        
        match ntoskrnl_disk_path(mods) {
            Ok(path) => {
                log_debug(&format!("Reading PE from {}", path));
                match std::fs::read(&path) {
                    Ok(pe) => {
                        log_debug(&format!("PE read {} bytes", pe.len()));
                        if let Some(base) = resolve_base_fallback_fast(&pe, lstar) {
                            nt.va = base;
                            return Ok(nt);
                        } else {
                            log_debug("resolve_base_fallback_fast returned None");
                        }
                    },
                    Err(e) => log_debug(&format!("Failed to read PE: {}", e)),
                }
            },
            Err(e) => log_debug(&format!("Failed to get PE path: {}", e)),
        }
        
        log_debug("Falling back to physical memory scan");
        if let Some(base) = resolve_base_fallback(dev, lstar) {
            nt.va = base;
        } else {
            bail!("Initialization failed (err 2)");
        }
    }
    Ok(nt)
}

pub fn ntoskrnl_disk_path(mods: &[KernelMod]) -> Result<String> {
    let nt = find_mod(mods, &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"])
        .context("ntoskrnl not in module list")?;
    let sysroot = std::env::var("SYSTEMROOT").unwrap_or_else(|_| "C:\\Windows".to_string());
    Ok(format!("{}\\system32\\{}", sysroot, nt.name))
}

fn rva_to_file_offset(pe: &[u8], rva: u32, e_lfanew: usize, num_sections: usize, opt_hdr_size: usize) -> Option<usize> {
    let sec_table_off = e_lfanew + 24 + opt_hdr_size;
    const SEC_HDR: usize = 40;
    for i in 0..num_sections {
        let sh = sec_table_off + i * SEC_HDR;
        if sh + SEC_HDR > pe.len() { break; }
        let virt_addr = u32::from_le_bytes(pe[sh + 12..sh + 16].try_into().ok()?) as usize;
        let virt_size = u32::from_le_bytes(pe[sh + 8..sh + 12].try_into().ok()?) as usize;
        let raw_off = u32::from_le_bytes(pe[sh + 20..sh + 24].try_into().ok()?) as usize;
        let rva_us = rva as usize;
        if rva_us >= virt_addr && rva_us < virt_addr + virt_size {
            return Some(raw_off + (rva_us - virt_addr));
        }
    }
    None
}

pub fn find_export_va(pe: &[u8], runtime_base: u64, symbol: &str) -> Result<u64> {
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

    let exp_rva = u32::from_le_bytes(pe[opt_off + 112..opt_off + 116].try_into()?);
    if exp_rva == 0 { bail!("no export directory"); }

    let exp_off = rva_to_file_offset(pe, exp_rva, e_lfanew, num_sections, opt_hdr_size)
        .context("export dir RVA not mapped to any section")?;
    if exp_off + 40 > pe.len() { bail!("export dir out of bounds"); }

    let num_names = u32::from_le_bytes(pe[exp_off + 24..exp_off + 28].try_into()?) as usize;
    let addr_funcs_rva = u32::from_le_bytes(pe[exp_off + 28..exp_off + 32].try_into()?);
    let addr_names_rva = u32::from_le_bytes(pe[exp_off + 32..exp_off + 36].try_into()?);
    let addr_ords_rva = u32::from_le_bytes(pe[exp_off + 36..exp_off + 40].try_into()?);

    let names_off = rva_to_file_offset(pe, addr_names_rva, e_lfanew, num_sections, opt_hdr_size)
        .context("AddressOfNames not mapped")?;
    let ords_off = rva_to_file_offset(pe, addr_ords_rva, e_lfanew, num_sections, opt_hdr_size)
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

pub fn hexdump(data: &[u8], base_addr: u64) {
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
