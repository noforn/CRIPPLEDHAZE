# CRIPPLEDHAZE

**Arbitrary Windows kernel read/write from user-mode via WHQL-signed driver.**

### OBJECTIVE(s):
Establish a user-mode control channel to the CYBELSOFT DriversCloud kernel driver surface and leverage its exposed IOCTL capabilities to develop a stable, reliable kernel read/write primitive for operations against arbitrary virtual addresses.

### REFERENCE:
[DriversCloud](https://www.driverscloud.com/en) (by CybelSoft, a French system utilities company) is a legitimate Windows system information and driver detection/update tool, and self descibed *"essential specialist for detecting and downloading drivers for internal components and external devices of your Windows PC"*.

Its desktop agent (DriversCloudAgent.exe) performs deep hardware/software scans (including BSOD analysis and hardware health monitoring).

Once loaded, ***DriversCloud_amd64.sys***, the WHQL-signed driver intended only to enable DriverCloudAgent.exe's low-level hardware queries and driver management functions, creates a device object with a null security descriptor. The driver implements zero access control, authentication, or authorization checks on any of its ***seven*** IOCTL interfaces.

***Any*** user-mode process can obtain a handle to ```\\.\DriversCloud_amd64``` and freely invoke all exposed operations.

***CRIPPLEDHAZE*** temporarily overwrites `IA32_LSTAR` (syscall entry MSR) with a gadget from `ntoskrnl.exe`, executes a `syscall` from user-mode, then utilizes the resulting kernel execution context to perform arbitrary reads and write operations before cleanly returning via `iretq`. Thread priority is raised and affinity is pinned during operations for reliability.

### CURRENT COMPONENTS:
- `src/`: primary DriversCloud CLI, device access, kernel read/write primitive, token helpers, DSE controls, and implant injection flow.
- `CloudStore/`: DLL loader path that extracts encrypted payload data from PNG candidates, decrypts it in-process, and starts it from executable memory.
- `mmdevlib/`: COM DLL loader path that initializes build-specific offsets, opens the DriversCloud device, and invokes the injection flow.
- `STAGE/`, `STAGE1/`, `STAGE2/`: staging, dropper, payload preparation, and UAC support tooling. BOF-specific notes live in [`STAGE2/UACbof/README.md`](STAGE2/UACbof/README.md).

### CLI SURFACE:
The Rust CLI opens the DriversCloud device before command dispatch. If no subcommand is supplied, it defaults to `inject`.

Current command groups include:
- Physical memory and MSR access: `rmem`, `rdmsr`, `wrmsr`, `sysentry`.
- Kernel discovery and R/W helpers: `kbase`, `rop`, `lookup`, `kread`, `kdump`, `kwrite`.
- Process and token inspection: `eprocess`, `procid`, `proclinks`, `token`, `priv`.
- Implant and policy controls: `inject`, `dse`, `discover`.

### IMPLANT FUNCTIONALITY:
- `inject [pid]` decrypts the embedded `sc_enc.bin` payload. If no PID is supplied, it selects a whitelisted target process, maps the payload through a section, and starts a remote thread.
- `CloudStore` searches PNG-backed payload candidate paths, extracts encrypted payload bytes, decrypts them into memory, changes the region to executable, and starts the payload in-process.

### PREREQUISITES / LIMITATIONS:
- Requires a Windows runtime with access to the `DriversCloud_amd64` device.
- The root build consumes `sc_enc.bin`; runtime injection fails if no encrypted shellcode was embedded.
- EPROCESS offsets currently include build `26200`. Unsupported builds should use `discover` output to update the offset table.

