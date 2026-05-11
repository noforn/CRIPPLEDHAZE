# CRIPPLEDHAZE

**Arbitrary Windows kernel read/write from user-mode via WHQL-signed driver.**

### OBJECTIVE(s):
Establish a user-mode control channel to the CYBELSOFT DriversCloud kernel driver surface and leverage its exposed IOCTL capabilities to develop a stable, reliable kernel read/write primitive for operation against arbitrary virtual addresses.

### REFERENCE:
DriversCloud (by CybelSoft, formerly associated with Ma-Config.com) is a legitimate Windows system information and driver detection/update tool. 
Its desktop agent (DriversCloudAgent.exe) performs deep hardware/software scans (including BSOD analysis and hardware health monitoring)

Once loaded, ***DriversCloud_amd64.sys***, the WHQL-signed driver intended only to enable DriverCloudAgent.exe's low-level hardware queries and driver management functions, creates a device object with a null security descriptor. The driver implements zero access control, authentication, or authorization checks on any of its seven IOCTL interfaces.

***Any*** user-mode process can obtain a handle to ```\\.\DriversCloud_amd64``` and freely invoke all exposed operations.

***CRIPPLEDHAZE*** temporarily overwrites `IA32_LSTAR` (syscall entry MSR) with a gadget from `ntoskrnl.exe`, executes a `syscall` from user-mode, then utilizes the resulting kernel execution context to perform arbitrary reads and write operations before cleanly returning via `iretq`. Thread priority is raised and affinity is pinned during operations for reliability.

