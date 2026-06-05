#include "indirect.h"

typedef struct {
  DWORD NtCreateFile;
  DWORD NtWriteFile;
  DWORD NtClose;
  DWORD NtQueryVirtualMemory;
} SSN_CACHE;

static SSN_CACHE g_cache;
static int g_ready;

static unsigned int ror13_hash(const char *name) {
  unsigned int h = 0;
  while (*name) {
    h = ((h >> 13) | (h << 19)) & 0xffffffffU;
    h = (h + (unsigned char)*name++) & 0xffffffffU;
  }
  return h;
}

static void *export_by_hash(HMODULE mod, unsigned int hash) {
  unsigned char *base = (unsigned char *)mod;
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  IMAGE_NT_HEADERS *nt =
      (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  DWORD exp_rva =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  if (!exp_rva)
    return NULL;

  IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
  DWORD *names = (DWORD *)(base + exp->AddressOfNames);
  DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
  WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
  DWORD i;

  for (i = 0; i < exp->NumberOfNames; i++) {
    const char *name = (const char *)(base + names[i]);
    if (ror13_hash(name) == hash)
      return base + funcs[ords[i]];
  }
  return NULL;
}

static DWORD ssn_from_export(void *fn) {
  unsigned char *p = (unsigned char *)fn;
  if (!fn)
    return 0;

  if (p[0] == 0x4c && p[1] == 0x8b && p[2] == 0xd1 && p[3] == 0xb8)
    return *(DWORD *)(p + 4);

  if (p[0] == 0xb8 && p[5] == 0x00 && p[6] == 0x00)
    return *(DWORD *)(p + 1);

  if (p[0] == 0xe9 || p[0] == 0xeb)
    return 0;

  return 0;
}

static void *find_syscall_gadget(HMODULE ntdll) {
  unsigned char *base = (unsigned char *)ntdll;
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
  IMAGE_NT_HEADERS *nt;
  IMAGE_SECTION_HEADER *sec;
  DWORD i, j;

  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  sec = IMAGE_FIRST_SECTION(nt);
  for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
    if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
      continue;

    unsigned char *start = base + sec->VirtualAddress;
    DWORD size = sec->Misc.VirtualSize;
    if (size < 3)
      continue;

    for (j = 0; j + 2 < size; j++) {
      if (start[j] == 0x0f && start[j + 1] == 0x05 && start[j + 2] == 0xc3)
        return start + j;
    }
  }
  return NULL;
}

static int resolve_ssns(HMODULE ntdll) {
  void *fn;

  fn = export_by_hash(ntdll, HASH_NtCreateFile);
  g_cache.NtCreateFile = ssn_from_export(fn);
  if (!g_cache.NtCreateFile)
    return 0;

  fn = export_by_hash(ntdll, HASH_NtWriteFile);
  g_cache.NtWriteFile = ssn_from_export(fn);
  if (!g_cache.NtWriteFile)
    return 0;

  fn = export_by_hash(ntdll, HASH_NtClose);
  g_cache.NtClose = ssn_from_export(fn);
  if (!g_cache.NtClose)
    return 0;

  fn = export_by_hash(ntdll, HASH_NtQueryVirtualMemory);
  g_cache.NtQueryVirtualMemory = ssn_from_export(fn);
  if (!g_cache.NtQueryVirtualMemory)
    return 0;

  return 1;
}

__attribute__((noinline)) int indirect_init(HMODULE hNtdll) {
  g_ready = 0;
  g_syscall_gadget = NULL;

  if (!hNtdll)
    return 0;

  g_syscall_gadget = find_syscall_gadget(hNtdll);
  if (!g_syscall_gadget)
    return 0;

  if (!resolve_ssns(hNtdll))
    return 0;

  g_ready = 1;
  return 1;
}

static int asc_to_w(const char *src, wchar_t *dst, int max) {
  int i = 0;
  if (!src || !dst || max < 2)
    return 0;
  while (src[i] && i < max - 1) {
    dst[i] = (wchar_t)(unsigned char)src[i];
    i++;
  }
  dst[i] = 0;
  return i;
}

static int build_nt_path(const char *path, wchar_t *buf, int max) {
  int n;
  if (!path || !buf || max < 8)
    return 0;

  if (path[0] == '\\' && path[1] == '?') {
    n = asc_to_w(path, buf, max);
    return n > 0;
  }

  if (max < 5)
    return 0;
  buf[0] = L'\\';
  buf[1] = L'?';
  buf[2] = L'?';
  buf[3] = L'\\';
  n = asc_to_w(path, buf + 4, max - 4);
  return n > 0;
}

typedef NTSTATUS(NTAPI *pNtCreateFile)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

typedef NTSTATUS(NTAPI *pNtWriteFile)(HANDLE FileHandle, HANDLE Event,
                                      void *ApcRoutine, PVOID ApcContext,
                                      PIO_STATUS_BLOCK IoStatusBlock,
                                      PVOID Buffer, ULONG Length,
                                      PLARGE_INTEGER ByteOffset,
                                      PULONG Key);

typedef NTSTATUS(NTAPI *pNtClose)(HANDLE Handle);

typedef NTSTATUS(NTAPI *pNtQueryVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
    PVOID MemoryInformation, SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength);

static ULONG win32_disposition(DWORD disposition) {
  switch (disposition) {
  case 1:
    return FILE_CREATE;
  case 2:
    return FILE_OVERWRITE_IF;
  case 3:
    return FILE_OPEN;
  case 4:
    return FILE_OPEN_IF;
  case 5:
    return FILE_OVERWRITE;
  default:
    return FILE_OVERWRITE_IF;
  }
}

static size_t wlen(const wchar_t *s) {
  size_t n = 0;
  if (!s)
    return 0;
  while (s[n])
    n++;
  return n;
}

__attribute__((noinline)) BOOL io_create_directory_a(const char *path) {
  wchar_t wpath[512];
  UNICODE_STRING ustr;
  OBJECT_ATTRIBUTES oa;
  IO_STATUS_BLOCK iosb;
  HANDLE h = NULL;
  NTSTATUS st;

  if (!g_ready || !path)
    return FALSE;

  if (!build_nt_path(path, wpath, 512))
    return FALSE;

  ustr.Length = (USHORT)(wlen(wpath) * sizeof(wchar_t));
  ustr.MaximumLength = ustr.Length + sizeof(wchar_t);
  ustr.Buffer = wpath;

  oa.Length = sizeof(OBJECT_ATTRIBUTES);
  oa.RootDirectory = NULL;
  oa.ObjectName = &ustr;
  oa.Attributes = OBJ_CASE_INSENSITIVE;
  oa.SecurityDescriptor = NULL;
  oa.SecurityQualityOfService = NULL;

  g_ssn = g_cache.NtCreateFile;
  st = ((pNtCreateFile)do_indirect_syscall)(
      &h, FILE_GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, NULL,
      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
      FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

  if (!NT_SUCCESS(st))
    return FALSE;

  g_ssn = g_cache.NtClose;
  ((pNtClose)do_indirect_syscall)(h);
  return TRUE;
}

__attribute__((noinline)) HANDLE io_create_file_a(const char *path, DWORD access,
                                                  DWORD disposition) {
  wchar_t wpath[512];
  UNICODE_STRING ustr;
  OBJECT_ATTRIBUTES oa;
  IO_STATUS_BLOCK iosb;
  HANDLE h = NULL;
  ACCESS_MASK desired = (ACCESS_MASK)access;
  ULONG disp = win32_disposition(disposition);
  NTSTATUS st;

  if (!g_ready || !path)
    return INVALID_HANDLE_VALUE;

  if (!build_nt_path(path, wpath, 512))
    return INVALID_HANDLE_VALUE;

  ustr.Length = (USHORT)(wlen(wpath) * sizeof(wchar_t));
  ustr.MaximumLength = ustr.Length + sizeof(wchar_t);
  ustr.Buffer = wpath;

  oa.Length = sizeof(OBJECT_ATTRIBUTES);
  oa.RootDirectory = NULL;
  oa.ObjectName = &ustr;
  oa.Attributes = OBJ_CASE_INSENSITIVE;
  oa.SecurityDescriptor = NULL;
  oa.SecurityQualityOfService = NULL;

  g_ssn = g_cache.NtCreateFile;
  st = ((pNtCreateFile)do_indirect_syscall)(
      &h, desired | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
      disp, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

  if (!NT_SUCCESS(st))
    return INVALID_HANDLE_VALUE;

  return h;
}

__attribute__((noinline)) BOOL io_write_file(HANDLE h, const void *buf, DWORD len,
                                             DWORD *written) {
  IO_STATUS_BLOCK iosb;
  NTSTATUS st;

  if (!g_ready || h == NULL || h == INVALID_HANDLE_VALUE)
    return FALSE;

  iosb.Status = 0;
  iosb.Information = 0;

  g_ssn = g_cache.NtWriteFile;
  st = ((pNtWriteFile)do_indirect_syscall)(h, NULL, NULL, NULL, &iosb, (PVOID)buf,
                                      len, NULL, NULL);

  if (!NT_SUCCESS(st))
    return FALSE;

  if (written)
    *written = (DWORD)iosb.Information;
  return TRUE;
}

__attribute__((noinline)) BOOL io_close_handle(HANDLE h) {
  NTSTATUS st;

  if (!g_ready || h == NULL || h == INVALID_HANDLE_VALUE)
    return FALSE;

  g_ssn = g_cache.NtClose;
  st = ((pNtClose)do_indirect_syscall)(h);
  return NT_SUCCESS(st);
}

__attribute__((noinline)) SIZE_T io_virtual_query(LPCVOID addr,
                                                  PMEMORY_BASIC_INFORMATION mbi,
                                                  SIZE_T len) {
  SIZE_T ret_len = 0;
  NTSTATUS st;

  if (!g_ready || !addr || !mbi || len < sizeof(MEMORY_BASIC_INFORMATION))
    return 0;

  g_ssn = g_cache.NtQueryVirtualMemory;
  st = ((pNtQueryVirtualMemory)do_indirect_syscall)(
      (HANDLE)(LONG_PTR)-1, (PVOID)addr, 0, mbi,
      sizeof(MEMORY_BASIC_INFORMATION), &ret_len);

  if (!NT_SUCCESS(st))
    return 0;

  return ret_len;
}
