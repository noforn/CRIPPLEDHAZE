#include "resolve.h"

typedef struct _RSV_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  WCHAR *Buffer;
} RSV_UNICODE_STRING;

typedef struct _RSV_LDR_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  RSV_UNICODE_STRING FullDllName;
  RSV_UNICODE_STRING BaseDllName;
} RSV_LDR_ENTRY;

typedef struct _RSV_PEB_LDR {
  BYTE Reserved1[8];
  PVOID Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} RSV_PEB_LDR;

typedef struct _RSV_PEB {
  BYTE Reserved1[2];
  BYTE BeingDebugged;
  BYTE Reserved2[1];
  PVOID Reserved3[2];
  RSV_PEB_LDR *Ldr;
} RSV_PEB;

#define API_CACHE_SIZE 32

typedef struct {
  HMODULE mod;
  DWORD hash;
  void *fn;
} API_CACHE_ENTRY;

static API_CACHE_ENTRY g_cache[API_CACHE_SIZE];
static int g_cache_count;

unsigned int ror13_hash(const char *name) {
  unsigned int h = 0;
  while (*name) {
    h = ((h >> 13) | (h << 19)) & 0xffffffffU;
    h = (h + (unsigned char)*name++) & 0xffffffffU;
  }
  return h;
}

unsigned int ror13_hash_lower(const char *name) {
  unsigned int h = 0;
  unsigned char c;
  while (*name) {
    c = (unsigned char)*name++;
    if (c >= 'A' && c <= 'Z')
      c += 32;
    h = ((h >> 13) | (h << 19)) & 0xffffffffU;
    h = (h + c) & 0xffffffffU;
  }
  return h;
}

void api_cache_reset(void) {
  g_cache_count = 0;
}

static void *cache_lookup(HMODULE mod, DWORD hash) {
  int i;
  for (i = 0; i < g_cache_count; i++) {
    if (g_cache[i].mod == mod && g_cache[i].hash == hash)
      return g_cache[i].fn;
  }
  return NULL;
}

static void cache_store(HMODULE mod, DWORD hash, void *fn) {
  void *existing;
  int i;

  if (!mod || !fn)
    return;

  existing = cache_lookup(mod, hash);
  if (existing)
    return;

  for (i = 0; i < g_cache_count; i++) {
    if (g_cache[i].mod == mod && g_cache[i].hash == hash) {
      g_cache[i].fn = fn;
      return;
    }
  }

  if (g_cache_count >= API_CACHE_SIZE)
    return;

  g_cache[g_cache_count].mod = mod;
  g_cache[g_cache_count].hash = hash;
  g_cache[g_cache_count].fn = fn;
  g_cache_count++;
}

static RSV_PEB *get_peb(void) {
#ifdef _WIN64
  void *peb;
  __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
  return (RSV_PEB *)peb;
#else
  void *peb;
  __asm__ volatile("mov %%fs:0x30, %0" : "=r"(peb));
  return (RSV_PEB *)peb;
#endif
}

__attribute__((noinline, optimize("O0")))
HMODULE mod_from_peb(DWORD base_name_hash) {
  RSV_PEB *peb = get_peb();
  LIST_ENTRY *head;
  LIST_ENTRY *entry;
  char name_buf[64];
  int i;
  WCHAR *w;
  int len;

  if (!peb || !peb->Ldr)
    return NULL;

  head = &peb->Ldr->InMemoryOrderModuleList;
  entry = head->Flink;
  while (entry && entry != head) {
    RSV_LDR_ENTRY *mod =
        (RSV_LDR_ENTRY *)((BYTE *)entry - sizeof(LIST_ENTRY));

    if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0) {
      w = mod->BaseDllName.Buffer;
      len = mod->BaseDllName.Length / (int)sizeof(WCHAR);
      if (len >= 63)
        len = 63;
      for (i = 0; i < len; i++) {
        WCHAR c = w[i];
        if (c >= L'A' && c <= L'Z')
          c += 32;
        name_buf[i] = (char)c;
      }
      name_buf[len] = 0;

      if (ror13_hash_lower(name_buf) == base_name_hash)
        return (HMODULE)mod->DllBase;
    }

    entry = entry->Flink;
  }

  return NULL;
}

static int batch_pending(API_SLOT *slots, int count) {
  int i;
  for (i = 0; i < count; i++) {
    if (!slots[i].out)
      return 1;
    if (!*slots[i].out)
      return 1;
  }
  return 0;
}

static int all_resolved(API_SLOT *slots, int count) {
  int i;
  for (i = 0; i < count; i++) {
    if (!slots[i].out || !*slots[i].out)
      return 0;
  }
  return 1;
}

__attribute__((noinline, optimize("O0")))
int resolve_api_batch(HMODULE mod, API_SLOT *slots, int count) {
  unsigned char *base = (unsigned char *)mod;
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS *nt;
  IMAGE_EXPORT_DIRECTORY *exp;
  DWORD *names;
  DWORD exp_rva;
  DWORD i, j;
  unsigned int h;
  const char *name;
  void *addr;

  if (!mod || !slots || count <= 0)
    return 0;

  for (i = 0; i < (DWORD)count; i++) {
    if (!slots[i].out)
      return 0;
    if (!*slots[i].out) {
      addr = cache_lookup(mod, slots[i].hash);
      if (addr)
        *slots[i].out = addr;
    }
  }

  if (all_resolved(slots, count))
    return 1;

  dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return 0;

  exp_rva =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  if (!exp_rva)
    return 0;

  exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
  names = (DWORD *)(base + exp->AddressOfNames);

  for (i = 0; i < exp->NumberOfNames; i++) {
    if (!batch_pending(slots, count))
      break;

    name = (const char *)(base + names[i]);
    h = ror13_hash(name);

    for (j = 0; j < (DWORD)count; j++) {
      if (slots[j].hash != h)
        continue;
      if (slots[j].out && !*slots[j].out) {
        addr = (void *)GetProcAddress(mod, name);
        if (!addr)
          continue;
        *slots[j].out = addr;
        cache_store(mod, h, addr);
      }
    }
  }

  return all_resolved(slots, count);
}

void *resolve_by_hash(HMODULE mod, DWORD hash) {
  void *fn;
  API_SLOT slot;

  fn = cache_lookup(mod, hash);
  if (fn)
    return fn;

  fn = NULL;
  slot.hash = hash;
  slot.out = &fn;
  if (!resolve_api_batch(mod, &slot, 1))
    return NULL;
  return fn;
}
