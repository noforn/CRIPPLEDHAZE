#ifndef RESOLVE_H
#define RESOLVE_H

#include <windows.h>
#include "api_hash.h"

typedef struct {
  DWORD hash;
  void **out;
} API_SLOT;

unsigned int ror13_hash(const char *name);
unsigned int ror13_hash_lower(const char *name);

HMODULE mod_from_peb(DWORD base_name_hash);

int resolve_api_batch(HMODULE mod, API_SLOT *slots, int count);
void *resolve_by_hash(HMODULE mod, DWORD hash);

void api_cache_reset(void);

#endif
