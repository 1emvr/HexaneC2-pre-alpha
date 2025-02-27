#ifndef MODULES_H
#define MODULES_H
#include <core/corelib.hpp>

struct LATE_LOAD_ENTRY {
	UINT32 hash;
	PEXECUTABLE mod;
};

namespace Modules {

	PRTL_RB_TREE
	FUNCTION __stdcall
	FindModuleIndex();

	PLIST_ENTRY
	FUNCTION __stdcall
	FindHashTable();

	VOID
	FUNCTION __stdcall
	CleanupModule(EXECUTABLE **mod, BOOL destroy);

	VOID
	FUNCTION __stdcall
	InsertTailList(LIST_ENTRY *head, LIST_ENTRY *entry);

	PLDR_DATA_TABLE_ENTRY
	FUNCTION __stdcall
	FindModuleEntry(UINT32 hash);

	BOOL
	FUNCTION __stdcall
	FindModulePath(EXECUTABLE *mod, const uint32 name_hash);

	PLDR_DATA_TABLE_ENTRY
	FUNCTION __stdcall
	FindModuleEntryByName(CONST WCHAR *mod_name);

	FARPROC
	FUNCTION __stdcall
	FindExportAddress(CONST VOID *base, uint32 hash);

	UINT_PTR
	FUNCTION __stdcall
	FindKernelModule(CHAR *module_name);

	UINT_PTR
	FUNCTION __stdcall
	FindSection(CONST CHAR* section_name, UINT_PTR base, UINT32 *size);

	BOOL
	FUNCTION __stdcall
	AddHashTableEntry(PLDR_DATA_TABLE_ENTRY entry);

	BOOL
	FUNCTION __stdcall
	LocalLdrFindExportAddress(HMODULE mod, CONST CHAR *fn_name, UINT16 ordinal, VOID **function);

	BOOL
	FUNCTION __stdcall
	ResolveImports(CONST EXECUTABLE *mod, VECTOR<LATE_LOAD_ENTRY>& late_loads);

	BOOL
	FUNCTION __stdcall
	ProcessLateLoadModules(VECTOR<LATE_LOAD_ENTRY>& mods);

	PEXECUTABLE
	FUNCTION __stdcall
	ImportModule(CONST UINT32 load_type, CONST UINT32 name_hash, UINT8 *memory, CONST UINT32 mem_size, WCHAR *name, BOOL cache);

	BOOL
	FUNCTION __stdcall
	MapModule(EXECUTABLE *mod);

	BOOL
	FUNCTION __stdcall
	AddModuleEntry(PLDR_DATA_TABLE_ENTRY entry, CONST VOID *base);

	BOOL
	FUNCTION __stdcall
	FindModule(EXECUTABLE *mod, UINT32 name_hash);

	BOOL
	FUNCTION __stdcall
	ReadModule(EXECUTABLE *mod);

	BOOL
	FUNCTION __stdcall
	LinkModule(EXECUTABLE *mod);

	BOOL
	FUNCTION __stdcall
	ConcealLibrary(EXECUTABLE pdModule, BOOL bConceal);
}

#endif //MODULES_H
