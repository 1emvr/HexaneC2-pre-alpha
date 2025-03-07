#ifndef MODULES_H
#define MODULES_H
#include <core/corelib.hpp>

namespace Modules {
	UINT_PTR
	FUNCTION __stdcall
	FindSection(CONST CHAR* section_name, UINT_PTR base, UINT32 *size);

    PLDR_DATA_TABLE_ENTRY
	FUNCTION __stdcall
	FindModuleEntry(CONST UINT32 hash);

    FARPROC
	FUNCTION __stdcall
	FindExportAddress(const VOID *base, const UINT32 hash);

    BOOL
	FUNCTION __stdcall
	LocalLdrFindExportAddress(HMODULE mod, CONST CHAR *export_name, CONST UINT16 ordinal, VOID **function);

	UINT_PTR
	FUNCTION __stdcall
	FindKernelModule(CHAR *module_name);

	FARPROC
	FUNCTION __stdcall
	FindKernelExport(HANDLE handle, UINT_PTR base, CONST CHAR *function);

    BOOL
	FUNCTION __stdcall
	FindModulePath(EXECUTABLE *mod, const UINT32 name_hash);

    VOID
	FUNCTION __stdcall
	InsertTailList(LIST_ENTRY *CONST head, LIST_ENTRY *CONST entry);

    PLIST_ENTRY
	FUNCTION __stdcall
	FindHashTable();

    BOOL
	FUNCTION __stdcall
	AddHashTableEntry(PLDR_DATA_TABLE_ENTRY entry);

	BOOL
	FUNCTION __stdcall
	ResolveEntries(CONST EXECUTABLE *mod, PIMAGE_THUNK_DATA thunk_a, PIMAGE_THUNK_DATA thunk_b, VOID *lib);

	BOOL
	FUNCTION __stdcall
	ResolveImports(CONST EXECUTABLE *mod);

	PRTL_RB_TREE
	FUNCTION __stdcall
	FindModuleIndex();

    BOOL
	FUNCTION __stdcall
	MapModule(EXECUTABLE *mod);

    BOOL
	FUNCTION __stdcall
	AddModuleEntry(PLDR_DATA_TABLE_ENTRY entry, CONST VOID *base);

    BOOL
	FUNCTION __stdcall
	ReadModule(EXECUTABLE *mod);

    BOOL
	FUNCTION __stdcall
	LinkModule(EXECUTABLE *mod);

	BOOL
	FUNCTION __stdcall
	BeginExecution(PEXECUTABLE mod);

	PEXECUTABLE
	FUNCTION __stdcall
	ImportModule(CONST UINT32 load_type, CONST UINT32 name_hash, UINT8 *memory, CONST UINT32 mem_size, WCHAR *name, BOOL cache);

	VOID
	FUNCTION __stdcall
	CleanupModule(EXECUTABLE **mod, BOOL destroy);

    BOOL
	FUNCTION __stdcall
	ConcealLibrary(EXECUTABLE pdModule, BOOL bConceal);
}

#endif //MODULES_H
