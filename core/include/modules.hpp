#ifndef MODULES_H
#define MODULES_H
#include <core/corelib.hpp>

    namespace Modules {

	    PRTL_RB_TREE
    	FUNCTION
		FindModuleIndex();

	    PLIST_ENTRY
    	FUNCTION
    	FindHashTable();

		VOID
		FUNCTION
		DestroyModule(EXECUTABLE *mod);

    	VOID
    	FUNCTION
    	InsertTailList(LIST_ENTRY *head, LIST_ENTRY *entry);

	    PLDR_DATA_TABLE_ENTRY
    	FUNCTION
    	FindModuleEntry(UINT32 hash);

		BOOL
		FUNCTION
		GetModulePath(EXECUTABLE *module, const uint32 name_hash);

	    PLDR_DATA_TABLE_ENTRY
    	FUNCTION
    	FindModuleEntryByName(CONST WCHAR *mod_name);

	    FARPROC
    	FUNCTION
		FindExportAddress(CONST VOID *base, uint32 hash);

		UINT_PTR
		FUNCTION
		FindKernelModule(CHAR *module_name);

		UINT_PTR
		FUNCTION
		FindSection(CONST CHAR* section_name, UINT_PTR base, UINT32 *size);

	    BOOL
    	FUNCTION
    	AddHashTableEntry(PLDR_DATA_TABLE_ENTRY entry);

	    BOOL
    	FUNCTION
    	LocalLdrFindExportAddress(HMODULE module, CONST CHAR *fn_name, UINT16 ordinal, VOID **function);

	    PEXECUTABLE
    	FUNCTION
		ImportModule(CONST UINT32 load_type, CONST UINT32 name_hash, UINT8 *memory, CONST UINT32 mem_size, WCHAR *name, BOOL cache);

	    BOOL
    	FUNCTION
    	ResolveImports(CONST EXECUTABLE *module);

	    BOOL
    	FUNCTION
    	MapModule(EXECUTABLE *module);

	    BOOL
    	FUNCTION
    	AddModuleEntry(PLDR_DATA_TABLE_ENTRY entry, CONST VOID *base);

	    BOOL
    	FUNCTION
		FindModule(EXECUTABLE *module, UINT32 name_hash);

	    BOOL
    	FUNCTION
    	ReadModule(EXECUTABLE *module);

	    BOOL
    	FUNCTION
    	LinkModule(EXECUTABLE *module);

	    BOOL
    	FUNCTION
    	ConcealLibrary(EXECUTABLE pdModule, BOOL bConceal);
    }

#endif //MODULES_H
