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
    		InsertTailList(LIST_ENTRY *head, LIST_ENTRY *entry);


	    PLDR_DATA_TABLE_ENTRY
    	FUNCTION
    		FindModuleEntry(UINT32 hash);


	    PLDR_DATA_TABLE_ENTRY
    	FUNCTION
    		FindModuleEntryByName(CONST WCHAR *mod_name);

	    FARPROC
    	FUNCTION
    		FindExportAddress(CONST VOID *base, uint32 hash);

	    BOOL
    	FUNCTION
    		AddHashTableEntry(PLDR_DATA_TABLE_ENTRY entry);

	    BOOL
    	FUNCTION
    		LocalLdrFindExportAddress(HMODULE module, CONST MBS_BUFFER *fn_name, UINT16 ordinal, VOID **function);

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
    		FindModule(EXECUTABLE *module, WCHAR *filename);

	    BOOL
    	FUNCTION
    		ReadModule(EXECUTABLE *module);

	    BOOL
    	FUNCTION
    		LinkModule(EXECUTABLE *module);

	    PEXECUTABLE
    	FUNCTION
    		LoadModule(UINT32 load_type, UINT32 name_hash, UINT8 *memory, UINT32 mem_size, WCHAR *name);

	    BOOL
    	FUNCTION
    		ConcealLibrary(EXECUTABLE pdModule, BOOL bConceal);
    }

#endif //MODULES_H
