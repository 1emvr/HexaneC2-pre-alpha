#ifndef HEXANE_CORELIB_MEMORY_HPP
#define HEXANE_CORELIB_MEMORY_HPP

#include <core/corelib.hpp>

namespace Memory {
    LPVOID ExceptionReturn = 0;

    namespace Methods {
        FUNCTION BOOL MoveFilePointer(HANDLE handle, int32_t offset, int32_t* current);
        FUNCTION UINT_PTR GetStackCookie();
        FUNCTION VOID GetProcessHeaps(HANDLE process, uint32_t access, uint32_t pid);
        FUNCTION _resource* GetIntResource(HMODULE base, int rsrc_id);
        FUNCTION _executable* CreateImageData(uint8_t *data);
    }

    namespace Context {
        FUNCTION VOID ContextInit();
        FUNCTION VOID ContextDestroy(_hexane* Ctx);
        FUNCTION VOID ResolveApi();
    }

    namespace Objects {
        FUNCTION BOOL BaseRelocation(_executable *object);
        FUNCTION UINT_PTR GetInternalAddress(uint32_t name, bool* internal);
        FUNCTION UINT_PTR ResolveSymbol(_executable *object, uint32_t entry_name, uint32_t type);
        FUNCTION SIZE_T GetFunctionMapSize(_executable *object);
        FUNCTION BOOL MapSections(_executable *object, const uint8_t *data);
    }

    namespace Modules {
        FUNCTION HMODULE GetModuleAddress(const LDR_DATA_TABLE_ENTRY* entry);
        FUNCTION LDR_DATA_TABLE_ENTRY* GetModuleEntry(uint32_t hash);
        FUNCTION FARPROC GetExportAddress(HMODULE base, uint32_t hash);
        FUNCTION UINT_PTR LoadExport(const char* module_name, const char* export_name);
    }

    namespace Scanners {
        FUNCTION UINT_PTR RelocateExport(void* process, const void* target, size_t size);
        FUNCTION BOOL SigCompare(const uint8_t* data, const char* signature, const char* mask);
        FUNCTION UINT_PTR SignatureScan(uintptr_t start, uint32_t size, const char* signature, const char* mask);
    }

    namespace Execute {
        FUNCTION LONG WINAPI Debugger(EXCEPTION_POINTERS *exception);
        FUNCTION VOID ExecuteCommand(_parser &parser);
        FUNCTION VOID ExecuteShellcode(const _parser& parser);
        FUNCTION BOOL ExecuteObject(_executable *object, const char *entrypoint, char *args, uint32_t size, uint32_t req_id);
    }
}
#endif //HEXANE_CORELIB_MEMORY_HPP
