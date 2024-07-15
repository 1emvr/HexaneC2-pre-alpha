#include <../monolith.hpp>
#include <inject/injectlib.hpp>
using namespace Memory;

EXTERN_C VOID Start();

DLL_EXPORT BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved) {

    switch(reason) {
        case DLL_PROCESS_ATTACH:
            // start routine should wrap inject, which wraps "entrypoint"
            CreateThread(nullptr, 0, ROUTINE(Entrypoint), module, 0, nullptr);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
        default:
            break;
    }
    return TRUE;
}

