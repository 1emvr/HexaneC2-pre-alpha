#include <core/monolith.hpp>
#include <inject/injectlib/injectlib.hpp>

EXTERN_C VOID Start();
DLL_EXPORT BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved) {

    switch(reason) {
        case DLL_PROCESS_ATTACH:
            CreateThread(nullptr, 0, REINTC(PTHREAD_START_ROUTINE, Start), module, 0, nullptr);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
        default:
            break;
    }
    return TRUE;
}

